package test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	rt "github.com/arnodel/golua/runtime"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func readSource(file *os.File) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, invalid("test inputs must be regular files")
	}
	source, err := io.ReadAll(io.LimitReader(file, maxSource+1))
	if err != nil || len(source) > maxSource {
		return nil, invalid("input source limit exceeded or input unreadable")
	}
	return source, nil
}

type Options struct {
	Includes, Excludes []string
	// Platform can be supplied by embedders and runner tests. The executable CLI
	// uses its own build metadata, never a user-provided platform/version flag.
	Platform Platform
	// Configuration is a fallback file path, not an override for suite content.
	Configuration string
	// Nil uses the normal product default filename. A callback permits in-memory
	// embedding/tests without creating or changing the actual system file.
	DefaultConfiguration func(context.Context) ([]byte, error)
}

func readPath(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|sourceOpenFlags, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readSource(file)
}

// RunPaths discovers every matching source before applying test-name filters.
// Directory symlinks are followed; file_content is separately confined to each
// physical suite's directory. Default configuration is loaded lazily, once.
func RunPaths(ctx context.Context, paths []string, options Options) (report Report) {
	start := startMeasurement()
	defer func() { report.DurationSeconds = start.seconds() }()
	if ctx == nil {
		return loadError(errors.System.Newf("evaluation context is required"), "evaluation context is required")
	}
	filter, err := compileFilter(options.Includes, options.Excludes)
	if err != nil {
		return loadError(err, "invalid test name filters")
	}
	if len(paths) == 0 {
		return loadError(invalid("suite paths are required"), "suite paths are required")
	}
	files, failures, directories := discoverFiles(ctx, paths)
	report = Report{APIVersion: APIVersion, Scope: scope, Results: failures}
	packages := map[string]int{}
	packageFor := func(directory string) int {
		if i, ok := packages[directory]; ok {
			return i
		}
		if physical, err := sys.CanonicalPath(directory); err == nil {
			directory = physical
		}
		if i, ok := packages[directory]; ok {
			return i
		}
		i := len(report.Packages)
		packages[directory] = i
		report.Packages = append(report.Packages, PackageRun{Name: packageName(directory), Directory: directory})
		return i
	}
	for _, directory := range directories {
		packageFor(directory)
	}
	for i := range report.Results {
		directory := filepath.Dir(report.Results[i].Source)
		if info, err := os.Stat(report.Results[i].Source); err == nil && info.IsDir() {
			directory = report.Results[i].Source
		}
		pkg := packageFor(directory)
		report.Results[i].Package = report.Packages[pkg].Name
	}
	report.InputFiles = append(report.InputFiles, files...)
	if options.Configuration != "" {
		report.InputFiles = append(report.InputFiles, options.Configuration)
	} else {
		report.InputFiles = append(report.InputFiles, configuration.DefaultFilename)
	}
	loaded := false
	var fallback []byte
	var fallbackErr error
	loadFallback := func() ([]byte, error) {
		if !loaded {
			loaded = true
			switch {
			case options.Configuration != "":
				fallback, fallbackErr = readPath(options.Configuration)
			case options.DefaultConfiguration != nil:
				fallback, fallbackErr = options.DefaultConfiguration(ctx)
			default:
				fallback, fallbackErr = readPath(configuration.DefaultFilename)
			}
		}
		return fallback, fallbackErr
	}
	seenIDs := map[string]bool{}
	suites := 0
	binary := options.Platform.resolved()
	for _, path := range files {
		pkg := packageFor(filepath.Dir(path))
		child := runPath(ctx, path, binary, filter, loadFallback, seenIDs)
		report.Packages[pkg].DurationSeconds += child.DurationSeconds
		if child.Suite != "" {
			suites++
			if suites == 1 {
				report.Suite = child.Suite
			} else {
				report.Suite = ""
			}
		}
		for i := range child.Results {
			child.Results[i].Source = path
			child.Results[i].Package = report.Packages[pkg].Name
			if child.Results[i].Suite == "" {
				child.Results[i].Suite = child.Suite
			}
		}
		for i := range child.SkippedSuites {
			child.SkippedSuites[i].Package = report.Packages[pkg].Name
		}
		for i := range child.Suites {
			child.Suites[i].Package = report.Packages[pkg].Name
		}
		report.Suites = append(report.Suites, child.Suites...)
		report.Results = append(report.Results, child.Results...)
		report.Warnings = append(report.Warnings, child.Warnings...)
		report.SkippedSuites = append(report.SkippedSuites, child.SkippedSuites...)
		report.InputFiles = append(report.InputFiles, child.InputFiles...)
	}
	// Execution remains in canonical source order. Presentation follows positional
	// input roots, with each physical directory (not its descendants) a package.
	ranks := map[string]int{}
	for i, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		physical, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			continue
		}
		if info, err := os.Stat(physical); err == nil && !info.IsDir() {
			physical = filepath.Dir(physical)
		}
		for _, pkg := range report.Packages {
			if _, found := ranks[pkg.Directory]; found {
				continue
			}
			if relative, err := filepath.Rel(physical, pkg.Directory); err == nil && (relative == "." || filepath.IsLocal(relative)) {
				ranks[pkg.Directory] = i
			}
		}
	}
	slices.SortStableFunc(report.Packages, func(a, b PackageRun) int {
		ar, aok := ranks[a.Directory]
		br, bok := ranks[b.Directory]
		if aok && !bok {
			return -1
		}
		if !aok && bok {
			return 1
		}
		if ar < br {
			return -1
		}
		if ar > br {
			return 1
		}
		return strings.Compare(a.Directory, b.Directory)
	})
	return report
}

func runPath(ctx context.Context, path string, binary Platform, filter nameFilter, fallback func() ([]byte, error), seenIDs map[string]bool) (report Report) {
	start := startMeasurement()
	var spec *suiteSpec
	defer func() {
		report.DurationSeconds = start.seconds()
		for i := range report.Results {
			if report.Results[i].DurationSeconds == 0 {
				report.Results[i].DurationSeconds = report.DurationSeconds
			}
		}
		if spec != nil {
			report.Suites = []SuiteRun{{Name: spec.name, Source: path, DeclaredTests: len(spec.tests), DurationSeconds: report.DurationSeconds}}
		}
	}()
	source, err := readPath(path)
	if err != nil {
		return loadError(err, "cannot read suite")
	}
	contents, err := newFileContents(filepath.Dir(path))
	if err != nil {
		return loadError(err, "cannot open physical suite directory")
	}
	defer contents.Close()
	defer func() { report.InputFiles = append(report.InputFiles, contents.inputs...) }()
	spec, err = discover(ctx, source, contents.read)
	if err != nil {
		return loadError(err, "suite load or resource limit failure")
	}
	if spec == nil {
		return noSuite(path)
	}
	if report, excluded := selectPlatform(spec, binary, path); excluded {
		return report
	}
	for _, test := range spec.tests {
		id := spec.name + "/" + test.name
		if seenIDs[id] {
			report := loadError(invalid("duplicate qualified test name"), "duplicate qualified test name")
			report.Suite = spec.name
			return report
		}
		seenIDs[id] = true
	}
	return runDiscovered(ctx, source, spec, filter, contents.read, fallback)
}

// RunFile is a convenience wrapper with the same suffix and fallback semantics
// as the positional CLI. It never treats suite configuration content as a path.
func RunFile(ctx context.Context, path, configurationFallback string) Report {
	return RunPaths(ctx, []string{path}, Options{Configuration: configurationFallback})
}

// RunSources is the in-memory entry point. Source bytes are bounded before
// compilation; no paths or other host data are resolved by this function.
func RunSources(ctx context.Context, source, configuration []byte) Report {
	return RunSourcesWithOptions(ctx, source, configuration, Options{})
}

// RunSourcesWithOptions adds explicit binary metadata and name filters to the
// in-memory runner. Configuration and DefaultConfiguration options are unused:
// only suite content or the supplied configuration bytes are available here.
func RunSourcesWithOptions(ctx context.Context, source, configuration []byte, options Options) (report Report) {
	start := startMeasurement()
	var spec *suiteSpec
	defer func() {
		report.DurationSeconds = start.seconds()
		report.Packages = []PackageRun{{Name: "<memory>", DurationSeconds: report.DurationSeconds}}
		if spec != nil {
			source := ""
			if len(report.SkippedSuites) > 0 {
				source = "<memory>"
			}
			report.Suites = []SuiteRun{{Name: spec.name, Source: source, DeclaredTests: len(spec.tests), Package: "<memory>", DurationSeconds: report.DurationSeconds}}
		}
		for i := range report.Results {
			report.Results[i].Package = "<memory>"
			if report.Results[i].DurationSeconds == 0 {
				report.Results[i].DurationSeconds = report.DurationSeconds
			}
		}
		for i := range report.SkippedSuites {
			report.SkippedSuites[i].Package = "<memory>"
		}
	}()
	filter, err := compileFilter(options.Includes, options.Excludes)
	if err != nil {
		return loadError(err, "invalid test name filters")
	}
	spec, err = discover(ctx, source, nil)
	if err != nil {
		return loadError(err, "suite load or resource limit failure")
	}
	if spec == nil {
		return noSuite("<memory>")
	}
	if report, excluded := selectPlatform(spec, options.Platform.resolved(), "<memory>"); excluded {
		return report
	}
	return runDiscovered(ctx, source, spec, filter, nil, func() ([]byte, error) { return configuration, nil })
}

func selectPlatform(spec *suiteSpec, binary Platform, source string) (Report, bool) {
	matched, reason, err := spec.platform.matches(binary)
	if err != nil {
		report := loadError(err, "platform selector evaluation failed")
		report.Suite = spec.name
		return report, true
	}
	if matched {
		return Report{}, false
	}
	names := make([]string, len(spec.tests))
	for i, test := range spec.tests {
		names[i] = test.name
	}
	return Report{APIVersion: APIVersion, Suite: spec.name, Scope: scope,
		SkippedSuites: []SkippedSuite{{Suite: spec.name, Source: source, Reason: reason, Tests: len(names), TestNames: names}}}, true
}

func noSuite(path string) Report {
	return Report{APIVersion: APIVersion, Scope: scope, Warnings: []Warning{{Source: path, Message: "file did not register a suite"}}}
}

func loadError(err error, message string) Report {
	return Report{APIVersion: APIVersion, Scope: scope, Results: []Result{failureResult("suite-load", err, message)}}
}

func discover(ctx context.Context, source []byte, fileContent func(string) (string, error)) (*suiteSpec, error) {
	s := newLuaState()
	s.fileContent = fileContent
	defer s.r.Close(nil)
	if err := s.run(ctx, source, nil); err != nil {
		return nil, err
	}
	// Do not retain discovery VM closures. A fresh VM replays the suite for each
	// test; copying tables would not isolate closure upvalues or global state.
	if s.spec != nil {
		for i := range s.spec.tests {
			s.spec.tests[i].verify = nil
		}
	}
	return s.spec, nil
}

func sameSpec(a, b *suiteSpec) bool {
	if a == nil || b == nil || a.name != b.name || !reflect.DeepEqual(a.platform, b.platform) || !reflect.DeepEqual(a.configuration, b.configuration) || !reflect.DeepEqual(a.environment, b.environment) || len(a.tests) != len(b.tests) {
		return false
	}
	for i := range a.tests {
		if a.tests[i].name != b.tests[i].name || !reflect.DeepEqual(a.tests[i].input, b.tests[i].input) {
			return false
		}
	}
	return true
}

func runDiscovered(ctx context.Context, source []byte, spec *suiteSpec, filter nameFilter, fileContent func(string) (string, error), fallback func() ([]byte, error)) Report {
	report := Report{APIVersion: APIVersion, Suite: spec.name, Scope: scope}
	selected := false
	for _, test := range spec.tests {
		selected = selected || filter.matches(spec.name+"/"+test.name)
	}
	if !selected {
		return report
	}
	var configurationSource []byte
	if spec.configuration != nil {
		configurationSource = []byte(*spec.configuration)
	} else {
		var err error
		configurationSource, err = fallback()
		if err != nil {
			report.Results = append(report.Results, failureResult("configuration-load", err, "cannot read fallback configuration"))
			return report
		}
	}
	conf, err := loadConfiguration(configurationSource)
	if err != nil {
		report.Results = append(report.Results, failureResult("configuration-load", err, "configuration validation failed"))
		return report
	}
	for index, test := range spec.tests {
		if filter.matches(spec.name + "/" + test.name) {
			result := runTest(ctx, source, conf, spec, index, test.name, fileContent)
			result.Suite = spec.name
			report.Results = append(report.Results, result)
		}
	}
	return report
}

func runTest(ctx context.Context, source []byte, conf *configuration.Configuration, spec *suiteSpec, index int, name string, fileContent func(string) (string, error)) (result Result) {
	start := startMeasurement()
	defer func() { result.DurationSeconds = start.seconds() }()
	s := newLuaState()
	s.fileContent = fileContent
	defer s.r.Close(nil)
	result = Result{Name: name, Status: "passed"}
	s.result = &result
	err := s.run(ctx, source, func() error {
		if !sameSpec(spec, s.spec) {
			return invalid("suite discovery changed during replay")
		}
		actual, err := evaluate(ctx, conf, s.spec.tests[index].input, s.spec.environment)
		if err != nil {
			return err
		}
		methodTable := s.r.NewTable()
		method := s.add(methodTable, "IsEqual", 4, true, s.assertEqual)
		s.testValue = s.r.NewUserDataValue(&dataView{value: map[string]any{"input": s.spec.tests[index].input, "configuration": configurationView(conf), "environment": s.spec.environment}, methods: map[string]rt.Value{"IsEqual": method}}, s.meta)
		_, err = rt.Call1(s.r.MainThread(), rt.FunctionValue(s.spec.tests[index].verify), s.testValue, s.wrap(actual))
		if s.assertionErr != nil {
			return s.assertionErr
		}
		return err
	})
	if err != nil {
		failed := failureResult(name, err, "test execution or resource limit failure")
		failed.Assertions, failed.Failures = result.Assertions, result.Failures
		return failed
	}
	if result.Assertions == 0 {
		return failureResult(name, errors.Config.Newf("no assertions"), "test did not execute any assertions")
	}
	if len(result.Failures) > 0 {
		result.Status = "failed"
	}
	return result
}
