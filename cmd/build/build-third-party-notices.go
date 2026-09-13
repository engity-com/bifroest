package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	gos "os"
	osexec "os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	log "github.com/echocat/slf4g"

	bib "github.com/engity-com/bifroest/internal/build"
	bbin "github.com/engity-com/bifroest/internal/build/binary"
)

const (
	thirdPartyNoticesFilename = "THIRD_PARTY_NOTICES.txt"
	thirdPartyNoticesFormat   = "1"
	goLicensesVersion         = "v2.0.1"
	goToolchainVersion        = "go1.27.0"
	goLicensesTemplate        = "cmd/build/third-party-notices.tpl"
	projectModule             = "github.com/engity-com/bifroest"
)

//go:embed third-party-license-policy.json
var thirdPartyLicensePolicyRaw []byte

type thirdPartyLicensePolicy struct {
	SchemaVersion       int                            `json:"schemaVersion"`
	AllowedLicenses     []string                       `json:"allowedLicenses"`
	CanonicalComponents []thirdPartyCanonicalComponent `json:"canonicalComponents"`
}

type thirdPartyCanonicalComponent struct {
	Name    string   `json:"name"`
	Modules []string `json:"modules"`
}

type thirdPartyLicenseRecord struct {
	Library string
	Version string
	License string
	Text    string
}

type thirdPartyModule struct {
	matches   []string
	component string
	version   string
	seen      bool
}

type thirdPartyLicenseText struct {
	licenses map[string]struct{}
	hash     string
	text     string
}

type thirdPartyNotice struct {
	name string
	hash string
	text string
}

type thirdPartyComponent struct {
	name      string
	versions  map[string]struct{}
	libraries map[string]struct{}
	licenses  map[string]thirdPartyLicenseText
	notices   map[string]thirdPartyNotice
}

func (this *buildBinary) createThirdPartyNotices(ctx context.Context, req bbin.BuildRequest, artifact *buildArtifact) (_ string, rErr error) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)
	if err != nil {
		return "", err
	}
	info, err := buildinfo.ReadFile(artifact.filepath)
	if err != nil {
		return "", fmt.Errorf("cannot inspect Go build information in %q: %w", artifact.filepath, err)
	}
	modules, err := thirdPartyModules(info, req.Platform, policy)
	if err != nil {
		return "", err
	}

	var report bytes.Buffer
	var reportWarnings bytes.Buffer
	if err := runThirdPartyLicenseTool(ctx, req, &report, &reportWarnings,
		"report",
		"--ignore="+projectModule,
		"--template="+goLicensesTemplate,
		"./cmd/bifroest",
	); err != nil {
		return "", fmt.Errorf("cannot scan third-party Go licenses for %s: %w\n%s", req.Platform, err, reportWarnings.String())
	}
	if reportWarnings.Len() > 0 {
		log.With("platform", req.Platform).With("warnings", strings.TrimSpace(reportWarnings.String())).Debug("go-licenses reported warnings")
	}
	records, err := parseThirdPartyLicenseRecords(report.Bytes())
	if err != nil {
		return "", err
	}

	temporaryDirectory, err := gos.MkdirTemp("", "bifroest-third-party-licenses-*")
	if err != nil {
		return "", fmt.Errorf("cannot create temporary third-party license directory: %w", err)
	}
	defer func() {
		if err := gos.RemoveAll(temporaryDirectory); rErr == nil && err != nil {
			rErr = err
		}
	}()
	saveDirectory := filepath.Join(temporaryDirectory, "licenses")
	var saveWarnings bytes.Buffer
	if err := runThirdPartyLicenseTool(ctx, req, gos.Stdout, &saveWarnings,
		"save",
		"--ignore="+projectModule,
		"--save_path="+saveDirectory,
		"./cmd/bifroest",
	); err != nil {
		return "", fmt.Errorf("cannot collect third-party Go notices for %s: %w\n%s", req.Platform, err, saveWarnings.String())
	}
	if saveWarnings.Len() > 0 {
		log.With("platform", req.Platform).With("warnings", strings.TrimSpace(saveWarnings.String())).Debug("go-licenses reported warnings while saving notices")
	}

	components, err := reconcileThirdPartyComponents(modules, records, saveDirectory, policy)
	if err != nil {
		return "", err
	}
	target, err := gos.CreateTemp("", "bifroest-third-party-notices-*.txt")
	if err != nil {
		return "", fmt.Errorf("cannot create third-party notices: %w", err)
	}
	targetName := target.Name()
	success := false
	defer func() {
		if !success {
			_ = gos.Remove(targetName)
		}
	}()
	if err := renderThirdPartyNotices(target, req.Platform, info, components); err != nil {
		_ = target.Close()
		return "", err
	}
	if err := target.Close(); err != nil {
		return "", fmt.Errorf("cannot close third-party notices %q: %w", targetName, err)
	}
	success = true
	return targetName, nil
}

func runThirdPartyLicenseTool(ctx context.Context, req bbin.BuildRequest, stdout, stderr io.Writer, args ...string) error {
	executable, err := verifiedGoTool("go-licenses", "github.com/google/go-licenses/v2", goLicensesVersion)
	if err != nil {
		return err
	}
	cmd := osexec.CommandContext(ctx, executable, args...)
	cmd.Env = req.Environment().Strings()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %w", cmd, err)
	}
	return nil
}

func readThirdPartyLicensePolicy(raw []byte) (thirdPartyLicensePolicy, error) {
	var result thirdPartyLicensePolicy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, fmt.Errorf("cannot parse third-party license policy: %w", err)
	}
	if result.SchemaVersion != 1 {
		return result, fmt.Errorf("unsupported third-party license policy schema version %d", result.SchemaVersion)
	}
	allowed := make(map[string]struct{}, len(result.AllowedLicenses))
	for _, license := range result.AllowedLicenses {
		if license == "" {
			return result, fmt.Errorf("third-party license policy contains an empty license")
		}
		if _, exists := allowed[license]; exists {
			return result, fmt.Errorf("third-party license policy contains duplicate license %q", license)
		}
		allowed[license] = struct{}{}
	}
	modules := make(map[string]string)
	for _, component := range result.CanonicalComponents {
		if component.Name == "" || len(component.Modules) == 0 {
			return result, fmt.Errorf("third-party license policy contains an incomplete canonical component")
		}
		containsName := false
		for _, module := range component.Modules {
			if existing, exists := modules[module]; exists {
				return result, fmt.Errorf("module %q belongs to canonical components %q and %q", module, existing, component.Name)
			}
			modules[module] = component.Name
			containsName = containsName || module == component.Name
		}
		if !containsName {
			return result, fmt.Errorf("canonical component %q does not include its own module", component.Name)
		}
	}
	return result, nil
}

func thirdPartyModules(info *debug.BuildInfo, platform bib.Platform, policy thirdPartyLicensePolicy) ([]*thirdPartyModule, error) {
	if info.Path != projectModule+"/cmd/bifroest" {
		return nil, fmt.Errorf("built binary contains unexpected main package %q", info.Path)
	}
	if info.GoVersion != goToolchainVersion {
		return nil, fmt.Errorf("built binary uses Go %q instead of %q", info.GoVersion, goToolchainVersion)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	expectedCgo := "0"
	if platform.Edition.String() == "extended" {
		expectedCgo = "1"
	}
	expectedSettings := map[string]string{
		"GOOS":        platform.Os.String(),
		"GOARCH":      platform.Arch.Bare(),
		"CGO_ENABLED": expectedCgo,
	}
	switch platform.Arch.String() {
	case "386":
		expectedSettings["GO386"] = "sse2"
	case "amd64":
		expectedSettings["GOAMD64"] = "v1"
	case "armv6":
		expectedSettings["GOARM"] = "6"
	case "armv7":
		expectedSettings["GOARM"] = "7"
	case "arm64":
		expectedSettings["GOARM64"] = "v8.0"
	case "riscv64":
		expectedSettings["GORISCV64"] = "rva20u64"
	}
	for key, expected := range expectedSettings {
		if actual := settings[key]; actual != expected {
			return nil, fmt.Errorf("built binary setting %s=%q does not match expected value %q for platform %s", key, actual, expected, platform)
		}
	}
	canonical := canonicalModuleMap(policy)
	result := make([]*thirdPartyModule, 0, len(info.Deps))
	for _, dependency := range info.Deps {
		effective := dependency
		if dependency.Replace != nil {
			effective = dependency.Replace
		}
		component := effective.Path
		if configured, exists := canonical[effective.Path]; exists {
			component = configured
		} else if configured, exists := canonical[dependency.Path]; exists {
			component = configured
		}
		matches := []string{dependency.Path}
		if effective.Path != dependency.Path {
			matches = append(matches, effective.Path)
		}
		result = append(result, &thirdPartyModule{matches: matches, component: component, version: effective.Version})
	}
	return result, nil
}

func canonicalModuleMap(policy thirdPartyLicensePolicy) map[string]string {
	result := make(map[string]string)
	for _, component := range policy.CanonicalComponents {
		for _, module := range component.Modules {
			result[module] = component.Name
		}
	}
	return result
}

func parseThirdPartyLicenseRecords(raw []byte) ([]thirdPartyLicenseRecord, error) {
	var result []thirdPartyLicenseRecord
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		if scanner.Text() == "" {
			continue
		}
		parts := strings.SplitN(scanner.Text(), "\t", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid go-licenses report line %q", scanner.Text())
		}
		values := make([]string, len(parts))
		for i, part := range parts {
			value, err := strconv.Unquote(part)
			if err != nil {
				return nil, fmt.Errorf("cannot decode go-licenses report field: %w", err)
			}
			values[i] = value
		}
		result = append(result, thirdPartyLicenseRecord{
			Library: values[0],
			Version: values[1],
			License: values[2],
			Text:    normalizeNoticeText(values[3]),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot read go-licenses report: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("go-licenses report is empty")
	}
	return result, nil
}

func reconcileThirdPartyComponents(modules []*thirdPartyModule, records []thirdPartyLicenseRecord, savedDirectory string, policy thirdPartyLicensePolicy) ([]thirdPartyComponent, error) {
	allowed := make(map[string]struct{}, len(policy.AllowedLicenses))
	for _, license := range policy.AllowedLicenses {
		allowed[license] = struct{}{}
	}
	components := make(map[string]*thirdPartyComponent)
	componentFor := func(module *thirdPartyModule) *thirdPartyComponent {
		result := components[module.component]
		if result == nil {
			result = &thirdPartyComponent{
				name:      module.component,
				versions:  make(map[string]struct{}),
				libraries: make(map[string]struct{}),
				licenses:  make(map[string]thirdPartyLicenseText),
				notices:   make(map[string]thirdPartyNotice),
			}
			components[module.component] = result
		}
		if module.version != "" {
			result.versions[module.version] = struct{}{}
		}
		return result
	}

	for _, record := range records {
		if record.Library == "" || record.License == "" || record.Text == "" || strings.EqualFold(record.License, "unknown") {
			return nil, fmt.Errorf("incomplete third-party license record for %q", record.Library)
		}
		if _, exists := allowed[record.License]; !exists {
			return nil, fmt.Errorf("third-party license %q for %q is not allowed", record.License, record.Library)
		}
		module := matchThirdPartyModule(record.Library, modules)
		if module == nil {
			return nil, fmt.Errorf("cannot match third-party library %q to built modules", record.Library)
		}
		if record.Version == "" || strings.TrimSuffix(record.Version, "+incompatible") != strings.TrimSuffix(module.version, "+incompatible") {
			return nil, fmt.Errorf("third-party library %q reports version %q instead of %q", record.Library, record.Version, module.version)
		}
		module.seen = true
		component := componentFor(module)
		component.libraries[canonicalLibraryName(record.Library)] = struct{}{}
		hash := sha256.Sum256([]byte(record.Text))
		key := hex.EncodeToString(hash[:])
		license := component.licenses[key]
		if license.licenses == nil {
			license = thirdPartyLicenseText{licenses: make(map[string]struct{}), hash: key, text: record.Text}
		}
		license.licenses[record.License] = struct{}{}
		component.licenses[key] = license
	}
	for _, module := range modules {
		if !module.seen {
			return nil, fmt.Errorf("built module %q has no third-party license record", module.component)
		}
	}

	err := filepath.WalkDir(savedDirectory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasPrefix(strings.ToUpper(entry.Name()), "NOTICE") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("saved notice %q is not a regular file", filename)
		}
		relative, err := filepath.Rel(savedDirectory, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		module := matchThirdPartyModule(relative, modules)
		if module == nil {
			return fmt.Errorf("cannot match saved notice %q to built modules", relative)
		}
		raw, err := gos.ReadFile(filename)
		if err != nil {
			return err
		}
		text := normalizeNoticeText(string(raw))
		hash := sha256.Sum256([]byte(text))
		name := canonicalLibraryName(relative)
		componentFor(module).notices[name+":"+hex.EncodeToString(hash[:])] = thirdPartyNotice{name: name, hash: hex.EncodeToString(hash[:]), text: text}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cannot inspect saved third-party notices: %w", err)
	}

	result := make([]thirdPartyComponent, 0, len(components))
	for _, component := range components {
		result = append(result, *component)
	}
	slices.SortFunc(result, func(a, b thirdPartyComponent) int { return strings.Compare(a.name, b.name) })
	return result, nil
}

func matchThirdPartyModule(name string, modules []*thirdPartyModule) *thirdPartyModule {
	var result *thirdPartyModule
	matchedLength := -1
	for _, module := range modules {
		for _, candidate := range module.matches {
			if (name == candidate || strings.HasPrefix(name, candidate+"/")) && len(candidate) > matchedLength {
				result = module
				matchedLength = len(candidate)
			}
		}
	}
	return result
}

func canonicalLibraryName(name string) string {
	const legacy = "github.com/docker/docker"
	if name == legacy || strings.HasPrefix(name, legacy+"/") {
		return "github.com/moby/moby" + strings.TrimPrefix(name, legacy)
	}
	return name
}

func normalizeNoticeText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.TrimRight(value, "\n") + "\n"
}

func renderThirdPartyNotices(target io.Writer, platform bib.Platform, info *debug.BuildInfo, components []thirdPartyComponent) error {
	write := func(format string, args ...any) error {
		_, err := fmt.Fprintf(target, format, args...)
		return err
	}
	if err := write("Bifroest THIRD_PARTY_NOTICES\nFormat-Version: %s\nTarget: %s/%s/%s\nGo-Version: %s\nGenerator: github.com/google/go-licenses/v2 %s\n\n", thirdPartyNoticesFormat, platform.Os, platform.Arch, platform.Edition, info.GoVersion, goLicensesVersion); err != nil {
		return err
	}
	if err := write("Bundled components not represented as external Go modules:\n- Go standard library %s; BSD-3-Clause; license: LICENSES/BSD-3-Clause-Go-1.27.0.txt\n- Modified Go standard library sources from go1.22.0; BSD-3-Clause; license: LICENSES/BSD-3-Clause.txt\n- Mozilla NSS CA certificate data; MPL-2.0; license: LICENSES/MPL-2.0.txt; provenance: pkg/crypto/ca-certs.crt\n\n", info.GoVersion); err != nil {
		return err
	}
	for _, component := range components {
		versions := sortedSet(component.versions)
		libraries := sortedSet(component.libraries)
		licenses := make([]thirdPartyLicenseText, 0, len(component.licenses))
		for _, license := range component.licenses {
			licenses = append(licenses, license)
		}
		slices.SortFunc(licenses, func(a, b thirdPartyLicenseText) int {
			if result := strings.Compare(strings.Join(sortedSet(a.licenses), ", "), strings.Join(sortedSet(b.licenses), ", ")); result != 0 {
				return result
			}
			return strings.Compare(a.hash, b.hash)
		})
		notices := make([]thirdPartyNotice, 0, len(component.notices))
		for _, notice := range component.notices {
			notices = append(notices, notice)
		}
		slices.SortFunc(notices, func(a, b thirdPartyNotice) int {
			if result := strings.Compare(a.name, b.name); result != 0 {
				return result
			}
			return strings.Compare(a.hash, b.hash)
		})

		if err := write("================================================================================\nComponent: %s\nVersions: %s\nLibraries:\n", component.name, strings.Join(versions, ", ")); err != nil {
			return err
		}
		for _, library := range libraries {
			if err := write("- %s\n", library); err != nil {
				return err
			}
		}
		for _, license := range licenses {
			if err := write("\n--------------------------------------------------------------------------------\nLicenses: %s\nText-SHA256: %s\n--------------------------------------------------------------------------------\n%s", strings.Join(sortedSet(license.licenses), ", "), license.hash, license.text); err != nil {
				return err
			}
		}
		for _, notice := range notices {
			if err := write("\n--------------------------------------------------------------------------------\nNotice: %s\nText-SHA256: %s\n--------------------------------------------------------------------------------\n%s", notice.name, notice.hash, notice.text); err != nil {
				return err
			}
		}
		if err := write("\n"); err != nil {
			return err
		}
	}
	return nil
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}
