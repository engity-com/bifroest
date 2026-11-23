package test

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

type TextOptions struct{ Verbose bool }

type textSuite struct {
	SuiteRun
	results []Result
	skipped []SkippedSuite
}

type textPackage struct {
	PackageRun
	suites []*textSuite
}

func packageName(directory string) string {
	working, err := os.Getwd()
	if err == nil {
		if physical, err := filepath.EvalSymlinks(working); err == nil {
			working = physical
		}
		if relative, err := filepath.Rel(working, directory); err == nil {
			return filepath.ToSlash(relative)
		}
	}
	return filepath.ToSlash(directory)
}

func displayText(text string) string {
	quoted := strconv.Quote(text)
	return quoted[1 : len(quoted)-1]
}

// WriteText is the compact package-oriented report. Both modes render the same
// completed model; formatting does not reexecute policy or observe new timings.
func (this Report) WriteText(out io.Writer) error {
	return this.WriteTextWithOptions(out, TextOptions{})
}

func (this Report) WriteTextWithOptions(out io.Writer, options TextOptions) error {
	var outputErr error
	printf := func(format string, args ...any) {
		if outputErr == nil {
			_, outputErr = fmt.Fprintf(out, format, args...)
		}
	}
	for _, pkg := range this.textPackages() {
		var summary Summary
		assertions, declared := 0, 0
		for _, suite := range pkg.suites {
			local, count := suite.counts()
			summary.Passed += local.Passed
			summary.Failed += local.Failed
			summary.Errors += local.Errors
			summary.Skipped += local.Skipped
			assertions += count
			declared += suite.DeclaredTests
		}
		if summary == (Summary{}) {
			reason := "no tests found"
			if declared > 0 {
				reason = "no tests selected"
			}
			printf("SKIP    %s: %s\n", displayText(pkg.Name), reason)
			continue
		}
		if options.Verbose {
			printf("=== RUN   %s\n", displayText(pkg.Name))
		}
		for _, suite := range pkg.suites {
			indent := ""
			if options.Verbose {
				indent = "    "
				if suite.Name != "" {
					printf("%s=== RUN   %s\n", indent, displayText(suite.Name))
					indent += "    "
				}
			}
			for _, test := range suite.results {
				if !options.Verbose && test.Status == "passed" {
					continue
				}
				name := test.qualifiedName()
				if options.Verbose {
					name = test.Name
				}
				printf("%s=== RUN   %s\n", indent, displayText(name))
				for _, failure := range test.Failures {
					source := "<memory>"
					if test.Source != "" {
						source = filepath.Base(test.Source)
					}
					printf("%s%s:%d: expected %s, actual %s; reason %q\n", indent, displayText(source), failure.Line, failure.Expected, failure.Actual, failure.Reason)
				}
				if test.Message != "" {
					printf("%s%s: %s\n", indent, displayText(test.Category), displayText(test.Message))
				}
				status := "PASS"
				if test.Status != "passed" {
					status = "FAIL"
				}
				noun := "assertions"
				if test.Assertions == 1 {
					noun = "assertion"
				}
				printf("%s--- %s: %s (%.3fs, %d %s)\n", indent, status, displayText(name), test.DurationSeconds, test.Assertions, noun)
			}
			if options.Verbose && suite.Name != "" {
				for _, skipped := range suite.skipped {
					for _, name := range skipped.TestNames {
						printf("%s=== RUN   %s\n", indent, displayText(name))
						printf("%s--- SKIP: %s: %s\n", indent, displayText(name), displayText(skipped.Reason))
					}
				}
				local, count := suite.counts()
				reason := ""
				if len(suite.skipped) > 0 {
					reason = ": " + displayText(suite.skipped[0].Reason)
				} else if local == (Summary{}) {
					reason = ": no tests selected"
				}
				printf("    --- %s: %s%s %s\n", textStatus(local), displayText(suite.Name), reason, textTotals(suite.DurationSeconds, count, local))
			}
		}
		if options.Verbose {
			printf("--- %s: %s %s\n", textStatus(summary), displayText(pkg.Name), textTotals(pkg.DurationSeconds, assertions, summary))
		} else {
			printf("%-7s %s %s\n", textStatus(summary), displayText(pkg.Name), textTotals(pkg.DurationSeconds, assertions, summary))
		}
	}
	if len(this.Results) == 0 {
		printf("ERROR  no tests selected\n")
	}
	summary := this.Summary()
	printf("\nRESULT: %d PASSED, %d FAILED, %d SKIPPED", summary.Passed, summary.Failed, summary.Skipped)
	if summary.Errors > 0 {
		printf(", %d ERRORS", summary.Errors)
	}
	printf("\n")
	return outputErr
}

func textStatus(summary Summary) string {
	if summary.Failed > 0 || summary.Errors > 0 {
		return "FAIL"
	}
	if summary.Passed > 0 {
		return "PASS"
	}
	return "SKIP"
}

func textTotals(seconds float64, assertions int, summary Summary) string {
	text := fmt.Sprintf("(%.3fs, assertions: %d, passed: %d, failed: %d, skipped: %d", seconds, assertions, summary.Passed, summary.Failed, summary.Skipped)
	if summary.Errors > 0 {
		text += fmt.Sprintf(", errors: %d", summary.Errors)
	}
	return text + ")"
}

func (this *textSuite) counts() (Summary, int) {
	var summary Summary
	assertions := 0
	for _, result := range this.results {
		assertions += result.Assertions
		switch result.Status {
		case "passed":
			summary.Passed++
		case "failed":
			summary.Failed++
		default:
			summary.Errors++
		}
	}
	for _, skipped := range this.skipped {
		summary.Skipped += skipped.Tests
	}
	return summary, assertions
}

func (this Report) textPackages() []*textPackage {
	var result []*textPackage
	packages := map[string]*textPackage{}
	packageFor := func(name, source string) *textPackage {
		if name == "" {
			name = "bifroest.policytest.runner"
			if source == "<memory>" {
				name = "<memory>"
			}
			if source != "" && source != "<memory>" {
				name = packageName(filepath.Dir(source))
			}
		}
		if pkg := packages[name]; pkg != nil {
			return pkg
		}
		pkg := &textPackage{PackageRun: PackageRun{Name: name}}
		packages[name] = pkg
		result = append(result, pkg)
		return pkg
	}
	for _, metadata := range this.Packages {
		packageFor(metadata.Name, "").PackageRun = metadata
	}
	type suiteID struct{ pkg, source, name string }
	suites := map[suiteID]*textSuite{}
	suiteFor := func(pkgName, source, name string) *textSuite {
		pkg := packageFor(pkgName, source)
		if source == "<memory>" {
			source = ""
		}
		id := suiteID{pkg.Name, source, name}
		if suite := suites[id]; suite != nil {
			return suite
		}
		suite := &textSuite{SuiteRun: SuiteRun{Package: pkg.Name, Name: name, Source: source}}
		suites[id] = suite
		pkg.suites = append(pkg.suites, suite)
		return suite
	}
	for _, metadata := range this.Suites {
		suiteFor(metadata.Package, metadata.Source, metadata.Name).SuiteRun = metadata
	}
	for _, test := range this.Results {
		suite := suiteFor(test.Package, test.Source, test.Suite)
		suite.results = append(suite.results, test)
	}
	for _, skipped := range this.SkippedSuites {
		suite := suiteFor(skipped.Package, skipped.Source, skipped.Suite)
		suite.skipped = append(suite.skipped, skipped)
	}
	return result
}
