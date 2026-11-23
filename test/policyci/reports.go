package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Deliberately independent wire types: importing the runner's reporter/summary
// here would make this check capable of repeating the same implementation bug.
const apiVersion = "bifroest.engity.org/testing/v1alpha1"
const scope = "post-authentication/session-target"

type counts struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

func (this counts) total() int { return this.Passed + this.Failed + this.Skipped + this.Errors }

type jsonFailure struct {
	Line             int
	Expected, Actual string
	Reason           string
}

type jsonResult struct {
	Package                                        string
	DurationSeconds                                float64
	Suite, Source, Name, Status, Category, Message string
	Assertions                                     int
	Failures                                       []jsonFailure
}

type jsonReport struct {
	DurationSeconds float64
	Packages        []struct {
		Name, Directory string
		DurationSeconds float64
	}
	Suites []struct {
		Name, Source, Package string
		DurationSeconds       float64
		DeclaredTests         int
	}
	APIVersion, Scope, Suite string
	Summary                  counts
	Results                  []jsonResult
	Warnings                 []json.RawMessage
	SkippedSuites            []struct {
		Suite, Source, Reason, Package string
		Tests                          int
		TestNames                      []string
	}
}

type xmlCounts struct {
	Tests    int `xml:"tests,attr"`
	Failures int `xml:"failures,attr"`
	Errors   int `xml:"errors,attr"`
	Skipped  int `xml:"skipped,attr"`
}

type xmlProblem struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type xmlCase struct {
	Time       string       `xml:"time,attr"`
	Name       string       `xml:"name,attr"`
	ClassName  string       `xml:"classname,attr"`
	File       string       `xml:"file,attr"`
	Line       int          `xml:"line,attr"`
	Assertions int          `xml:"assertions,attr"`
	Failures   []xmlProblem `xml:"failure"`
	Errors     []xmlProblem `xml:"error"`
	Skips      []xmlProblem `xml:"skipped"`
}

type xmlReport struct {
	Name    string   `xml:"name,attr"`
	Time    string   `xml:"time,attr"`
	XMLName xml.Name `xml:"testsuites"`
	xmlCounts
	Suites []struct {
		ID   int    `xml:"id,attr"`
		Time string `xml:"time,attr"`
		Name string `xml:"name,attr"`
		xmlCounts
		Properties []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"properties>property"`
		Cases    []xmlCase `xml:"testcase"`
		Warnings string    `xml:"system-err"`
	} `xml:"testsuite"`
}

type caseID struct{ source, suite, name string }
type expectedCase struct {
	jsonResult
	skipReason string
}

func readJSON(path string) (jsonReport, error) {
	var report jsonReport
	raw, err := os.ReadFile(path)
	if err != nil {
		return report, err
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return report, err
	}
	if report.APIVersion != apiVersion || report.Scope != scope {
		return report, fmt.Errorf("unexpected JSON API version or scope")
	}
	return report, nil
}

func validateReports(jsonPath, xmlPath string, want counts) error {
	document, err := readJSON(jsonPath)
	if err != nil {
		return err
	}
	if document.Summary != want || len(document.Warnings) != 0 {
		return fmt.Errorf("JSON summary/warnings differ: got %+v, want %+v", document.Summary, want)
	}
	expected := map[caseID]expectedCase{}
	add := func(result jsonResult, reason string) error {
		id := caseID{result.Source, result.Suite, result.Name}
		if _, exists := expected[id]; exists || result.Name == "" {
			return fmt.Errorf("duplicate or empty JSON testcase: %+v", id)
		}
		expected[id] = expectedCase{result, reason}
		return nil
	}
	var observed counts
	for _, result := range document.Results {
		if result.Source == "" || !strings.HasSuffix(result.Source, "_bftest.lua") {
			return fmt.Errorf("result lost its source path")
		}
		switch result.Status {
		case "passed":
			observed.Passed++
			if result.Assertions < 1 || len(result.Failures) != 0 {
				return fmt.Errorf("invalid passing assertion details")
			}
		case "failed":
			observed.Failed++
			if len(result.Failures) == 0 || result.Failures[0].Line <= 0 || result.Assertions < 1 {
				return fmt.Errorf("assertion failure lost its details/line")
			}
		case "error":
			observed.Errors++
			if result.Category != "config" || result.Message == "" {
				return fmt.Errorf("invalid-input error lost its category/message")
			}
		default:
			return fmt.Errorf("unsupported JSON outcome: %q", result.Status)
		}
		if err := add(result, ""); err != nil {
			return err
		}
	}
	for _, skipped := range document.SkippedSuites {
		if skipped.Tests != len(skipped.TestNames) || skipped.Tests < 1 || skipped.Reason == "" || skipped.Source == "" {
			return fmt.Errorf("platform exclusion lost declared names/source/reason")
		}
		observed.Skipped += skipped.Tests
		for _, name := range skipped.TestNames {
			if err := add(jsonResult{Suite: skipped.Suite, Source: skipped.Source, Name: name, Status: "skipped"}, skipped.Reason); err != nil {
				return err
			}
		}
	}
	if len(document.Results) == 0 {
		observed.Errors++
		if err := add(jsonResult{Name: "no-tests-selected", Status: "error", Category: "system", Message: "no tests selected"}, ""); err != nil {
			return err
		}
	}
	if observed != want {
		return fmt.Errorf("JSON outcomes do not support their summary: %+v", observed)
	}
	raw, err := os.ReadFile(xmlPath)
	if err != nil {
		return err
	}
	var report xmlReport
	if err := xml.Unmarshal(raw, &report); err != nil {
		return err
	}
	if err := compareCounts(report.xmlCounts, want); err != nil {
		return err
	}
	seenGroups := map[[2]string]bool{}
	var all counts
	for _, suite := range report.Suites {
		properties := map[string]string{}
		for _, property := range suite.Properties {
			if _, exists := properties[property.Name]; exists {
				return fmt.Errorf("duplicate JUnit property")
			}
			properties[property.Name] = property.Value
		}
		if properties["apiVersion"] != apiVersion || properties["scope"] != scope || properties["authenticationAssumed"] != "true" {
			return fmt.Errorf("JUnit lost offline-boundary metadata")
		}
		group := [2]string{properties["source"], suite.Name}
		if seenGroups[group] {
			return fmt.Errorf("duplicate JUnit source/suite group")
		}
		seenGroups[group] = true
		var local counts
		for _, item := range suite.Cases {
			name := suite.Name
			if name == "bifroest.policytest.runner" {
				name = ""
			}
			id := caseID{item.File, name, item.Name}
			result, exists := expected[id]
			if !exists || item.ClassName != suite.Name || item.File != properties["source"] {
				return fmt.Errorf("unknown/duplicate/misgrouped JUnit testcase: %+v", id)
			}
			delete(expected, id)
			if err := compareCase(item, result); err != nil {
				return err
			}
			switch result.Status {
			case "passed":
				local.Passed++
			case "failed":
				local.Failed++
			case "error":
				local.Errors++
			case "skipped":
				local.Skipped++
			}
		}
		if err := compareCounts(suite.xmlCounts, local); err != nil {
			return err
		}
		all.Passed += local.Passed
		all.Failed += local.Failed
		all.Errors += local.Errors
		all.Skipped += local.Skipped
	}
	if len(expected) != 0 || all != want {
		return fmt.Errorf("JUnit omitted outcomes or has inconsistent totals")
	}
	return nil
}

func compareCounts(got xmlCounts, want counts) error {
	if got != (xmlCounts{Tests: want.total(), Failures: want.Failed, Errors: want.Errors, Skipped: want.Skipped}) {
		return fmt.Errorf("JUnit counts differ: got %+v, want %+v", got, want)
	}
	return nil
}

func compareCase(item xmlCase, result expectedCase) error {
	status := "passed"
	if len(item.Failures)+len(item.Errors)+len(item.Skips) > 1 {
		return fmt.Errorf("JUnit testcase has multiple status nodes")
	}
	if len(item.Failures) > 0 {
		status = "failed"
	}
	if len(item.Errors) > 0 {
		status = "error"
	}
	if len(item.Skips) > 0 {
		status = "skipped"
	}
	if status != result.Status || item.Assertions != result.Assertions {
		return fmt.Errorf("JUnit status/assertions differ for %q", item.Name)
	}
	var problem xmlProblem
	switch status {
	case "failed":
		problem = item.Failures[0]
		if problem.Type != "assertion" || problem.Message == "" {
			return fmt.Errorf("JUnit assertion failure lost its type/message")
		}
	case "error":
		problem = item.Errors[0]
		if problem.Type != result.Category || problem.Message != result.Message {
			return fmt.Errorf("JUnit execution error lost its category/message")
		}
	case "skipped":
		if item.Skips[0].Message != result.skipReason {
			return fmt.Errorf("JUnit platform skip lost its reason")
		}
	}
	line := 0
	for _, failure := range result.Failures {
		if line == 0 && failure.Line > 0 {
			line = failure.Line
		}
		for _, detail := range []string{fmt.Sprintf("%s:%d:", result.Source, failure.Line), failure.Expected, failure.Actual, fmt.Sprintf("%q", failure.Reason)} {
			if !strings.Contains(problem.Body, detail) {
				return fmt.Errorf("JUnit failure body lost assertion details")
			}
		}
	}
	if item.Line != line {
		return fmt.Errorf("JUnit assertion line differs")
	}
	return nil
}

func validateReportFailure(folder string, sentinel []byte) error {
	path := filepath.Join(folder, "blocked")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, sentinel) {
		return fmt.Errorf("non-directory parent was modified")
	}
	document, err := readJSON(filepath.Join(folder, "report.json"))
	if err != nil {
		return err
	}
	if document.Summary != (counts{Passed: 1}) {
		return fmt.Errorf("later JUnit failure changed the earlier JSON report")
	}
	diagnostics, err := os.ReadFile(filepath.Join(folder, "cli.stderr.txt"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(diagnostics), "cannot write offline policy test report") || !strings.Contains(string(diagnostics), "blocked") || !strings.Contains(string(diagnostics), "mkdir") {
		return fmt.Errorf("report failure lost its target or underlying filesystem cause")
	}
	return nil
}

func validateMeasurements(jsonPath, xmlPath string) error {
	document, err := readJSON(jsonPath)
	if err != nil {
		return err
	}
	positive := func(seconds float64) bool { return seconds > 0 && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) }
	if !positive(document.DurationSeconds) || len(document.Packages) == 0 {
		return fmt.Errorf("missing measured run duration/packages")
	}
	packages := map[string]bool{}
	for _, pkg := range document.Packages {
		if pkg.Name == "" || !positive(pkg.DurationSeconds) {
			return fmt.Errorf("invalid package name/duration")
		}
		packages[pkg.Name] = true
	}
	raw, err := os.ReadFile(xmlPath)
	if err != nil {
		return err
	}
	var report xmlReport
	if err := xml.Unmarshal(raw, &report); err != nil {
		return err
	}
	check := func(text string, seconds float64) error {
		value, err := strconv.ParseFloat(text, 64)
		if err != nil || !positive(value) || math.Abs(value-seconds) > 1e-9 {
			return fmt.Errorf("JUnit time differs from measured JSON duration")
		}
		return nil
	}
	if err := check(report.Time, document.DurationSeconds); err != nil {
		return err
	}
	for _, result := range document.Results {
		if !packages[result.Package] {
			return fmt.Errorf("testcase lost its package")
		}
		if result.Status != "passed" && result.Status != "failed" {
			continue
		}
		if !positive(result.DurationSeconds) {
			return fmt.Errorf("missing testcase duration")
		}
		found := false
		for _, suite := range report.Suites {
			for _, item := range suite.Cases {
				if item.File == result.Source && item.Name == result.Name {
					found = true
					if err := check(item.Time, result.DurationSeconds); err != nil {
						return err
					}
				}
			}
		}
		if !found {
			return fmt.Errorf("timed testcase missing from JUnit")
		}
	}
	for _, metadata := range document.Suites {
		if !packages[metadata.Package] || !positive(metadata.DurationSeconds) {
			return fmt.Errorf("missing suite package/duration")
		}
		found := false
		for _, suite := range report.Suites {
			if suite.Name != metadata.Name {
				continue
			}
			properties := map[string]string{}
			for _, property := range suite.Properties {
				properties[property.Name] = property.Value
			}
			if properties["source"] == metadata.Source && properties["package"] == metadata.Package {
				found = true
				if err := check(suite.Time, metadata.DurationSeconds); err != nil {
					return err
				}
			}
		}
		if !found {
			return fmt.Errorf("timed suite/package missing from JUnit")
		}
	}
	return nil
}

func validateText(folder string, want counts) error {
	raw, err := os.ReadFile(filepath.Join(folder, "cli.stdout.txt"))
	if err != nil {
		return err
	}
	text := fmt.Sprintf("RESULT: %d PASSED, %d FAILED, %d SKIPPED", want.Passed, want.Failed, want.Skipped)
	if want.Errors > 0 {
		text += fmt.Sprintf(", %d ERRORS", want.Errors)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(raw)), text) {
		return fmt.Errorf("text summary differs from JSON/JUnit/process expectations")
	}
	return nil
}

func validateRed(path string) error {
	document, err := readJSON(path)
	if err != nil {
		return err
	}
	if len(document.Results) != 1 {
		return fmt.Errorf("expected exactly one deliberately red test")
	}
	red := document.Results[0]
	line := 19
	switch filepath.Base(red.Source) {
	case "red-unix_bftest.lua":
	case "red-windows_bftest.lua":
		line = 18
	default:
		return fmt.Errorf("unexpected deliberately red fixture source")
	}
	if red.Name != "wrong-target-contract" || len(red.Failures) != 1 {
		return fmt.Errorf("deliberately red fixture identity/details differ")
	}
	failure := red.Failures[0]
	if failure.Line != line || failure.Expected != `"not-alice"` || failure.Reason != "Deliberately red smoke test" {
		return fmt.Errorf("deliberately red fixture lost its known line/value/reason")
	}
	return nil
}
