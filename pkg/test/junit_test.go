package test

import (
	"bytes"
	"encoding/xml"
	"io"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/stretchr/testify/require"
)

func readJUnit(t *testing.T, report Report) (junitReport, string) {
	t.Helper()
	var output bytes.Buffer
	require.NoError(t, report.WriteJUnit(&output))
	require.True(t, strings.HasPrefix(output.String(), xml.Header))
	var parsed junitReport
	require.NoError(t, xml.Unmarshal(output.Bytes(), &parsed))
	require.Equal(t, "testsuites", parsed.XMLName.Local)
	var tests, failures, executionErrors, skipped int
	for _, suite := range parsed.Suites {
		require.Equal(t, suite.Tests, len(suite.Cases))
		var caseFailures, caseErrors, caseSkips int
		for _, test := range suite.Cases {
			states := 0
			if test.Failure != nil {
				caseFailures++
				states++
			}
			if test.Error != nil {
				caseErrors++
				states++
			}
			if test.Skip != nil {
				caseSkips++
				states++
			}
			require.LessOrEqual(t, states, 1, "a testcase has at most one outcome")
		}
		require.Equal(t, suite.Failures, caseFailures)
		require.Equal(t, suite.Errors, caseErrors)
		require.Equal(t, suite.Skipped, caseSkips)
		tests += suite.Tests
		failures += suite.Failures
		executionErrors += suite.Errors
		skipped += suite.Skipped
	}
	require.Equal(t, parsed.Tests, tests)
	require.Equal(t, parsed.Failures, failures)
	require.Equal(t, parsed.Errors, executionErrors)
	require.Equal(t, parsed.Skipped, skipped)
	summary := report.Summary()
	require.Equal(t, summary.Passed+summary.Failed+summary.Errors+summary.Skipped, parsed.Tests)
	require.Equal(t, summary.Failed, parsed.Failures)
	require.Equal(t, summary.Errors, parsed.Errors)
	require.Equal(t, summary.Skipped, parsed.Skipped)
	return parsed, output.String()
}

func TestJUnitUsesTheSharedOutcomesWithoutCountingAssertionsAsTests(t *testing.T) {
	source := filepath.Join("fixture", "red_bftest.lua")
	report := Report{APIVersion: APIVersion, Scope: scope,
		SkippedSuites: []SkippedSuite{{Suite: "windows", Source: "windows_bftest.lua", Reason: "os does not match platform", Tests: 2, TestNames: []string{"first", "second"}}},
		Results: []Result{
			{Suite: "suite", Source: "green_bftest.lua", Name: "green", Status: "passed", Assertions: 11},
			{Suite: "suite", Source: source, Name: "red", Status: "failed", Assertions: 2, Failures: []Failure{{Line: 20, Expected: `"expected"`, Actual: `"actual"`, Reason: "first reason"}, {Line: 24, Expected: "true", Actual: "false", Reason: "second reason"}}},
			{Suite: "suite", Source: source, Name: "error-after-assertion", Status: "error", Category: "config", Message: "test execution or resource limit failure", Assertions: 1, Failures: []Failure{{Line: 30, Expected: "true", Actual: "false", Reason: "recorded before fatal error"}}},
		},
	}
	parsed, raw := readJUnit(t, report)
	require.Equal(t, 5, parsed.Tests)
	require.Equal(t, 1, parsed.Failures)
	require.Equal(t, 1, parsed.Errors)
	require.Equal(t, 2, parsed.Skipped)
	require.Len(t, parsed.Suites, 3, "identical suite names from different physical sources stay separate")
	var red, executionError junitCase
	for _, suite := range parsed.Suites {
		properties := map[string]string{}
		for _, property := range suite.Properties {
			properties[property.Name] = property.Value
		}
		require.Equal(t, scope, properties["scope"])
		require.Equal(t, APIVersion, properties["apiVersion"])
		require.Equal(t, "true", properties["authenticationAssumed"])
		for _, test := range suite.Cases {
			if test.Name == "red" {
				red = test
			}
			if test.Name == "error-after-assertion" {
				executionError = test
			}
		}
	}
	require.Equal(t, source, red.File)
	require.Equal(t, int32(20), red.Line)
	require.Equal(t, 2, red.Assertions)
	require.Contains(t, red.Failure.Body, source+`:20: expected "expected", actual "actual"; reason "first reason"`)
	require.Contains(t, red.Failure.Body, source+`:24:`)
	require.Equal(t, "2 assertions failed", red.Failure.Message)
	require.Equal(t, "config", executionError.Error.Type)
	require.Nil(t, executionError.Failure)
	require.Contains(t, executionError.Error.Body, "recorded before fatal error")
	require.NotContains(t, raw, " timestamp=")
	require.NotContains(t, raw, " time=")
	_, again := readJUnit(t, report)
	require.Equal(t, raw, again, "serialization is deterministic and has no clock/random observations")
}

func TestJUnitEmptyAndExcludedSelectionsRemainErrors(t *testing.T) {
	for _, report := range []Report{
		{},
		{SkippedSuites: []SkippedSuite{{Suite: "excluded", Tests: 2, TestNames: []string{"one", "two"}, Reason: "arch does not match platform"}}},
		{Warnings: []Warning{{Source: "helper_bftest.lua", Message: "file did not register a suite"}}},
	} {
		parsed, raw := readJUnit(t, report)
		require.Equal(t, 1, parsed.Errors)
		require.Equal(t, 2, report.ExitCode())
		require.Contains(t, raw, `name="no-tests-selected"`)
		require.Contains(t, raw, `message="no tests selected"`)
		if len(report.Warnings) > 0 {
			require.Contains(t, raw, "<system-err>")
			require.Contains(t, raw, "helper_bftest.lua")
		}
	}
}

func TestJUnitRetainsActualSkippedNamesBeforeNameFilters(t *testing.T) {
	source := []byte(`local tests={}
for i=1,3 do tests[i]={name="case-"..i,input=object{},verify=function(t,actual)t:IsEqual(true,true)end}end
suite{name="excluded",platform={os={"windows"}},environment=object{accounts=list{}},tests=tests}`)
	report := RunSourcesWithOptions(t.Context(), source, nil, Options{Platform: Platform{OS: "linux"}, Includes: []string{"/case-1$"}})
	require.Equal(t, []string{"case-1", "case-2", "case-3"}, report.SkippedSuites[0].TestNames)
	parsed, _ := readJUnit(t, report)
	require.Equal(t, 3, parsed.Skipped)
	require.Equal(t, 1, parsed.Errors)
	require.Equal(t, 4, parsed.Tests)
	var names []string
	for _, suite := range parsed.Suites {
		for _, test := range suite.Cases {
			if test.Skip != nil {
				names = append(names, test.Name)
				require.Equal(t, "os does not match platform", test.Skip.Message)
			}
		}
	}
	require.Equal(t, report.SkippedSuites[0].TestNames, names)
}

func TestJUnitDoesNotHideUnknownOrContradictoryReportStates(t *testing.T) {
	parsed, _ := readJUnit(t, Report{Results: []Result{{Name: "unknown", Status: "future-state"}}})
	require.Equal(t, 1, parsed.Errors)
	require.Contains(t, parsed.Suites[0].Cases[0].Error.Message, "unsupported result status")
	for _, report := range []Report{
		{SkippedSuites: []SkippedSuite{{Tests: 1}}},
		{SkippedSuites: []SkippedSuite{{Tests: -1}}},
		{SkippedSuites: []SkippedSuite{{Tests: 1, TestNames: []string{""}}}},
		{SkippedSuites: []SkippedSuite{{Tests: 2, TestNames: []string{"duplicate", "duplicate"}}}},
		{Results: []Result{{Name: "contradictory", Status: "passed", Failures: []Failure{{Line: 1}}}}},
		{Results: []Result{{Name: "negative", Status: "passed", Assertions: -1}}},
	} {
		var output bytes.Buffer
		err := report.WriteJUnit(&output)
		require.Error(t, err)
		require.Empty(t, output.String(), "invalid reports are rejected before even writing the XML header")
		category, ok := errors.IsError(err)
		require.True(t, ok)
		require.Equal(t, errors.Config, category.Type)
	}
}

func TestJUnitEscapesMarkupAndSpellsOutXMLForbiddenData(t *testing.T) {
	file := "bad\x00\xff_bftest.lua"
	message := "reason <&\"' ]]><fake> \x01 \ufffe \ufffd \U0001f600"
	report := Report{APIVersion: APIVersion, Scope: scope, Results: []Result{{Name: "case <&\"'", Suite: "suite <&", Source: file, Status: "failed", Failures: []Failure{{Line: 7, Expected: message, Actual: "actual\x00", Reason: message}}}}}
	parsed, raw := readJUnit(t, report)
	item := parsed.Suites[0].Cases[0]
	require.Equal(t, `bad\u0000\xff_bftest.lua`, item.File)
	require.Equal(t, "case <&\"'", item.Name)
	require.Contains(t, item.Failure.Body, `\u0001`)
	require.Contains(t, item.Failure.Body, `\ufffe`)
	require.Contains(t, item.Failure.Body, "\ufffd")
	require.Contains(t, item.Failure.Body, "\U0001f600")
	require.Contains(t, raw, "&lt;fake&gt;")
	require.NotContains(t, raw, "<fake>")
	require.NotContains(t, raw, "\x00")
	require.NotContains(t, raw, "\xff")
}

type junitShortWriter struct{}

func (junitShortWriter) Write([]byte) (int, error) { return 0, nil }

type junitLimitedWriter struct{ remaining int }

func (this *junitLimitedWriter) Write(p []byte) (int, error) {
	if len(p) > this.remaining {
		n := this.remaining
		this.remaining = 0
		return n, io.ErrClosedPipe
	}
	this.remaining -= len(p)
	return len(p), nil
}

func TestJUnitPreservesOutputErrorsAndDoesNotInventMemoryLocations(t *testing.T) {
	report := Report{Results: []Result{{Name: "memory", Status: "failed", Failures: []Failure{{Expected: "true", Actual: "false"}}}}}
	parsed, _ := readJUnit(t, report)
	require.Empty(t, parsed.Suites[0].Cases[0].File)
	require.Zero(t, parsed.Suites[0].Cases[0].Line)
	require.Contains(t, parsed.Suites[0].Cases[0].Failure.Body, "<memory>: expected")
	require.ErrorContains(t, report.WriteJUnit(rejectedReportWriter{}), "report output unavailable")
	require.ErrorIs(t, report.WriteJUnit(junitShortWriter{}), io.ErrShortWrite)
	var complete bytes.Buffer
	require.NoError(t, report.WriteJUnit(&complete))
	for _, limit := range []int{len(xml.Header), complete.Len() - 1} {
		require.ErrorIs(t, report.WriteJUnit(&junitLimitedWriter{remaining: limit}), io.ErrClosedPipe)
	}
}

func TestJUnitUsesMeasuredRunSuiteAndTestDurations(t *testing.T) {
	report := run(t, `t:IsEqual(true,true)`)
	parsed, raw := readJUnit(t, report)
	require.NotEmpty(t, parsed.Time)
	require.Len(t, parsed.Suites, 1)
	require.NotEmpty(t, parsed.Suites[0].Time)
	require.NotEmpty(t, parsed.Suites[0].Cases[0].Time)
	require.NotContains(t, raw, "timestamp=")
	for _, seconds := range []float64{-1, math.NaN(), math.Inf(1)} {
		report.DurationSeconds = seconds
		var out bytes.Buffer
		require.Error(t, report.WriteJUnit(&out))
		require.Empty(t, out.String())
	}
}
