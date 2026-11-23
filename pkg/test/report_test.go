package test

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTextReportAlignsStatusesCountsTestsAndLocatesAssertions(t *testing.T) {
	report := Report{APIVersion: APIVersion, Scope: scope,
		Packages:      []PackageRun{{Name: "fixture", DurationSeconds: .040}},
		Suites:        []SuiteRun{{Package: "fixture", Name: "suite", Source: filepath.Join("fixture", "red-unix_bftest.lua"), DurationSeconds: .039}},
		SkippedSuites: []SkippedSuite{{Package: "fixture", Suite: "excluded", Reason: "os does not match platform", Tests: 2, TestNames: []string{"first", "second"}}},
		Results: []Result{
			{Package: "fixture", Suite: "suite", Source: filepath.Join("fixture", "red-unix_bftest.lua"), Name: "passed", Status: "passed", Assertions: 1, DurationSeconds: .011},
			{Package: "fixture", Suite: "suite", Name: "failed", Source: filepath.Join("fixture", "red-unix_bftest.lua"), Status: "failed", Assertions: 2, DurationSeconds: .012,
				Failures: []Failure{{Line: 20, Expected: `"expected"`, Actual: `"actual"`, Reason: "deliberately red"}}},
		},
	}
	var text, raw bytes.Buffer
	require.NoError(t, report.WriteText(&text))
	require.Equal(t, "=== RUN   suite/failed\n"+
		"red-unix_bftest.lua:20: expected \"expected\", actual \"actual\"; reason \"deliberately red\"\n"+
		"--- FAIL: suite/failed (0.012s, 2 assertions)\n"+
		"FAIL    fixture (0.040s, assertions: 3, passed: 1, failed: 1, skipped: 2)\n"+
		"\nRESULT: 1 PASSED, 1 FAILED, 2 SKIPPED\n", text.String())
	require.Equal(t, Summary{Passed: 1, Failed: 1, Skipped: 2}, report.Summary())
	require.Equal(t, 1, report.ExitCode())
	require.NoError(t, report.WriteJSON(&raw))
	var decoded struct {
		Summary Summary `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(raw.Bytes(), &decoded))
	require.Equal(t, report.Summary(), decoded.Summary)
	text.Reset()
	require.NoError(t, report.WriteTextWithOptions(&text, TextOptions{Verbose: true}))
	require.Contains(t, text.String(), "=== RUN   fixture\n    === RUN   suite\n        === RUN   passed\n        --- PASS: passed (0.011s, 1 assertion)\n")
	require.Contains(t, text.String(), "    --- FAIL: suite (0.039s, assertions: 3, passed: 1, failed: 1, skipped: 0)\n")
	require.Contains(t, text.String(), "        --- SKIP: first: os does not match platform\n")
	require.Contains(t, text.String(), "--- FAIL: fixture (0.040s, assertions: 3, passed: 1, failed: 1, skipped: 2)\n")
	require.NotContains(t, text.String(), `"suite`)
}

func TestEmptyAndErroredReportsCannotLookSuccessful(t *testing.T) {
	for _, report := range []Report{
		{},
		{SkippedSuites: []SkippedSuite{{Suite: "excluded", Tests: 4}}},
		{Results: []Result{{Name: "load", Status: "error", Category: "config", Message: "invalid source"}}},
	} {
		var text bytes.Buffer
		require.NoError(t, report.WriteText(&text))
		require.Equal(t, 2, report.ExitCode())
		require.Contains(t, text.String(), ", 1 ERRORS")
		if len(report.Results) == 0 {
			require.Contains(t, text.String(), "ERROR  no tests selected")
		}
		var command *CommandError
		require.ErrorAs(t, report.Err(), &command)
		require.False(t, command.Reported, "an embedding error has not necessarily been printed")
	}
}

func TestAssertionLocationsHandleMemoryAndUnsafeFilenames(t *testing.T) {
	for _, test := range []struct{ source, location string }{
		{"", "<memory>:9:"},
		{filepath.Join("fixture", "line\nbreak_bftest.lua"), `line\nbreak_bftest.lua:9:`},
	} {
		report := Report{Results: []Result{{Status: "failed", Source: test.source, Failures: []Failure{{Line: 9}}}}}
		var out bytes.Buffer
		require.NoError(t, report.WriteText(&out))
		require.Contains(t, out.String(), test.location)
		require.NotContains(t, out.String(), "  line 9:")
	}
}

type rejectedReportWriter struct{}

func (rejectedReportWriter) Write([]byte) (int, error) {
	return 0, errors.New("report output unavailable")
}

func TestReportWriterErrorsRemainErrors(t *testing.T) {
	for _, report := range []Report{
		{},
		{SkippedSuites: []SkippedSuite{{Suite: "excluded", Tests: 1}}},
		{Results: []Result{{Status: "passed", Assertions: 1}}},
		{Warnings: []Warning{{Message: "no suite"}}},
	} {
		require.Error(t, report.WriteText(rejectedReportWriter{}))
		require.Error(t, report.WriteJSON(rejectedReportWriter{}))
		if len(report.Warnings) > 0 {
			require.Error(t, report.WriteWarnings(rejectedReportWriter{}))
		}
	}
}
