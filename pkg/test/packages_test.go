package test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPhysicalDirectoriesArePackagesEvenForSingleFilesAndEmptyInputs(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, input := range []struct{ path, suite string }{
		{"tests1/a_bftest.lua", "one"}, {"tests1/bar/b_bftest.lua", "bar"}, {"tests1/foo/c_bftest.lua", "foo"}, {"tests2/d_bftest.lua", "two"},
	} {
		writeInput(t, filepath.FromSlash(input.path), inlineSuite(input.suite, `t:IsEqual(true,true)`))
	}
	require.NoError(t, os.Mkdir("empty", 0700))
	report := RunPaths(t.Context(), []string{"tests1", "tests2", "empty"}, Options{})
	require.Zero(t, report.ExitCode())
	var packages []string
	total := 0.0
	for _, pkg := range report.Packages {
		packages = append(packages, pkg.Name)
		total += pkg.DurationSeconds
	}
	require.Equal(t, []string{"tests1", "tests1/bar", "tests1/foo", "tests2", "empty"}, packages)
	require.GreaterOrEqual(t, report.DurationSeconds, total)
	require.Len(t, report.Suites, 4)
	for _, suite := range report.Suites {
		require.Positive(t, suite.DurationSeconds)
		require.Equal(t, 1, suite.DeclaredTests)
	}
	for _, result := range report.Results {
		require.Positive(t, result.DurationSeconds)
		require.Contains(t, packages, result.Package)
	}
	var out bytes.Buffer
	require.NoError(t, report.WriteText(&out))
	require.Contains(t, out.String(), "SKIP    empty: no tests found\n")
	require.NotContains(t, out.String(), "=== RUN")
	for _, pkg := range packages[:4] {
		require.Contains(t, out.String(), "PASS    "+pkg+" (")
	}
	single := RunFile(t.Context(), filepath.FromSlash("tests1/foo/c_bftest.lua"), "")
	require.Len(t, single.Packages, 1)
	require.Equal(t, "tests1/foo", single.Packages[0].Name)
	require.Zero(t, single.ExitCode())
	var raw bytes.Buffer
	require.NoError(t, single.WriteJSON(&raw))
	var decoded Report
	require.NoError(t, json.Unmarshal(raw.Bytes(), &decoded))
	require.Equal(t, single.DurationSeconds, decoded.DurationSeconds)
	require.Equal(t, single.Results[0].DurationSeconds, decoded.Results[0].DurationSeconds)
}

func TestAllExcludedAndFilteredPackagesAreNotPassingTests(t *testing.T) {
	t.Chdir(t.TempDir())
	source := inlineSuite("excluded", `t:IsEqual(true,true)`)
	source = strings.Replace(source, `name="excluded",`, `name="excluded",platform={os={}},`, 1)
	writeInput(t, "excluded/case_bftest.lua", source)
	writeInput(t, "selected/case_bftest.lua", inlineSuite("selected", `t:IsEqual(true,true)`))
	for _, verbose := range []bool{false, true} {
		report := RunPaths(t.Context(), []string{"excluded"}, Options{})
		require.Equal(t, 2, report.ExitCode())
		var out bytes.Buffer
		require.NoError(t, report.WriteTextWithOptions(&out, TextOptions{Verbose: verbose}))
		require.Contains(t, out.String(), "SKIP")
		require.Contains(t, out.String(), "RESULT: 0 PASSED, 0 FAILED, 1 SKIPPED, 1 ERRORS")
		require.NotContains(t, out.String(), "--- PASS")
		if verbose {
			require.Contains(t, out.String(), "--- SKIP: excluded: os does not match platform")
		}
	}
	filtered := RunPaths(t.Context(), []string{"selected"}, Options{Includes: []string{"^none/"}})
	var out bytes.Buffer
	require.NoError(t, filtered.WriteText(&out))
	require.Contains(t, out.String(), "SKIP    selected: no tests selected")
	require.Equal(t, 2, filtered.ExitCode())
}

func TestDiscoveryFailuresShareThePhysicalPackageWithValidFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	writeInput(t, "tests/valid_bftest.lua", inlineSuite("valid", `t:IsEqual(true,true)`))
	report := RunPaths(t.Context(), []string{"tests", "tests/missing_bftest.lua"}, Options{})
	require.Equal(t, 2, report.ExitCode())
	require.Equal(t, Summary{Passed: 1, Errors: 1}, report.Summary())
	require.Len(t, report.Packages, 1)
	require.Equal(t, "tests", report.Packages[0].Name)
	require.Positive(t, report.Packages[0].DurationSeconds)
	for _, result := range report.Results {
		require.Equal(t, "tests", result.Package)
	}
	var text bytes.Buffer
	require.NoError(t, report.WriteText(&text))
	require.Equal(t, 1, strings.Count(text.String(), "FAIL    tests ("))
	require.Contains(t, text.String(), "passed: 1, failed: 0, skipped: 0, errors: 1")
}
