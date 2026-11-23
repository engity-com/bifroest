package test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/stretchr/testify/require"
)

func namedSuite(name, body string) string {
	return strings.Replace(suiteSource(body), `name="offline"`, `name="`+name+`"`, 1)
}
func inlineSuite(name, body string) string {
	return strings.Replace(namedSuite(name, body), `name="`+name+`",`, `name="`+name+`",configuration=[[`+testConfiguration+`]],`, 1)
}
func writeInput(t *testing.T, path, content string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func TestRecursiveInputsReadOnlyMatchingFilesInStableOrder(t *testing.T) {
	dir := t.TempDir()
	b := writeInput(t, filepath.Join(dir, "nested", "b_bftest.lua"), inlineSuite("beta", `t:IsEqual("primary",actual.flow)`))
	a := writeInput(t, filepath.Join(dir, "a_bftest.lua"), inlineSuite("alpha", `t:IsEqual("primary",actual.flow)`))
	writeInput(t, filepath.Join(dir, "ignored.lua"), `error("must not execute")`)
	writeInput(t, filepath.Join(dir, "notes_bftest.lua"), `local unrelated = 1`)
	report := RunPaths(t.Context(), []string{dir, b, a}, Options{})
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Len(t, report.Results, 2)
	require.Equal(t, "alpha/example", report.Results[0].qualifiedName())
	require.Equal(t, "beta/example", report.Results[1].qualifiedName())
	require.Len(t, report.Warnings, 1)
	var warnings bytes.Buffer
	require.NoError(t, report.WriteWarnings(&warnings))
	require.Contains(t, warnings.String(), "WARN")
	require.Contains(t, warnings.String(), "notes_bftest.lua")
	require.Equal(t, 2, RunPaths(t.Context(), []string{filepath.Join(dir, "ignored.lua")}, Options{}).ExitCode())
}

func TestNoSuiteWarnsButSyntaxAndRuntimeFailuresAreErrors(t *testing.T) {
	dir := t.TempDir()
	good := writeInput(t, filepath.Join(dir, "good_bftest.lua"), inlineSuite("good", `t:IsEqual(true,true)`))
	orphan := writeInput(t, filepath.Join(dir, "orphan_bftest.lua"), `local unrelated = 1`)
	orphanReport := RunPaths(t.Context(), []string{orphan}, Options{})
	require.Equal(t, 2, orphanReport.ExitCode())
	require.Empty(t, orphanReport.Results)
	require.Len(t, orphanReport.Warnings, 1)
	for _, source := range []string{`not valid Lua {{{`, `error("private-secret")`} {
		bad := writeInput(t, filepath.Join(dir, "bad_bftest.lua"), source)
		report := RunPaths(t.Context(), []string{good, bad}, Options{Includes: []string{"^good/"}})
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
		require.Empty(t, report.Warnings)
		require.Len(t, report.Results, 2)
	}
	require.Equal(t, 2, RunPaths(t.Context(), nil, Options{}).ExitCode())
	require.Equal(t, 2, RunPaths(t.Context(), []string{t.TempDir()}, Options{}).ExitCode())
}

func TestRepeatedNameFiltersUseUnionAndExclusionWins(t *testing.T) {
	dir := t.TempDir()
	writeInput(t, filepath.Join(dir, "a_bftest.lua"), inlineSuite("alpha", `t:IsEqual(true,true)`))
	writeInput(t, filepath.Join(dir, "b_bftest.lua"), inlineSuite("beta", `t:IsEqual(true,true)`))
	for _, test := range []struct {
		name    string
		options Options
		names   []string
		code    int
	}{
		{"default all", Options{}, []string{"alpha/example", "beta/example"}, 0},
		{"include union", Options{Includes: []string{"^alpha/", "^beta/"}}, []string{"alpha/example", "beta/example"}, 0},
		{"exclude priority", Options{Includes: []string{"^alpha/", "^beta/"}, Excludes: []string{"^alpha/"}}, []string{"beta/example"}, 0},
		{"exclude union", Options{Excludes: []string{"^alpha/", "^beta/"}}, nil, 2},
		{"include no matches", Options{Includes: []string{"^missing/"}}, nil, 2},
		{"explicit empty regex matches all", Options{Includes: []string{""}}, []string{"alpha/example", "beta/example"}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := RunPaths(t.Context(), []string{dir}, test.options)
			require.Equal(t, test.code, report.ExitCode(), "%+v", report)
			var names []string
			for _, result := range report.Results {
				names = append(names, result.qualifiedName())
			}
			require.Equal(t, test.names, names)
		})
	}
	for _, options := range []Options{{Includes: []string{"["}}, {Excludes: []string{"["}}} {
		report := RunPaths(t.Context(), []string{dir}, options)
		require.Equal(t, 2, report.ExitCode())
		require.Equal(t, "invalid test name filters", report.Results[0].Message)
	}
}

func TestConfigurationPresenceAndFallbackPrecedence(t *testing.T) {
	dir := t.TempDir()
	inline := writeInput(t, filepath.Join(dir, "inline_bftest.lua"), inlineSuite("inline", `t:IsEqual("primary",actual.flow)`))
	absent := writeInput(t, filepath.Join(dir, "absent_bftest.lua"), namedSuite("absent", `t:IsEqual("primary",actual.flow)`))
	second := writeInput(t, filepath.Join(dir, "second_bftest.lua"), namedSuite("second", `t:IsEqual("primary",actual.flow)`))
	fallback := writeInput(t, filepath.Join(dir, "fallback.yaml"), testConfiguration)
	calls := 0
	options := Options{Configuration: filepath.Join(dir, "missing.yaml"), DefaultConfiguration: func(context.Context) ([]byte, error) { calls++; return []byte(testConfiguration), nil }}
	require.Zero(t, RunPaths(t.Context(), []string{inline}, options).ExitCode())
	require.Zero(t, calls)
	options.Configuration = fallback
	require.Zero(t, RunPaths(t.Context(), []string{absent}, options).ExitCode())
	require.Zero(t, calls)
	options.Configuration = ""
	require.Zero(t, RunPaths(t.Context(), []string{absent, second}, options).ExitCode())
	require.Equal(t, 1, calls, "system fallback must be captured once for the entire run")
	for _, value := range []string{`""`, `"configuration.yaml"`, `false`, `null`, `[[invalid: yaml]]`} {
		source := strings.Replace(namedSuite("invalid", `t:IsEqual(true,true)`), `name="invalid",`, `name="invalid",configuration=`+value+`,`, 1)
		path := writeInput(t, filepath.Join(dir, "invalid_bftest.lua"), source)
		calls = 0
		options.Configuration = fallback
		report := RunPaths(t.Context(), []string{path}, options)
		require.Equal(t, 2, report.ExitCode(), "%+v", report)
		require.Zero(t, calls)
	}
	options.Configuration = filepath.Join(dir, "missing.yaml")
	calls = 0
	require.Equal(t, 2, RunPaths(t.Context(), []string{absent}, options).ExitCode())
	require.Zero(t, calls, "a bad flag path must not fall back to the system file")
	options.Includes = []string{"^not-selected/"}
	report := RunPaths(t.Context(), []string{absent}, options)
	require.Equal(t, 2, report.ExitCode())
	require.Empty(t, report.Results)
	require.Zero(t, calls)
}

func TestFileContentWorksForConfigurationAndOtherStrings(t *testing.T) {
	dir := t.TempDir()
	writeInput(t, filepath.Join(dir, "configuration.yaml"), testConfiguration)
	writeInput(t, filepath.Join(dir, "fixtures", "message.txt"), "modeled file string")
	source := strings.Replace(namedSuite("files", `t:IsEqual("modeled file string",file_content("fixtures/message.txt"))`), `name="files",`, `name="files",configuration=file_content("configuration.yaml"),`, 1)
	path := writeInput(t, filepath.Join(dir, "files_bftest.lua"), source)
	require.Zero(t, RunPaths(t.Context(), []string{path}, Options{}).ExitCode())
	contents, err := newFileContents(dir)
	require.NoError(t, err)
	defer contents.Close()
	spec, err := discover(t.Context(), []byte(source), contents.read)
	require.NoError(t, err)
	_, err = contents.read("fixtures/message.txt")
	require.NoError(t, err)
	writeInput(t, filepath.Join(dir, "configuration.yaml"), "now invalid")
	writeInput(t, filepath.Join(dir, "fixtures", "message.txt"), "changed")
	report := runDiscovered(t.Context(), []byte(source), spec, nameFilter{}, contents.read, func() ([]byte, error) { t.Fatal("explicit content must win"); return nil, nil })
	require.Zero(t, report.ExitCode(), "replay must use the original captured strings: %+v", report)
	for _, name := range []string{"../outside", filepath.ToSlash(filepath.Join(t.TempDir(), "outside")), "missing.txt"} {
		source := `pcall(function() file_content("` + name + `") end);` + inlineSuite("blocked", `t:IsEqual(true,true)`)
		path := writeInput(t, filepath.Join(dir, "blocked_bftest.lua"), source)
		report := RunPaths(t.Context(), []string{path}, Options{})
		require.Equal(t, 2, report.ExitCode())
		require.Zero(t, report.Results[0].Assertions, "caught file errors must fail before evaluation")
	}
}

func TestDuplicateQualifiedNamesAreNotSilentlyRunTwice(t *testing.T) {
	dir := t.TempDir()
	writeInput(t, filepath.Join(dir, "a_bftest.lua"), inlineSuite("duplicate", `t:IsEqual(true,true)`))
	writeInput(t, filepath.Join(dir, "b_bftest.lua"), inlineSuite("duplicate", `t:IsEqual(true,true)`))
	report := RunPaths(t.Context(), []string{dir}, Options{})
	require.Equal(t, 2, report.ExitCode())
	require.Len(t, report.Results, 2)
	require.Equal(t, "duplicate qualified test name", report.Results[1].Message)
}

func TestDiscoveryReadsBeyondOneDirectoryBatch(t *testing.T) {
	dir := t.TempDir()
	for i := range 300 {
		writeInput(t, filepath.Join(dir, fmt.Sprintf("ignored-%03d.txt", i)), "not Lua")
	}
	writeInput(t, filepath.Join(dir, "last_bftest.lua"), inlineSuite("last", `t:IsEqual(true,true)`))
	report := RunPaths(t.Context(), []string{dir}, Options{})
	require.Zero(t, report.ExitCode(), "%+v", report)
	require.Len(t, report.Results, 1)
	require.Equal(t, "last/example", report.Results[0].qualifiedName())
}

func TestFallbackErrorsPreserveCategoryAndAreCapturedOnce(t *testing.T) {
	dir := t.TempDir()
	writeInput(t, filepath.Join(dir, "a_bftest.lua"), namedSuite("alpha", `t:IsEqual(true,true)`))
	writeInput(t, filepath.Join(dir, "b_bftest.lua"), namedSuite("beta", `t:IsEqual(true,true)`))
	calls := 0
	report := RunPaths(t.Context(), []string{dir}, Options{DefaultConfiguration: func(context.Context) ([]byte, error) {
		calls++
		return nil, errors.Permission.Newf("private backend detail")
	}})
	require.Equal(t, 2, report.ExitCode())
	require.Equal(t, 1, calls)
	require.Len(t, report.Results, 2)
	for _, result := range report.Results {
		require.Equal(t, errors.Permission.String(), result.Category)
		require.NotContains(t, result.Message, "private backend detail")
	}
}

func TestInMemoryConfigurationIsContentAndCannotReadHostFiles(t *testing.T) {
	source := inlineSuite("memory", `t:IsEqual("primary",actual.flow)`)
	require.Zero(t, RunSources(t.Context(), []byte(source), []byte("invalid fallback")).ExitCode())
	source = strings.Replace(source, testConfiguration, "", 1)
	require.Equal(t, 2, RunSources(t.Context(), []byte(source), []byte(testConfiguration)).ExitCode())
	source = `pcall(function() file_content("configuration.yaml") end);` + inlineSuite("memory", `t:IsEqual(true,true)`)
	require.Equal(t, 2, RunSources(t.Context(), []byte(source), []byte(testConfiguration)).ExitCode())
}

func TestVerificationFileErrorsRemainSticky(t *testing.T) {
	dir := t.TempDir()
	for _, call := range []string{`file_content("missing.txt")`, `file_content(false)`, `file_content("a","b")`, `file_content()`} {
		source := inlineSuite("files", `pcall(function() `+call+` end);t:IsEqual(true,true)`)
		path := writeInput(t, filepath.Join(dir, "files_bftest.lua"), source)
		report := RunPaths(t.Context(), []string{path}, Options{})
		require.Equal(t, 2, report.ExitCode(), "%s: %+v", call, report)
		require.Equal(t, 1, report.Results[0].Assertions)
	}
}

func TestFileContentSnapshotSurvivesRemovalAndEnforcesBounds(t *testing.T) {
	dir := t.TempDir()
	path := writeInput(t, filepath.Join(dir, "message.txt"), "original")
	contents, err := newFileContents(dir)
	require.NoError(t, err)
	defer contents.Close()
	value, err := contents.read("message.txt")
	require.NoError(t, err)
	require.Equal(t, "original", value)
	require.NoError(t, os.Remove(path))
	value, err = contents.read("message.txt")
	require.NoError(t, err)
	require.Equal(t, "original", value)
	writeInput(t, filepath.Join(dir, "large.txt"), strings.Repeat("x", maxSource+1))
	_, err = contents.read("large.txt")
	require.Error(t, err)
	_, err = contents.read(".")
	require.Error(t, err)
	for i := range 63 {
		name := fmt.Sprintf("file-%d.txt", i)
		writeInput(t, filepath.Join(dir, name), "bounded")
		_, err = contents.read(name)
		require.NoError(t, err)
	}
	writeInput(t, filepath.Join(dir, "extra.txt"), "not captured")
	_, err = contents.read("extra.txt")
	require.Error(t, err)
}

func TestDiscoveryRejectsMissingAndCanceledInputs(t *testing.T) {
	require.Equal(t, 2, RunPaths(nil, []string{t.TempDir()}, Options{}).ExitCode())
	require.Equal(t, 2, RunPaths(t.Context(), []string{filepath.Join(t.TempDir(), "missing")}, Options{}).ExitCode())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	report := RunPaths(ctx, []string{t.TempDir()}, Options{})
	require.Equal(t, 2, report.ExitCode())
	require.Equal(t, errors.System.String(), report.Results[0].Category)
}
