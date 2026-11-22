package cli

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	clibase "github.com/echocat/cli4g"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sys"
	bftest "github.com/engity-com/bifroest/pkg/test"
	"github.com/stretchr/testify/require"
)

func TestOfflinePolicyCommandAndProfiles(t *testing.T) {
	app := newTestApplications(t).Executable
	platform := "unix"
	if runtime.GOOS == "windows" {
		platform = "windows"
	}
	root := filepath.Join("..", "test", "examples", "ssh")
	for _, test := range []struct {
		suite string
		code  int
	}{{"green-" + platform + "_bftest.lua", 0}, {"red-" + platform + "_bftest.lua", 1}, {"local-" + platform + "_bftest.lua", 0}, {"missing_bftest.lua", 2}} {
		t.Run(test.suite, func(t *testing.T) {
			var out bytes.Buffer
			ctx := clibase.ContextWithStdio(t.Context(), nil, &out, nil)
			err := app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}, "test", filepath.Join(root, test.suite))
			if test.code == 0 {
				require.NoError(t, err)
			} else {
				var commandErr *bftest.CommandError
				require.ErrorAs(t, err, &commandErr)
				require.Equal(t, test.code, commandErr.Code)
				require.True(t, commandErr.Reported)
			}
			require.Contains(t, out.String(), "RESULT:")
		})
	}
	for _, profile := range []string{common.ProfileRemote, common.ProfileManagement} {
		var out bytes.Buffer
		ctx := clibase.ContextWithStdio(t.Context(), nil, &out, nil)
		require.Error(t, app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{profile}}, "test", filepath.Join(root, "green-"+platform+"_bftest.lua")))
		require.Empty(t, out.String())
	}
}

func TestOfflinePolicyReportsReplaceExistingFilesAndCreateParents(t *testing.T) {
	app := newTestApplications(t).Executable
	platform := "unix"
	if runtime.GOOS == "windows" {
		platform = "windows"
	}
	path := filepath.Join(t.TempDir(), "created", "parents", "report.json")
	args := []string{"test", filepath.Join("..", "test", "examples", "ssh", "green-"+platform+"_bftest.lua"), "--json", path}
	ctx := clibase.ContextWithStdio(t.Context(), nil, &bytes.Buffer{}, nil)
	opts := &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}
	require.NoError(t, app.ParseAndExecute(ctx, opts, args...))
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(before), `"status":"passed"`)
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("old report", 10000)), 0600))
	err = app.ParseAndExecute(ctx, opts, args...)
	require.NoError(t, err)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, json.Valid(after))
	require.NotContains(t, string(after), "old report")
}

func TestOfflinePolicyPositionalDirectoriesAndRepeatedFilters(t *testing.T) {
	app := newTestApplications(t).Executable
	platform := "unix"
	if runtime.GOOS == "windows" {
		platform = "windows"
	}
	root := filepath.Join("..", "test", "examples", "ssh")
	opts := &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}
	for _, test := range []struct {
		name  string
		flags []string
		code  int
	}{
		{"only green", []string{"--includes", "^ssh-target-" + platform + "/"}, 0},
		{"include union", []string{"--includes", "^ssh-target-" + platform + "/", "--includes", "^deliberately-red-" + platform + "/"}, 1},
		{"exclude wins", []string{"--includes", "^ssh-target-" + platform + "/", "--includes", "^deliberately-red-" + platform + "/", "--excludes", "^deliberately-red-", "--excludes", "/not-present$"}, 0},
		{"no matches", []string{"--includes", "^not-present/"}, 2},
		{"bad include", []string{"--includes", "["}, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			ctx := clibase.ContextWithStdio(t.Context(), nil, &out, &diagnostic)
			args := append([]string{"test", root, filepath.Join(root, "green-"+platform+"_bftest.lua")}, test.flags...)
			err := app.ParseAndExecute(ctx, opts, args...)
			if test.code == 0 {
				require.NoError(t, err)
			} else {
				var commandErr *bftest.CommandError
				require.ErrorAs(t, err, &commandErr)
				require.Equal(t, test.code, commandErr.Code)
			}
			if test.code == 0 {
				require.Contains(t, out.String(), "RESULT: 1 PASSED, 0 FAILED,")
			}
		})
	}
	var out bytes.Buffer
	ctx := clibase.ContextWithStdio(t.Context(), nil, &out, nil)
	require.Error(t, app.ParseAndExecute(ctx, opts, "test", "--suite", filepath.Join(root, "green-"+platform+"_bftest.lua")))
}

func TestOfflinePolicyNoSuiteWarningsGoToStderr(t *testing.T) {
	app := newTestApplications(t).Executable
	dir := t.TempDir()
	path := filepath.Join(dir, "helpers_bftest.lua")
	require.NoError(t, os.WriteFile(path, []byte(`local not_a_suite = true`), 0600))
	var out, diagnostic bytes.Buffer
	ctx := clibase.ContextWithStdio(t.Context(), nil, &out, &diagnostic)
	err := app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}, "test", path)
	var commandErr *bftest.CommandError
	require.ErrorAs(t, err, &commandErr)
	require.Equal(t, 2, commandErr.Code)
	require.Contains(t, diagnostic.String(), "WARN")
	require.Contains(t, diagnostic.String(), "helpers_bftest.lua")
	require.NotContains(t, out.String(), "WARN")
}

type policyTestVersionBase interface{ sys.Version }

type policyTestBinaryVersion struct {
	policyTestVersionBase
	value string
}

func (this policyTestBinaryVersion) Version() string { return this.value }
func (this policyTestBinaryVersion) Os() sys.Os {
	var result sys.Os
	_ = result.Set(runtime.GOOS)
	return result
}
func (this policyTestBinaryVersion) Arch() sys.Arch { return sys.ArchAmd64 }

func TestOfflinePolicyUsesBinaryMetadataWithoutCLIOverrides(t *testing.T) {
	platform := "unix"
	if runtime.GOOS == "windows" {
		platform = "windows"
	}
	source, err := os.ReadFile(filepath.Join("..", "test", "examples", "ssh", "green-"+platform+"_bftest.lua"))
	require.NoError(t, err)
	configuration, err := os.ReadFile(filepath.Join("..", "test", "examples", "ssh", "configuration.yaml"))
	require.NoError(t, err)
	// The architecture comes from the binary's sys.Version, not host detection.
	// Replace the declaration by line so the Unix and Windows examples share this test.
	lines := strings.Split(string(source), "\n")
	for i, line := range lines {
		if strings.Contains(line, "platform =") {
			lines[i] = `  platform = { arch = { "amd64" }, version = { "1.2", "development" } },`
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "binary_bftest.lua")
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "configuration.yaml"), configuration, 0600))
	for _, test := range []struct {
		version string
		code    int
	}{{"v1.2.7", 0}, {"development", 0}, {"Development", 2}, {"1.3.0", 2}} {
		t.Run(test.version, func(t *testing.T) {
			app, err := NewApplication[clibase.NoOptions](policyTestBinaryVersion{value: test.version}, "", nil).Create()
			require.NoError(t, err)
			defer app.Close()
			var output bytes.Buffer
			ctx := clibase.ContextWithStdio(t.Context(), nil, &output, nil)
			opts := &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}
			err = app.ParseAndExecute(ctx, opts, "test", path)
			if test.code == 0 {
				require.NoError(t, err)
			} else {
				var commandErr *bftest.CommandError
				require.ErrorAs(t, err, &commandErr)
				require.Equal(t, test.code, commandErr.Code)
				require.Contains(t, output.String(), "SKIP")
			}
			for _, flag := range []string{"--platform.version", "--platform.os", "--platform.arch", "--version", "--os", "--arch"} {
				require.Error(t, app.ParseAndExecute(ctx, opts, "test", path, flag, "development"))
			}
		})
	}
}

func TestOfflinePolicyDirectorySelectsItsOwnPlatform(t *testing.T) {
	app := newTestApplications(t).Executable
	var output bytes.Buffer
	ctx := clibase.ContextWithStdio(t.Context(), nil, &output, nil)
	err := app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}, "test", filepath.Join("..", "test", "examples", "ssh"))
	var commandErr *bftest.CommandError
	require.ErrorAs(t, err, &commandErr)
	require.Equal(t, 1, commandErr.Code, "only the deliberately red platform example should fail")
	require.NotContains(t, output.String(), "--- PASS:")
	require.Contains(t, output.String(), "RESULT: 2 PASSED, 1 FAILED, 3 SKIPPED")
	require.NotContains(t, output.String(), "ERROR")
}

func TestOfflinePolicyOidcExamplesUseAssumedInteractiveResults(t *testing.T) {
	var output bytes.Buffer
	ctx := clibase.ContextWithStdio(t.Context(), nil, &output, nil)
	err := newTestApplications(t).Executable.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}, "test", filepath.Join("..", "test", "examples", "oidc"), "--verbose")
	require.NoError(t, err)
	require.Contains(t, output.String(), "RESULT: 2 PASSED, 0 FAILED, 0 SKIPPED")
	require.Contains(t, output.String(), "    === RUN   assumed-oidc")
	require.Contains(t, output.String(), "--- PASS: device-mapped-identity")
	require.Contains(t, output.String(), "--- PASS: code-mapped-identity")
}

func TestOfflinePolicyHttpExamplesKeepCanonicalScopeAndPublishedBinding(t *testing.T) {
	var output bytes.Buffer
	ctx := clibase.ContextWithStdio(t.Context(), nil, &output, nil)
	err := newTestApplications(t).Executable.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}, "test", filepath.Join("..", "test", "examples", "http"), "-v")
	require.NoError(t, err)
	require.Contains(t, output.String(), "RESULT: 7 PASSED, 0 FAILED, 0 SKIPPED")
	require.Contains(t, output.String(), "    === RUN   http-selection")
	require.Regexp(t, `--- PASS: nameless-code \(\d+\.\d{3}s, 10 assertions\)`, output.String())
	require.Contains(t, output.String(), "--- PASS: published-wrong-method-is-pinned")
}

func TestOfflinePolicyJUnitUsesTheSameOutcomesAndCanAccompanyJSON(t *testing.T) {
	platform := "unix"
	if runtime.GOOS == "windows" {
		platform = "windows"
	}
	root := filepath.Join("..", "test", "examples", "ssh")
	for _, test := range []struct {
		name, path                                     string
		flags                                          []string
		code, passed, failed, skipped, executionErrors int
	}{
		{name: "passing", path: filepath.Join(root, "green-"+platform+"_bftest.lua"), passed: 1},
		{name: "assertion failure", path: filepath.Join(root, "red-"+platform+"_bftest.lua"), code: 1, failed: 1},
		{name: "load error", path: filepath.Join(root, "missing_bftest.lua"), code: 2, executionErrors: 1},
		{name: "empty selection", path: root, flags: []string{"--includes", "^none/"}, code: 2, skipped: 3, executionErrors: 1},
		{name: "mixed", path: root, code: 1, passed: 2, failed: 1, skipped: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			ctx := clibase.ContextWithStdio(t.Context(), nil, &output, &diagnostics)
			dir := t.TempDir()
			junit := filepath.Join(dir, "report.xml")
			raw := filepath.Join(dir, "report.json")
			args := append([]string{"test", test.path, "--junit", junit, "--json", raw}, test.flags...)
			err := newTestApplications(t).Executable.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...)
			if test.code == 0 {
				require.NoError(t, err)
			} else {
				var command *bftest.CommandError
				require.ErrorAs(t, err, &command)
				require.Equal(t, test.code, command.Code)
				require.True(t, command.Reported)
			}
			data, err := os.ReadFile(junit)
			require.NoError(t, err)
			var parsed struct {
				XMLName  xml.Name
				Tests    int `xml:"tests,attr"`
				Failures int `xml:"failures,attr"`
				Errors   int `xml:"errors,attr"`
				Skipped  int `xml:"skipped,attr"`
			}
			require.NoError(t, xml.Unmarshal(data, &parsed))
			require.Equal(t, "testsuites", parsed.XMLName.Local)
			require.Equal(t, test.passed+test.failed+test.skipped+test.executionErrors, parsed.Tests)
			require.Equal(t, test.failed, parsed.Failures)
			require.Equal(t, test.executionErrors, parsed.Errors)
			require.Equal(t, test.skipped, parsed.Skipped)
			data, err = os.ReadFile(raw)
			require.NoError(t, err)
			var document struct {
				Summary bftest.Summary `json:"summary"`
			}
			require.NoError(t, json.Unmarshal(data, &document))
			require.Equal(t, bftest.Summary{Passed: test.passed, Failed: test.failed, Skipped: test.skipped, Errors: test.executionErrors}, document.Summary)
			require.Contains(t, output.String(), "RESULT:")
			require.Empty(t, diagnostics.String())
			if test.failed > 0 {
				data, err = os.ReadFile(junit)
				require.NoError(t, err)
				require.Contains(t, string(data), "red-"+platform+"_bftest.lua")
				line := `line="19"`
				if runtime.GOOS == "windows" {
					line = `line="18"`
				}
				require.Contains(t, string(data), line)
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(junit)
				require.NoError(t, err)
				require.Equal(t, os.FileMode(0600), info.Mode().Perm())
			}
		})
	}
}

func TestOfflinePolicyJUnitProtectsInputsAndDoesNotHideOutputErrors(t *testing.T) {
	platform := "unix"
	if runtime.GOOS == "windows" {
		platform = "windows"
	}
	source := filepath.Join("..", "test", "examples", "ssh", "green-"+platform+"_bftest.lua")
	for _, kind := range []string{"input", "configuration-input", "directory", "parent-is-file", "same-formats-path"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "report.xml")
			var before []byte
			args := []string{"test", source}
			switch kind {
			case "input":
				path = source
				var err error
				before, err = os.ReadFile(path)
				require.NoError(t, err)
			case "configuration-input":
				path = filepath.Join(filepath.Dir(source), "configuration.yaml")
				var err error
				before, err = os.ReadFile(path)
				require.NoError(t, err)
			case "directory":
				path = dir
			case "parent-is-file":
				parent := filepath.Join(dir, "not-a-directory")
				require.NoError(t, os.WriteFile(parent, []byte("parent file"), 0600))
				path = filepath.Join(parent, "report.xml")
			case "same-formats-path":
				args = append(args, "--json", path)
			}
			args = append(args, "--junit", path)
			ctx := clibase.ContextWithStdio(t.Context(), nil, &bytes.Buffer{}, nil)
			err := newTestApplications(t).Executable.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...)
			var command *bftest.CommandError
			require.ErrorAs(t, err, &command)
			require.Equal(t, 2, command.Code)
			require.False(t, command.Reported)
			require.ErrorContains(t, err, strconv.Quote(path))
			if before != nil {
				after, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, before, after)
			}
			if kind == "same-formats-path" {
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				require.True(t, json.Valid(data), "a later output failure must not overwrite the already written JSON report")
			}
		})
	}
}
