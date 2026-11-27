package main

import (
	"context"
	"io/fs"
	gos "os"
	goexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestLuaLintToolsAreTaskOwnedAndKeepBothChecks(t *testing.T) {
	raw, err := gos.ReadFile("../../mise.toml")
	require.NoError(t, err)
	var configuration struct {
		Aliases map[string]string `toml:"tool_alias"`
		Tasks   map[string]struct {
			Tools map[string]any `toml:"tools"`
			Run   any            `toml:"run"`
		} `toml:"tasks"`
	}
	_, err = toml.Decode(string(raw), &configuration)
	require.NoError(t, err)
	require.Equal(t, "github:lunarmodules/luacheck", configuration.Aliases["luacheck"])
	require.Equal(t, "aqua:JohnnyMorganz/StyLua", configuration.Aliases["stylua"])
	lint := configuration.Tasks["lint:lua"]
	require.Len(t, lint.Tools, 2)
	require.Equal(t, "{{ vars.tool_version_stylua }}", lint.Tools["stylua"])
	options, ok := lint.Tools["luacheck"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "{{ vars.tool_version_luacheck }}", options["version"])
	require.Contains(t, options["asset_pattern"], "luacheck.exe")
	require.Contains(t, options["asset_pattern"], "unsupported-")
	require.Equal(t, []any{
		"luacheck --config .luacheckrc --no-default-config pkg/test",
		"stylua --config-path .stylua.toml --check pkg/test",
	}, lint.Run)
	require.Equal(t, map[string]any{"stylua": "{{ vars.tool_version_stylua }}"}, configuration.Tasks["format:lua"].Tools)
	require.Equal(t, "stylua --config-path .stylua.toml --verify pkg/test", configuration.Tasks["format:lua"].Run)
}

func TestLuaWorkflowSharesExistingLintJobsAndMiseSetup(t *testing.T) {
	jobs := readGoJobsWorkflow(t)
	require.NotContains(t, jobs, "lint-lua", "Lua must not need its own runners or MISE setup")
	for name, expectedChecks := range map[string]int{
		"lint-go-host":      1,
		"lint-go-container": 0,
	} {
		t.Run(name, func(t *testing.T) {
			job := jobs[name]
			require.Equal(t, "Lint ${{ matrix.os }}", job.Name)
			require.Equal(t, map[string]string{"contents": "read"}, job.Permissions)
			require.False(t, job.ContinueOnError)
			checks, setups := 0, 0
			for _, step := range job.Steps {
				require.False(t, step.ContinueOnError)
				for _, forbidden := range []string{"sudo", "apt-get", "luarocks", "mise install", "mise exec"} {
					require.NotContains(t, step.Run, forbidden)
				}
				if strings.HasPrefix(step.Uses, "jdx/mise-action@") {
					setups++
				}
				if step.Run == "mise run lint:lua" {
					checks++
					require.Equal(t, "runner.os == 'Windows'", step.If)
					require.Equal(t, map[string]string{"GH_TOKEN": "", "MISE_GITHUB_TOKEN": ""}, step.Env)
				}
			}
			require.Equal(t, expectedChecks, checks, "check all Lua sources once on the supported Windows runner")
			require.Equal(t, 1, setups, "reuse the Go linter's MISE setup and post-cache save")
			if expectedChecks != 0 {
				require.Less(t, goJobsStepContaining(t, job, "mise run lint:lua"), goJobsStepContaining(t, job, "mise run lint:go"))
			}
		})
	}
}

func TestLuaSourceCheckoutsKeepUnixLineEndingsOnWindows(t *testing.T) {
	raw, err := gos.ReadFile("../../.gitattributes")
	require.NoError(t, err)
	require.Regexp(t, `(?m)^\*\.lua\s+text eol=lf$`, string(raw))
}

// Opt-in because this provisions the catalog's Go prerequisite and two native
// lint tools from empty MISE data. No Lua interpreter, LuaRocks or sudo is used.
func TestMiseLuaLintInstallsNativeToolsAndPreservesFailuresWithoutSystemTools(t *testing.T) {
	if gos.Getenv("BIFROEST_TEST_MISE_LUA") != "1" {
		t.Skip("set BIFROEST_TEST_MISE_LUA=1 for native Lua tool provisioning")
	}
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("upstream native Luacheck binaries cover Linux/x64 and Windows/x64")
	}
	mise, err := goexec.LookPath("mise")
	require.NoError(t, err)
	root := t.TempDir()
	for _, name := range []string{"mise.toml", dependencyToolsPath, ".luacheckrc", ".stylua.toml"} {
		raw, err := gos.ReadFile(filepath.Join("..", "..", name))
		require.NoError(t, err)
		require.NoError(t, gos.WriteFile(filepath.Join(root, name), raw, 0o600))
	}
	luaRoot := filepath.Join("..", "..", "pkg", "test")
	original := map[string][]byte{}
	require.NoError(t, filepath.WalkDir(luaRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".lua" {
			return nil
		}
		relative, err := filepath.Rel(luaRoot, path)
		if err != nil {
			return err
		}
		target := filepath.Join(root, "pkg", "test", relative)
		raw, err := gos.ReadFile(path)
		if err != nil {
			return err
		}
		if err := gos.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		original[target] = raw
		return gos.WriteFile(target, raw, 0o600)
	}))
	require.NotEmpty(t, original)
	ambient := filepath.Join(root, "ambient")
	require.NoError(t, gos.Mkdir(ambient, 0o700))
	for _, name := range []string{"luacheck", "stylua", "lua", "luajit", "luarocks"} {
		payload := "#!/bin/sh\necho 'ambient Lua tools must not be used' >&2\nexit 97\n"
		if runtime.GOOS == "windows" {
			name += ".exe"
			payload = "not an executable: ambient Lua tools must not be used"
		}
		require.NoError(t, gos.WriteFile(filepath.Join(ambient, name), []byte(payload), 0o700))
	}
	data := filepath.Join(root, "data")
	var environment []string
	for _, entry := range gos.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if (strings.HasPrefix(upper, "MISE_") && upper != "MISE_GITHUB_TOKEN") ||
			strings.HasPrefix(upper, "__MISE_") || upper == "PATH" || upper == "GOROOT" {
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(environment,
		"PATH="+ambient+string(filepath.ListSeparator)+gos.Getenv("PATH"),
		"MISE_DATA_DIR="+data,
		"MISE_CONFIG_DIR="+filepath.Join(root, "config"),
		"MISE_GLOBAL_CONFIG_FILE="+filepath.Join(root, "global.toml"),
		"MISE_SYSTEM_CONFIG_FILE="+filepath.Join(root, "system.toml"),
		"MISE_STATE_DIR="+filepath.Join(root, "state"),
		"MISE_CEILING_PATHS="+filepath.Dir(root),
		"MISE_TRUSTED_CONFIG_PATHS="+root,
	)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	run := func(args ...string) (string, error) {
		t.Helper()
		command := goexec.CommandContext(ctx, mise, args...)
		command.Dir = root
		command.Env = environment
		output, err := command.CombinedOutput()
		require.NotContains(t, string(output), "ambient Lua tools must not be used")
		return string(output), err
	}
	output, err := run("run", "--quiet", "lint:lua")
	require.NoError(t, err, output)
	catalogRaw, err := gos.ReadFile(filepath.Join(root, dependencyToolsPath))
	require.NoError(t, err)
	catalog, err := parseDependencyToolCatalog(catalogRaw)
	require.NoError(t, err)
	output, err = run("exec", "luacheck@"+catalog.versions["luacheck"].Value, "--", "luacheck", "--version")
	require.NoError(t, err, output)
	require.Contains(t, output, "Luacheck: "+catalog.versions["luacheck"].Value)
	entries, err := gos.ReadDir(filepath.Join(data, "installs"))
	require.NoError(t, err)
	var installed []string
	for _, entry := range entries {
		if entry.IsDir() {
			installed = append(installed, entry.Name())
		}
	}
	require.ElementsMatch(t, []string{"go", "luacheck", "stylua"}, installed)
	for _, test := range []struct{ name, source, diagnostic string }{
		{"unknown-global", "suite { name = missing_fixture_global }\n", "missing_fixture_global"},
		{"read-only-global", "suite = {}\n", "read-only global"},
		{"syntax", "suite {\n", "expected"},
		{"format", "suite{ name = \"portable\" }\n", "Diff"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, "pkg", "test", "portable_probe_bftest.lua")
			require.NoError(t, gos.WriteFile(path, []byte(test.source), 0o600))
			output, err := run("run", "--quiet", "lint:lua")
			require.Error(t, err, "lint must reject %s", test.name)
			require.Contains(t, output, test.diagnostic)
			actual, err := gos.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, test.source, string(actual), "lint must never rewrite sources")
		})
	}
	for path, expected := range original {
		actual, err := gos.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, expected, actual, "lint must not modify existing Lua sources")
	}
}
