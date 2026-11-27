package main

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
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

func TestMiseTaskToolsUseTheSingleVersionCatalog(t *testing.T) {
	raw, err := gos.ReadFile("../../mise.tools.yaml")
	require.NoError(t, err)
	catalog, err := parseDependencyToolCatalog(raw)
	require.NoError(t, err)
	referenced := map[string]bool{}
	t.Run("mise.toml", func(t *testing.T) {
		raw, err := gos.ReadFile("../../mise.toml")
		require.NoError(t, err)
		var configuration struct {
			Vars struct {
				Import struct {
					File string `toml:"file"`
				} `toml:"_"`
			} `toml:"vars"`
			Tools map[string]any `toml:"tools"`
			Tasks map[string]struct {
				Tools map[string]any `toml:"tools"`
				Run   any            `toml:"run"`
			} `toml:"tasks"`
		}
		_, err = toml.Decode(string(raw), &configuration)
		require.NoError(t, err)
		require.Equal(t, dependencyToolsPath, configuration.Vars.Import.File)
		require.Equal(t, map[string]any{"go": "{{ vars.tool_version_go }}"}, configuration.Tools, "only the Go installer prerequisite may be selected globally")
		require.NotEmpty(t, configuration.Tasks)
		for taskName, task := range configuration.Tasks {
			for tool, options := range task.Tools {
				t.Run(taskName+"/"+tool, func(t *testing.T) {
					require.Contains(t, catalog.versions, tool)
					version, ok := options.(string)
					if !ok {
						table, ok := options.(map[string]any)
						require.True(t, ok)
						version, ok = table["version"].(string)
						require.True(t, ok)
					}
					require.Equal(t, "{{ vars."+toolVersionPrefix+tool+" }}", version)
					referenced[tool] = true
				})
			}
			if len(task.Tools) != 0 || taskName == "build:var" {
				continue
			}
			run, ok := task.Run.([]any)
			require.True(t, ok, "%s must declare tools unless it only delegates to other tasks", taskName)
			for _, entry := range run {
				invocation, ok := entry.(map[string]any)
				require.True(t, ok, "%s contains an executable command without tools", taskName)
				require.NotEmpty(t, invocation["task"])
			}
		}
	})
	require.Len(t, referenced, len(catalog.versions), "every catalog tool must be used by a task")
	for _, name := range []string{".tool-versions", "web/.tool-versions", ".github/mise.toml"} {
		_, err := gos.Stat(filepath.Join("..", "..", filepath.FromSlash(name)))
		require.ErrorIs(t, err, gos.ErrNotExist, "do not reintroduce a duplicate version catalog")
	}
}

func TestMiseWorkflowsHaveNoJobSpecificToolListsAndSaveTaskInstalls(t *testing.T) {
	for _, name := range []string{"build.yml", "ci.yml", "release.yml", "e2e.yml", "nanoserver.yml", "pr-update.yml", "dependencies.yml", "windows-conpty-client-progress.yml"} {
		for jobName, job := range readGoJobsWorkflowFile(t, name) {
			for _, step := range job.Steps {
				require.NotContains(t, step.Run, "mise exec", "invoke task-owned tools directly")
				require.NotContains(t, step.Run, "mise -C web exec")
				require.NotRegexp(t, `\bmise(?: -C \S+)? install(?:\s|$)`, step.Run, "no workflow-owned tool installation")
				require.NotContains(t, step.Run, "mise.tools.yaml", "do not probe for legacy task support")
				require.NotEqual(t, "var/ci-workflow", step.With["path"], "use helpers from the selected source")
				if !strings.HasPrefix(step.Uses, "jdx/mise-action@") {
					continue
				}
				require.Empty(t, step.With["install_args"], name+"/"+jobName)
				require.Empty(t, step.With["tool_versions"], name+"/"+jobName)
				require.Empty(t, step.With["mise_toml"], name+"/"+jobName)
				require.NotEqual(t, "false", step.With["install"], "install the global Go prerequisite and register post-cache saving")
				require.Equal(t, "true", step.With["cache_save_post"], "include tools installed by later tasks")
				require.Contains(t, step.With["cache_key"], "mise.tools.yaml", "a catalog bump must invalidate the tool cache")
				require.NotContains(t, step.With["cache_key"], "install_args")
			}
		}
	}
}

func TestMiseNativeTaskParsingDoesNotInstallAnyTool(t *testing.T) {
	mise, err := goexec.LookPath("mise")
	if err != nil {
		t.Skip("MISE is required to check native task parsing")
	}
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	data := filepath.Join(t.TempDir(), "data")
	for _, directory := range []string{root, filepath.Join(root, ".github")} {
		command := goexec.CommandContext(t.Context(), mise, "-C", directory, "tasks", "ls", "--json", "--hidden")
		command.Env = append(gos.Environ(), "MISE_TRUSTED_CONFIG_PATHS="+root, "MISE_DATA_DIR="+data)
		var stderr strings.Builder
		command.Stderr = &stderr
		raw, err := command.Output()
		require.NoError(t, err, stderr.String())
		var tasks []struct {
			Name  string         `json:"name"`
			Tools map[string]any `json:"tools"`
		}
		require.NoError(t, json.Unmarshal(raw, &tasks))
		parsed := map[string]map[string]any{}
		for _, task := range tasks {
			parsed[task.Name] = task.Tools
			tools, err := json.Marshal(task.Tools)
			require.NoError(t, err)
			require.NotContains(t, string(tools), "{{", "MISE itself must resolve all catalog references")
		}
		require.Equal(t, "1.27.4", parsed["ci:go:env"]["go"])
		require.Equal(t, "26.9.0", parsed["test:go:native"]["node"])
		require.Equal(t, map[string]any{"node": "26.9.0"}, parsed["ci:group-binary-matrices"])
	}
	_, err = gos.Stat(filepath.Join(data, "installs"))
	require.ErrorIs(t, err, gos.ErrNotExist)
}

func TestMiseWindowsAuthorizationTaskPreservesScopeAndCmdQuoting(t *testing.T) {
	raw, err := gos.ReadFile("../../mise.toml")
	require.NoError(t, err)
	var configuration struct {
		Tasks map[string]struct {
			Run any `toml:"run"`
		} `toml:"tasks"`
	}
	_, err = toml.Decode(string(raw), &configuration)
	require.NoError(t, err)
	require.Equal(t, `go test ./pkg/configuration ./pkg/authorization ./pkg/windowslocal ./pkg/environment ./pkg/service -run "^(TestWindowsLocal.*|TestLocalWindowsAuthorizationAccountReplacement|TestLocalSAMIntegration|TestSIDMatching|TestMissingIdentity|TestNames|TestFieldsWithoutConfiguration|TestInvalidCredentials|TestAccountUnavailable|TestS4ULogonBuffer)$"`, configuration.Tasks["test:go:windows-local"].Run, "single quotes would be literal under cmd.exe and silently select no tests")
}

// Opt-in because this downloads a compiler and builds the licensing tool.
// An unusable ambient Go must never be used, even when it is first on PATH.
func TestMiseGoBackedInstallerUsesCatalogCompilerFromEmptyData(t *testing.T) {
	if gos.Getenv("BIFROEST_TEST_MISE_INSTALLS") != "1" {
		t.Skip("set BIFROEST_TEST_MISE_INSTALLS=1 for native installer integration")
	}
	mise, err := goexec.LookPath("mise")
	require.NoError(t, err)
	root := t.TempDir()
	for _, name := range []string{"mise.toml", dependencyToolsPath} {
		raw, err := gos.ReadFile(filepath.Join("..", "..", name))
		require.NoError(t, err)
		if name == "mise.toml" {
			raw = append(raw, []byte(`
[tasks.installer-probe]
tools = { go = "{{ vars.tool_version_go }}", go_licenses = "{{ vars.tool_version_go_licenses }}" }
run = "go-licenses --help"
`)...)
		}
		require.NoError(t, gos.WriteFile(filepath.Join(root, name), raw, 0o600))
	}
	bin := filepath.Join(root, "ambient")
	require.NoError(t, gos.Mkdir(bin, 0o700))
	fakeGo, payload := "go", "#!/bin/sh\necho 'ambient Go must not be used' >&2\nexit 97\n"
	if runtime.GOOS == "windows" {
		fakeGo, payload = "go.exe", "not a Windows executable: ambient Go must not be used"
	}
	require.NoError(t, gos.WriteFile(filepath.Join(bin, fakeGo), []byte(payload), 0o700))
	data := filepath.Join(root, "data")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	command := goexec.CommandContext(ctx, mise, "run", "--quiet", "installer-probe")
	command.Dir = root
	for _, entry := range gos.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if (strings.HasPrefix(upper, "MISE_") && upper != "MISE_GITHUB_TOKEN") ||
			strings.HasPrefix(upper, "__MISE_") || upper == "PATH" || upper == "GOROOT" {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env,
		"PATH="+bin+string(filepath.ListSeparator)+gos.Getenv("PATH"),
		"MISE_DATA_DIR="+data,
		"MISE_CONFIG_DIR="+filepath.Join(root, "config"),
		"MISE_GLOBAL_CONFIG_FILE="+filepath.Join(root, "global.toml"),
		"MISE_SYSTEM_CONFIG_FILE="+filepath.Join(root, "system.toml"),
		"MISE_STATE_DIR="+filepath.Join(root, "state"),
		"MISE_CEILING_PATHS="+filepath.Dir(root),
		"MISE_TRUSTED_CONFIG_PATHS="+root,
	)
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
	require.NotContains(t, string(output), "ambient Go must not be used")
	entries, err := gos.ReadDir(filepath.Join(data, "installs"))
	require.NoError(t, err)
	var installed []string
	for _, entry := range entries {
		if entry.IsDir() {
			installed = append(installed, entry.Name())
		}
	}
	require.ElementsMatch(t, []string{"go", "go-licenses"}, installed, "do not install unrelated task tools")
	raw, err := gos.ReadFile(filepath.Join(root, dependencyToolsPath))
	require.NoError(t, err)
	catalog, err := parseDependencyToolCatalog(raw)
	require.NoError(t, err)
	name := "go-licenses"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	info, err := buildinfo.ReadFile(filepath.Join(data, "installs", "go-licenses", strings.TrimPrefix(catalog.versions["go_licenses"].Value, "v"), "bin", name))
	require.NoError(t, err)
	require.Equal(t, "github.com/google/go-licenses/v2", info.Main.Path)
	require.Equal(t, "v"+strings.TrimPrefix(catalog.versions["go_licenses"].Value, "v"), info.Main.Version)
	require.Equal(t, "go"+catalog.versions["go"].Value, info.GoVersion, "the installer must use the catalog compiler, not system Go")
}
