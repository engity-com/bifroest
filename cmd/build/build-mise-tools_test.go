package main

import (
	"encoding/json"
	gos "os"
	goexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestMiseTaskToolsUseTheSingleVersionCatalog(t *testing.T) {
	raw, err := gos.ReadFile("../../mise.tools.yaml")
	require.NoError(t, err)
	catalog, err := parseDependencyToolCatalog(raw)
	require.NoError(t, err)
	referenced := map[string]bool{}
	for _, name := range []string{"mise.toml", ".github/mise.toml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := gos.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
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
			require.Equal(t, filepath.ToSlash(filepath.Join(filepath.Dir(name), configuration.Vars.Import.File)), dependencyToolsPath)
			require.Empty(t, configuration.Tools, "global tool selections are additive; tasks must own all tool requirements")
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
	}
	require.Len(t, referenced, len(catalog.versions), "every catalog tool must be used by a task")
	for _, name := range []string{".tool-versions", "web/.tool-versions"} {
		_, err := gos.Stat(filepath.Join("..", "..", filepath.FromSlash(name)))
		require.ErrorIs(t, err, gos.ErrNotExist, "do not reintroduce a duplicate version catalog")
	}
}

func TestMiseWorkflowsHaveNoJobSpecificToolListsAndSaveTaskInstalls(t *testing.T) {
	for _, name := range []string{"build.yml", "ci.yml", "release.yml", "e2e.yml", "nanoserver.yml", "pr-update.yml", "dependencies.yml"} {
		for jobName, job := range readGoJobsWorkflowFile(t, name) {
			for _, step := range job.Steps {
				if !strings.HasPrefix(step.Uses, "jdx/mise-action@") {
					continue
				}
				require.Empty(t, step.With["install_args"], name+"/"+jobName)
				require.Empty(t, step.With["tool_versions"], name+"/"+jobName)
				require.Empty(t, step.With["mise_toml"], name+"/"+jobName)
				require.NotEqual(t, "false", step.With["install"], "this action only registers post saving when its (empty) initial install is enabled")
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
		if directory != root {
			require.Equal(t, map[string]any{"node": "26.9.0"}, parsed["group-binary-matrices"])
		}
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
