package main

import (
	"encoding/json"
	gos "os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCIBuildToolsetsAreExplicitWithoutChangingHistoricalReleases(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/workflows/build.yml")
	require.NoError(t, err)
	var workflow struct {
		Env map[string]string `yaml:"env"`
		On  struct {
			WorkflowCall struct {
				Inputs map[string]struct {
					Type    string `yaml:"type"`
					Default any    `yaml:"default"`
				} `yaml:"inputs"`
			} `yaml:"workflow_call"`
		} `yaml:"on"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	require.Equal(t, "${{ inputs.minimal_tools && 'false' || 'true' }}", workflow.Env["MISE_AUTO_INSTALL"])
	input, ok := workflow.On.WorkflowCall.Inputs["minimal_tools"]
	require.True(t, ok)
	require.Equal(t, "boolean", input.Type)
	require.Equal(t, false, input.Default, "historical release sources retain their own full toolchain")

	expected := map[string]string{
		"browser":           "go go-licenses node bun",
		"test-static":       "go gotestsum node helm",
		"test-web":          "go node bun biome",
		"test-browser":      "go gotestsum node bun",
		"test-host":         "go gotestsum node helm",
		"test-container":    "go gotestsum node helm",
		"test-race":         "go gotestsum node helm",
		"lint-go-host":      "go golangci-lint",
		"lint-go-container": "go golangci-lint",
		"binary-host":       "go go-licenses",
		"binary-container":  "go go-licenses",
	}
	for name, job := range readGoJobsWorkflow(t) {
		count := 0
		for _, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "jdx/mise-action@") {
				continue
			}
			count++
			switch name {
			case "test-policy":
				require.Equal(t, "go", step.With["install_args"])
			case "test-policy-oci":
				require.Equal(t, "go docker-cli", step.With["install_args"])
			case "lint-lua":
				require.Equal(t, "stylua", step.With["install_args"])
			case "assemble", "package":
				require.Equal(t, "${{ inputs.minimal_tools && (inputs.lint_reuse && 'go syft python uv pipx:reuse' || 'go syft') || '' }}", step.With["install_args"])
			default:
				tools, ok := expected[name]
				require.True(t, ok, "new MISE callers must declare the tools their checks need: %s", name)
				require.Equal(t, "${{ inputs.minimal_tools && '"+tools+"' || '' }}", step.With["install_args"])
			}
		}
		require.Equal(t, 1, count, name)
		require.Empty(t, job.Env["MISE_AUTO_INSTALL"], "jobs must not re-enable automatic full-toolchain installation")
	}
	for _, filename := range []string{"ci.yml", "release.yml"} {
		raw, err := gos.ReadFile("../../.github/workflows/" + filename)
		require.NoError(t, err)
		var caller struct {
			Jobs map[string]struct {
				With map[string]any `yaml:"with"`
			} `yaml:"jobs"`
		}
		require.NoError(t, yaml.Unmarshal(raw, &caller))
		if filename == "ci.yml" {
			require.Equal(t, true, caller.Jobs["build"].With["minimal_tools"])
		} else {
			require.NotContains(t, caller.Jobs["build"].With, "minimal_tools")
		}
	}
}

func TestPRWorkflowToolsetsDoNotAutomaticallyInstallUnrelatedTools(t *testing.T) {
	expected := map[string]map[string]string{
		"ci.yml": {
			"evaluate":      "go node@26.9.0",
			"biome":         "biome",
			"reuse":         "python uv pipx:reuse",
			"documentation": "python uv",
		},
		"e2e.yml": {
			"runtime":       "${{ matrix.suite == 'docker' && 'go go-licenses docker-cli node bun' || 'go docker-cli' }}",
			"authorization": "go",
			"pam":           "go go-licenses docker-cli node bun",
			"darwin":        "go",
			"kind":          "go go-licenses docker-cli kind kubectl node bun",
		},
		"nanoserver.yml": {
			"windows-local": "go go-licenses docker-cli node bun",
		},
	}
	for filename, jobs := range expected {
		raw, err := gos.ReadFile("../../.github/workflows/" + filename)
		require.NoError(t, err)
		var workflow struct {
			Env map[string]string `yaml:"env"`
		}
		require.NoError(t, yaml.Unmarshal(raw, &workflow))
		require.Equal(t, "false", workflow.Env["MISE_AUTO_INSTALL"])
		seen := map[string]string{}
		for name, job := range readGoJobsWorkflowFile(t, filename) {
			for _, step := range job.Steps {
				if strings.HasPrefix(step.Uses, "jdx/mise-action@") {
					require.NotContains(t, seen, name)
					seen[name] = step.With["install_args"]
				}
				for _, line := range strings.Split(step.Run, "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "mise -C web install") {
						require.Equal(t, "mise -C web install node bun", strings.TrimSpace(line))
					}
				}
			}
			require.Empty(t, job.Env["MISE_AUTO_INSTALL"])
		}
		require.Equal(t, jobs, seen)
	}
}

func TestBrowserJobsRetainTransitiveLicenseAndLintTools(t *testing.T) {
	// Vite's WASM build invokes cmd/build browser-licenses, including when
	// build:web is a transitive dependency of the native PAM test task.
	for file, names := range map[string][]string{
		"build.yml":      {"browser"},
		"e2e.yml":        {"runtime", "pam", "kind"},
		"nanoserver.yml": {"windows-local"},
	} {
		jobs := readGoJobsWorkflowFile(t, file)
		for _, name := range names {
			for _, step := range jobs[name].Steps {
				if strings.HasPrefix(step.Uses, "jdx/mise-action@") {
					require.Contains(t, step.With["install_args"], "go-licenses", file+"/"+name+" builds browser or native binary license inventories")
				}
			}
		}
	}
	raw, err := gos.ReadFile("../../web/package.json")
	require.NoError(t, err)
	var web struct {
		Scripts map[string]string `json:"scripts"`
	}
	require.NoError(t, json.Unmarshal(raw, &web))
	require.Contains(t, web.Scripts["check"], "biome check")
	for _, step := range readGoJobsWorkflow(t)["test-web"].Steps {
		if strings.HasPrefix(step.Uses, "jdx/mise-action@") {
			require.Contains(t, step.With["install_args"], "biome", "lint:web runs the package.json check script")
		}
	}
}
