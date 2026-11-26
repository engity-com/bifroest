package main

import (
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
		"browser":           "go node bun",
		"test-static":       "go gotestsum node helm",
		"test-web":          "go node bun",
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
			"runtime":       "${{ matrix.suite == 'docker' && 'go docker-cli node bun' || 'go docker-cli' }}",
			"authorization": "go",
			"pam":           "go docker-cli node bun",
			"darwin":        "go",
			"kind":          "go docker-cli kind kubectl node bun",
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
