package main

import (
	gos "os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// These guards describe the workflow; they are not hosted/native runtime proof.
func TestPolicyWorkflowRunsNativeCLIOnAllThreePlatformsAndKeepsFailedReports(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/workflows/build.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]yaml.Node `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	var job struct {
		Permissions map[string]string `yaml:"permissions"`
		RunsOn      string            `yaml:"runs-on"`
		Timeout     int               `yaml:"timeout-minutes"`
		Env         map[string]string `yaml:"env"`
		Strategy    struct {
			FailFast bool `yaml:"fail-fast"`
			Matrix   struct {
				Include []struct{ Os, Runner string } `yaml:"include"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
		Steps []struct {
			Uses            string            `yaml:"uses"`
			Run             string            `yaml:"run"`
			If              string            `yaml:"if"`
			ContinueOnError bool              `yaml:"continue-on-error"`
			With            map[string]any    `yaml:"with"`
			Env             map[string]string `yaml:"env"`
		} `yaml:"steps"`
	}
	node, ok := workflow.Jobs["test-policy"]
	require.True(t, ok)
	require.NoError(t, node.Decode(&job))
	require.Equal(t, map[string]string{"contents": "read"}, job.Permissions)
	require.Equal(t, "${{ matrix.runner }}", job.RunsOn)
	require.Equal(t, 20, job.Timeout)
	require.False(t, job.Strategy.FailFast)
	platforms := map[string]string{}
	for _, entry := range job.Strategy.Matrix.Include {
		platforms[entry.Os] = entry.Runner
	}
	require.Equal(t, map[string]string{"linux": "ubuntu-latest", "darwin": "macos-15", "windows": "windows-latest"}, platforms)
	require.Equal(t, "0", job.Env["CGO_ENABLED"])
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "MISE_GITHUB_TOKEN"} {
		value, exists := job.Env[key]
		require.True(t, exists)
		require.Empty(t, value)
	}
	checkout, install, compile, upload := -1, -1, -1, -1
	for i, step := range job.Steps {
		require.False(t, step.ContinueOnError)
		require.NotContains(t, step.Run, "secrets.")
		for _, value := range step.Env {
			require.NotContains(t, value, "secrets.")
		}
		if step.Uses == "./.github/actions/cache-go" {
			require.Equal(t, "test-policy", step.With["scope"])
			require.Equal(t, "cgo0", step.With["context"])
		} else if step.Uses != "" {
			require.Regexp(t, `@[a-f0-9]{40}$`, step.Uses)
		}
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			checkout = i
			require.Equal(t, "${{ inputs.commit || inputs.ref }}", step.With["ref"])
			require.Equal(t, false, step.With["persist-credentials"])
		}
		if strings.Contains(step.Run, "mise run install:go") {
			install = i
		}
		if strings.HasPrefix(step.Uses, "jdx/mise-action@") {
			require.Equal(t, "go", step.With["install_args"])
		}
		if step.Run == "mise run test:policy" {
			compile = i
			require.Empty(t, step.If)
			for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "MISE_GITHUB_TOKEN"} {
				value, exists := step.Env[key]
				require.True(t, exists)
				require.Empty(t, value)
			}
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			upload = i
			require.Equal(t, "always()", step.If)
			require.Equal(t, "var/policy-ci/reports/", step.With["path"], "do not upload private inputs or binaries")
			require.Equal(t, "policy-reports-${{ matrix.os }}", step.With["name"])
		}
	}
	require.NotEqual(t, -1, checkout)
	require.Greater(t, install, checkout)
	require.Greater(t, compile, install)
	require.Greater(t, upload, compile)
	raw, err = gos.ReadFile("../../mise.toml")
	require.NoError(t, err)
	_, rest, found := strings.Cut(string(raw), `[tasks."test:policy"]`)
	require.True(t, found)
	body, _, _ := strings.Cut(rest, "\n[tasks.")
	require.Contains(t, body, "go run ./test/policyci --output var/policy-ci")
	require.NotContains(t, body, "continue")
}
