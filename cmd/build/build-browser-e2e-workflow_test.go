package main

import (
	gos "os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDockerBrowserE2ERunsInBothExistingRuntimeJobsWithoutSkip(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/workflows/e2e.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Runtime []string `yaml:"runtime"`
					Suite   []string `yaml:"suite"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	job := workflow.Jobs["runtime"]
	require.ElementsMatch(t, []string{"docker", "podman"}, job.Strategy.Matrix.Runtime)
	require.Contains(t, job.Strategy.Matrix.Suite, "docker")
	prepared, executed := false, false
	for _, step := range job.Steps {
		command, ok := step["run"].(string)
		if !ok {
			continue
		}
		if strings.Contains(command, "mise -C web run build:web") {
			require.Equal(t, "matrix.suite == 'docker'", step["if"])
			for _, required := range []string{"mise -C web install", "mise -C web run install:web", "mise -C web run install:web:browser"} {
				require.Contains(t, command, required)
			}
			prepared = true
		}
		if strings.Contains(command, "^TestOpenSSHDockerBrowserSharedWorkload$") {
			require.True(t, prepared, "frontend must precede fixture Go embedding")
			require.Equal(t, "matrix.suite == 'docker'", step["if"])
			env := step["env"].(map[string]any)
			require.Equal(t, "1", env["BIFROEST_TEST_BROWSER_UI"])
			require.Contains(t, command, `mise -C web which node`)
			require.Contains(t, command, `e.get('Action') == 'pass'`)
			require.Contains(t, command, `('skip', 'fail', 'build-fail')`)
			executed = true
		}
	}
	require.True(t, executed, "a native SSH-only Docker suite is not browser coverage")
}
