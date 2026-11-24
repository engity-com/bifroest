package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGoWorkflowCachesFollowPinnedToolchain(t *testing.T) {
	for _, name := range []string{"build.yml", "ci.yml", "dependencies.yml", "e2e.yml", "nanoserver.yml", "pr-update.yml", "release.yml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
			require.NoError(t, err)
			var workflow struct {
				Jobs map[string]struct {
					Steps []struct {
						Uses string            `yaml:"uses"`
						With map[string]string `yaml:"with"`
					} `yaml:"steps"`
				} `yaml:"jobs"`
			}
			require.NoError(t, yaml.Unmarshal(raw, &workflow))
			cached := 0
			for jobName, job := range workflow.Jobs {
				checkout, toolchain := false, false
				for _, step := range job.Steps {
					if strings.HasPrefix(step.Uses, "actions/checkout@") {
						checkout = true
					}
					if strings.HasPrefix(step.Uses, "jdx/mise-action@") {
						toolchain = true
					}
					require.NotEqual(t, "~/go/pkg/mod", step.With["path"], "%s must use the resolved module and build caches", jobName)
					if step.Uses == "./.github/actions/cache-go" {
						require.True(t, checkout, "%s must check out the local action first", jobName)
						require.True(t, toolchain, "%s must resolve its pinned Go before caching", jobName)
						require.NotEmpty(t, step.With["scope"], "%s must select a build-cache scope", jobName)
						cached++
					}
				}
			}
			require.Positive(t, cached, "the workflow must persist Go build results, not just its toolchain")
		})
	}
}
