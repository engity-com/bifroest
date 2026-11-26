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
			cacheAction := "./.github/actions/cache-go"
			workflowRevision := name == "build.yml" || name == "release.yml"
			if workflowRevision {
				cacheAction = "./var/ci-workflow/.github/actions/cache-go"
			}
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
			cached, buildCached := 0, 0
			for jobName, job := range workflow.Jobs {
				checkout, toolchain, helper := false, false, false
				for _, step := range job.Steps {
					if strings.HasPrefix(step.Uses, "actions/checkout@") && step.With["path"] == "" {
						checkout = true
					}
					if strings.HasPrefix(step.Uses, "actions/checkout@") && step.With["path"] == "var/ci-workflow" {
						require.True(t, checkout, "%s must keep its selected source checkout", jobName)
						require.Equal(t, "${{ github.workflow_sha }}", step.With["ref"])
						require.Equal(t, "${{ github.repository }}", step.With["repository"])
						sparse := ".github/actions/cache-go"
						if name == "release.yml" {
							sparse += "\n.github/scripts/group-binary-matrices.ts\n.github/mise.toml\nmise.tools.yaml\n"
						}
						require.Equal(t, sparse, step.With["sparse-checkout"])
						require.Equal(t, "false", step.With["sparse-checkout-cone-mode"])
						require.Equal(t, "false", step.With["persist-credentials"])
						helper = true
					}
					if strings.HasPrefix(step.Uses, "jdx/mise-action@") {
						toolchain = true
					}
					require.NotEqual(t, "~/go/pkg/mod", step.With["path"], "%s must use the resolved module and build caches", jobName)
					if step.Uses == cacheAction {
						require.True(t, checkout, "%s must check out the local action first", jobName)
						require.True(t, toolchain, "%s must resolve its pinned Go before caching", jobName)
						if workflowRevision {
							require.True(t, helper, "%s must load cache infrastructure from its workflow revision, not an older source tag", jobName)
						}
						require.NotEmpty(t, step.With["scope"], "%s must select a build-cache scope", jobName)
						cached++
						if name == "build.yml" && (jobName == "test-static" || jobName == "test-host" || jobName == "test-container" || jobName == "test-race") {
							require.Equal(t, "true", step.With["build-cache"], "%s must persist expensive test builds", jobName)
							buildCached++
						} else if name == "build.yml" && jobName == "test-browser" {
							require.Equal(t, "restore-only", step.With["build-cache"], "browser shards must not multiply persistent build snapshots")
							require.Equal(t, "browser", step.With["scope"], "reuse the static core writer's cache identity")
						} else {
							require.Empty(t, step.With["build-cache"], "%s must keep the module-only default instead of crowding out expensive test caches", jobName)
						}
					}
				}
			}
			require.Positive(t, cached, "the workflow must cache Go dependencies, not just its toolchain")
			if name == "build.yml" {
				require.Equal(t, 4, buildCached, "only core tests, race and browser may write build snapshots")
			}
		})
	}
}
