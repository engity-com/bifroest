package main

import (
	gos "os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDockerBrowserE2ERunsSequentiallyWithBothRuntimesWithoutSkip(t *testing.T) {
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
	require.Empty(t, job.Strategy.Matrix.Runtime, "runtime setup and compiler cache must be shared")
	require.Contains(t, job.Strategy.Matrix.Suite, "docker")
	preparations := 0
	var executed []string
	baseline := make(map[string]bool)
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
			preparations++
		}
		if command == "mise run test:e2e:${{ matrix.suite }}" {
			env := step["env"].(map[string]any)
			baseline[env["BIFROEST_E2E_RUNTIME"].(string)] = true
		}
		if strings.HasPrefix(step["name"].(string), "Verify shared Docker workload through browser and OpenSSH with ") {
			require.Equal(t, 1, preparations, "frontend is built once before fixture Go embedding")
			env := step["env"].(map[string]any)
			runtime := env["BIFROEST_E2E_RUNTIME"].(string)
			require.True(t, baseline[runtime], "native SSH/recording baseline remains enabled")
			require.Equal(t, "${{ !cancelled() && matrix.suite == 'docker' && steps."+runtime+"-suite.outcome != 'skipped' }}", step["if"]) //nolint:misspell // GitHub Actions status function.
			require.Nil(t, step["continue-on-error"])
			require.Equal(t, "bash", step["shell"])
			require.Equal(t, "1", env["BIFROEST_TEST_BROWSER_UI"])
			for _, required := range []string{
				"set -euo pipefail",
				`mise -C web which node`,
				"go test -json -count=1 -tags=e2e -timeout=15m -run '^Test(SharedBrowserNetworkArguments|SharedBrowserNetworkIsolation|OpenSSHDockerBrowserSharedWorkload)$' ./test/e2e",
				`| tee "var/e2e/${BIFROEST_E2E_RUNTIME}/docker-browser.json"`,
				"os.environ['BIFROEST_E2E_RUNTIME'] / 'docker-browser.json'",
				"required = {'TestSharedBrowserNetworkArguments', 'TestSharedBrowserNetworkIsolation', 'TestOpenSSHDockerBrowserSharedWorkload'}",
				"passed = {e.get('Test') for e in events if e.get('Action') == 'pass'}",
				"assert required <= passed",
				"('skip', 'fail', 'build-fail')",
			} {
				require.Contains(t, command, required)
			}
			executed = append(executed, runtime)
		}
	}
	require.Equal(t, []string{"docker", "podman"}, executed, "both runtimes need real browser coverage")
}

// Configuration guard only; the actual kind/browser execution is a separate E2E.
func TestKubernetesBrowserE2ERunsSequentiallyWithBothKindProvidersWithoutSkip(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/workflows/e2e.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			If    string            `yaml:"if"`
			Needs any               `yaml:"needs"`
			Env   map[string]string `yaml:"env"`
			Steps []map[string]any  `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	job := workflow.Jobs["kind"]
	require.Equal(t, "files-changed", job.Needs)
	require.Equal(t, "always() && (github.event_name != 'pull_request' || needs.files-changed.outputs.go == 'true')", job.If)
	require.Equal(t, "docker", job.Env["BIFROEST_E2E_RUNTIME"])
	require.Equal(t, "docker", job.Env["KIND_EXPERIMENTAL_PROVIDER"])
	require.Equal(t, "0", job.Env["CGO_ENABLED"])
	for _, runtime := range []string{"docker", "podman"} {
		t.Run(runtime, func(t *testing.T) {
			baseline, prepared, executed := false, false, false
			for _, step := range job.Steps {
				command, ok := step["run"].(string)
				if !ok {
					continue
				}
				if command == "mise run test:e2e:kubernetes" && step["id"] == runtime+"-suite" {
					require.Nil(t, step["continue-on-error"])
					if runtime == "podman" {
						require.Equal(t, "${{ !cancelled() && steps.docker-suite.outcome != 'skipped' && (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') }}", step["if"]) //nolint:misspell // GitHub Actions status function.
						env := step["env"].(map[string]any)
						require.Equal(t, runtime, env["BIFROEST_E2E_RUNTIME"])
						require.Equal(t, runtime, env["KIND_EXPERIMENTAL_PROVIDER"])
					}
					baseline = true
				}
				if step["name"] == "Prepare actual Kubernetes browser E2E" {
					require.Nil(t, step["if"])
					require.Nil(t, step["continue-on-error"])
					for _, required := range []string{"mise -C web install", "mise -C web run install:web", "mise -C web run build:web", "mise -C web run install:web:browser"} {
						require.Contains(t, command, required)
					}
					prepared = true
				}
				if step["name"] == "Verify shared Kubernetes workload through browser and OpenSSH with "+strings.ToUpper(runtime[:1])+runtime[1:] {
					require.True(t, baseline, "native SSH/recording baseline remains enabled")
					require.True(t, prepared, "frontend must precede fixture Go embedding")
					require.Equal(t, "${{ !cancelled() && steps."+runtime+"-suite.outcome != 'skipped' }}", step["if"]) //nolint:misspell // GitHub Actions status function.
					require.Nil(t, step["continue-on-error"])
					require.Equal(t, "bash", step["shell"])
					env := step["env"].(map[string]any)
					require.Equal(t, "1", env["BIFROEST_TEST_BROWSER_UI"])
					if runtime == "podman" {
						require.Equal(t, runtime, env["BIFROEST_E2E_RUNTIME"])
						require.Equal(t, runtime, env["KIND_EXPERIMENTAL_PROVIDER"])
					}
					for _, required := range []string{
						"set -euo pipefail",
						`mise -C web which node`,
						"go test -json -count=1 -tags=e2e -timeout=30m -run '^Test(SharedBrowserNetworkArguments|SharedBrowserNetworkIsolation|OpenSSHKubernetesBrowserSharedWorkload)$' ./test/e2e",
						`| tee "var/e2e/${BIFROEST_E2E_RUNTIME}/kubernetes-browser.json"`,
						"os.environ['BIFROEST_E2E_RUNTIME'] / 'kubernetes-browser.json'",
						"required = {'TestSharedBrowserNetworkArguments', 'TestSharedBrowserNetworkIsolation', 'TestOpenSSHKubernetesBrowserSharedWorkload'}",
						"passed = {e.get('Test') for e in events if e.get('Action') == 'pass'}",
						"assert required <= passed",
						"('skip', 'fail', 'build-fail')",
					} {
						require.Contains(t, command, required)
					}
					executed = true
				}
			}
			require.True(t, executed, "a native SSH-only kind suite is not browser coverage")
		})
	}
}

func TestWorkloadBrowserE2ENetworkIsolationIsMandatory(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/workflows/e2e.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	for _, name := range []string{"runtime", "kind"} {
		t.Run(name, func(t *testing.T) {
			prepared := false
			for _, step := range workflow.Jobs[name].Steps {
				if step["name"] == "Prepare and check browser network isolation" {
					require.Nil(t, step["continue-on-error"])
					require.Equal(t, "bash", step["shell"])
					if name == "runtime" {
						require.Equal(t, "matrix.suite == 'docker'", step["if"])
					} else {
						require.Nil(t, step["if"])
					}
					command := step["run"].(string)
					for _, required := range []string{
						"set -euo pipefail",
						"sudo apt-get install --yes passt",
						`pasta --quiet --config-net --ipv4-only --splice-only --tcp-ports none --udp-ports none --tcp-ns none --udp-ns none -- /bin/sh -c 'exec "$@"' bifroest-browser /bin/true`,
						"exit 1",
					} {
						require.Contains(t, command, required)
					}
					prepared = true
				}
				if step["name"] == "Prepare actual Docker browser E2E" || step["name"] == "Prepare actual Kubernetes browser E2E" {
					require.True(t, prepared, "network isolation must be checked before expensive browser setup")
				}
			}
			require.True(t, prepared, "all Linux workload browser jobs require network isolation")
		})
	}
}
