package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Configuration guards only; hosted runner timings and both runtime executions
// still need to be measured in CI.
func TestE2ERuntimesSharePreparationWithoutHidingFailures(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/e2e.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			Env             map[string]string `yaml:"env"`
			TimeoutMinutes  int               `yaml:"timeout-minutes"`
			ContinueOnError bool              `yaml:"continue-on-error"`
			Strategy        struct {
				FailFast *bool               `yaml:"fail-fast"`
				Matrix   map[string][]string `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct {
				ID              string            `yaml:"id"`
				Name            string            `yaml:"name"`
				Uses            string            `yaml:"uses"`
				Run             string            `yaml:"run"`
				If              string            `yaml:"if"`
				Env             map[string]string `yaml:"env"`
				ContinueOnError bool              `yaml:"continue-on-error"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	require.NotContains(t, workflow.Jobs, "kind-docker")
	require.NotContains(t, workflow.Jobs, "kind-podman")
	require.Empty(t, workflow.Jobs["runtime"].Strategy.Matrix, "all three suites must share a single runner")
	for _, name := range []string{"runtime", "kind"} {
		t.Run(name, func(t *testing.T) {
			job := workflow.Jobs[name]
			require.False(t, job.ContinueOnError)
			budget := 120
			if name == "runtime" {
				budget = 360
			}
			require.Equal(t, budget, job.TimeoutMinutes, "combined job retains the previous total execution budget")
			counts := make(map[string]int)
			var runtimes, diagnostics []string
			prepared := false
			for _, step := range job.Steps {
				require.False(t, step.ContinueOnError, "a runtime failure must fail the combined job")
				counts[step.Name]++
				if step.Uses == "./.github/actions/cache-go" {
					counts["cache"]++
				}
				if name == "runtime" && step.ID == "prepare" {
					require.Equal(t, "Prepare shared browser E2E", step.Name)
					require.Empty(t, step.If, "setup must be required before any suite")
					prepared = true
				}
				nativeSuite := strings.HasPrefix(step.Run, "mise run test:e2e:") && !strings.HasSuffix(step.Run, ":browser")
				if nativeSuite {
					runtime := step.Env["BIFROEST_E2E_RUNTIME"]
					if runtime == "" {
						runtime = job.Env["BIFROEST_E2E_RUNTIME"]
					}
					suite := strings.TrimPrefix(step.Run, "mise run test:e2e:")
					runtimes = append(runtimes, runtime+":"+suite)
					if name == "runtime" {
						require.True(t, prepared, "build the frontend once before fixture Go embedding")
						require.Equal(t, runtime+"-"+suite, step.ID)
						require.Equal(t, "${{ !cancelled() && steps.prepare.outcome == 'success' }}", step.If) //nolint:misspell // GitHub Actions status function.
					} else if step.ID == "docker-suite" {
						require.Empty(t, step.If)
					} else {
						require.Contains(t, step.If, "!cancelled()", "explicit status check overrides implicit success()") //nolint:misspell // GitHub Actions status function.
						require.Contains(t, step.If, "steps.docker-suite.outcome != 'skipped'", "do not run after failed shared setup")
					}
					if name == "kind" {
						require.Equal(t, "mise run test:e2e:kubernetes", step.Run)
					}
				}
				if strings.HasPrefix(step.Name, "Collect ") {
					require.Contains(t, step.If, "failure()")
					require.Contains(t, step.Run, "var/e2e/${BIFROEST_E2E_RUNTIME}")
					runtime := step.Env["BIFROEST_E2E_RUNTIME"]
					if runtime == "" {
						runtime = job.Env["BIFROEST_E2E_RUNTIME"]
					}
					diagnostics = append(diagnostics, runtime)
				}
			}
			expected := []string{"docker:kubernetes", "podman:kubernetes"}
			if name == "runtime" {
				expected = []string{"docker:local", "docker:docker", "docker:ssh", "podman:local", "podman:docker", "podman:ssh"}
			}
			require.Equal(t, expected, runtimes, "all suites and runtimes must execute exactly once in order")
			require.Equal(t, []string{"docker", "podman"}, diagnostics, "runtime logs must not overwrite each other")
			for _, setup := range []string{"Install Podman", "Checkout code", "Install MISE", "Install dependencies", "cache", "Upload failure diagnostics"} {
				require.Equal(t, 1, counts[setup], "shared step: %s", setup)
			}
			browser := "Prepare shared browser E2E"
			if name == "kind" {
				browser = "Prepare actual Kubernetes browser E2E"
			}
			require.Equal(t, 1, counts[browser], "browser toolchain and frontend are built once")
		})
	}
}

func TestAuthorizationE2EWarmBuildPreservesRuntimeBudgetAndFreshFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../mise.toml")
	require.NoError(t, err)
	section := func(name string) string {
		_, rest, found := strings.Cut(string(raw), "[tasks.\""+name+"\"]")
		require.True(t, found, "required MISE task %s", name)
		body, _, _ := strings.Cut(rest, "\n[tasks.")
		return body
	}
	test := section("test:e2e:authorization")
	require.Contains(t, test, `"build:e2e:authorization"`)
	require.Contains(t, test, "-count=1 -tags=e2e -timeout=5m")
	require.Contains(t, test, "^Test(HtpasswdAuthorization|OIDC.*|SimpleRememberMe)$")
	build := section("build:e2e:authorization")
	for _, value := range []string{`CGO_ENABLED = "0"`, "-tags local_build,local_kind -trimpath", "-tags e2e -trimpath", "./cmd/bifroest", "./test/e2e/helper"} {
		require.Contains(t, build, value)
	}
	harness, err := os.ReadFile("../../test/e2e/harness_test.go")
	require.NoError(t, err)
	require.NotContains(t, string(harness), "authorization-build-cache", "warm outputs are never test inputs")
	require.Contains(t, string(harness), `bifroestVersion: "e2e-" + unique`)
	require.Contains(t, string(harness), `"-s -w -X main.version=" + f.bifroestVersion`)
	require.Contains(t, string(harness), `result := runCommand(ctx, f.repoRoot, build.environment, f.goTool, args...)`)
}

func TestDarwinE2EKeepsNativeIntegrationsAndFixtureRegressions(t *testing.T) {
	raw, err := os.ReadFile("../../mise.toml")
	require.NoError(t, err)
	_, task, found := strings.Cut(string(raw), "[tasks.\"test:e2e:darwin\"]")
	require.True(t, found)
	task, _, _ = strings.Cut(task, "\n[tasks.")
	require.Contains(t, task, "-count=1 -tags=e2e -timeout=30m")
	match := regexp.MustCompile(`-run '([^']+)'`).FindStringSubmatch(task)
	require.Len(t, match, 2)
	selection, err := regexp.Compile(match[1])
	require.NoError(t, err)
	for _, name := range []string{
		"TestOpenSSHLocalNative", "TestDarwinLocalAccountLifecycle", "TestDarwinLaunchDaemon",
		"TestFixtureBinarySelection", "TestFixtureBuildFailure", "TestFixtureRejectsUnknownBuildMode",
	} {
		require.True(t, selection.MatchString(name), "Darwin task must execute %s", name)
	}
	require.False(t, selection.MatchString("TestOpenSSHDockerEnvironment"))
}
