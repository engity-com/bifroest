package main

import (
	gos "os"
	goexec "os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type goJobsWorkflowStep struct {
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	If              string            `yaml:"if"`
	Shell           string            `yaml:"shell"`
	ContinueOnError bool              `yaml:"continue-on-error"`
	With            map[string]string `yaml:"with"`
	Env             map[string]string `yaml:"env"`
}

type goJobsWorkflowJob struct {
	Name            string            `yaml:"name"`
	Needs           yaml.Node         `yaml:"needs"`
	If              string            `yaml:"if"`
	RunsOn          string            `yaml:"runs-on"`
	ContinueOnError bool              `yaml:"continue-on-error"`
	Permissions     map[string]string `yaml:"permissions"`
	Env             map[string]string `yaml:"env"`
	Container       struct {
		Image string `yaml:"image"`
	} `yaml:"container"`
	Strategy struct {
		FailFast *bool `yaml:"fail-fast"`
		Matrix   any   `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []goJobsWorkflowStep `yaml:"steps"`
}

func readGoJobsWorkflow(t *testing.T) map[string]goJobsWorkflowJob {
	t.Helper()
	raw, err := gos.ReadFile("../../.github/workflows/build.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]goJobsWorkflowJob `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	return workflow.Jobs
}

// Configuration guards only: hosted runner execution remains a CI check.
func TestGoWorkflowTestsRaceAndLintRunIndependently(t *testing.T) {
	jobs := readGoJobsWorkflow(t)
	checks := map[string]struct {
		command, matrix string
		lint, native    bool
	}{
		"test-host":         {"mise -C web exec -- node scripts/native-go-tests.ts", "test_host_matrix", false, false},
		"test-container":    {"mise run test:go", "test_container_matrix", false, true},
		"test-race":         {"mise run test:go:race", "test_container_matrix", false, true},
		"lint-go-host":      {"mise run lint:go", "test_host_matrix", true, false},
		"lint-go-container": {"mise run lint:go", "test_container_matrix", true, true},
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			job, found := jobs[name]
			require.True(t, found)
			require.Zero(t, job.Needs.Kind, "checks must use independent runners, not wait for one another")
			require.False(t, job.ContinueOnError)
			require.Equal(t, map[string]string{"contents": "read"}, job.Permissions)
			require.Equal(t, "${{ matrix.runner }}", job.RunsOn)
			require.Equal(t, "${{ fromJSON(inputs."+check.matrix+") }}", job.Strategy.Matrix)
			require.NotNil(t, job.Strategy.FailFast)
			require.False(t, *job.Strategy.FailFast, "one platform failure must not cancel the other checks")
			if check.lint {
				require.Equal(t, "inputs.lint_go", job.If)
			} else {
				require.Empty(t, job.If, "normal and race tests remain mandatory")
			}
			if check.native {
				require.Equal(t, "${{ matrix.image }}", job.Container.Image)
				require.NotEqual(t, "0", job.Env["CGO_ENABLED"], "prepared containers retain native PAM compilation")
			} else {
				require.Empty(t, job.Container.Image)
				require.Equal(t, "0", job.Env["CGO_ENABLED"])
				require.Equal(t, "-p=2", job.Env["GOFLAGS"])
			}

			checkout, dependencies, command, node := -1, -1, -1, -1
			for i, step := range job.Steps {
				require.False(t, step.ContinueOnError)
				require.Empty(t, step.If, "a scheduled check must not silently skip preparation or execution")
				if check.native {
					require.NotEqual(t, "0", step.Env["CGO_ENABLED"])
				}
				if strings.HasPrefix(step.Uses, "actions/checkout@") {
					checkout = i
					require.Equal(t, "${{ inputs.commit || inputs.ref }}", step.With["ref"])
					require.Equal(t, "false", step.With["persist-credentials"])
				}
				if strings.Contains(step.Run, "mise run install:go") {
					dependencies = i
					require.Equal(t, jobs["test-host"].Steps[goJobsStepContaining(t, jobs["test-host"], "mise run install:go")], step)
				}
				if step.Run == "mise -C web install node" {
					node = i
				}
				if step.Run == check.command {
					require.Equal(t, -1, command, "run each check once")
					command = i
				} else {
					require.NotContains(t, step.Run, "mise run lint:go")
					require.NotContains(t, step.Run, "mise run test:go")
					require.NotContains(t, step.Run, "scripts/native-go-tests.ts")
				}
			}
			require.NotEqual(t, -1, checkout)
			require.Greater(t, dependencies, checkout)
			require.Greater(t, command, dependencies)
			if name == "test-host" {
				require.Greater(t, node, checkout, "keep the pinned Node WebCrypto runtime")
				require.Less(t, node, command)
			}
		})
	}
}

func TestGoWorkflowRaceRetainsPreparedContainerAndAsciinema(t *testing.T) {
	jobs := readGoJobsWorkflow(t)
	normal, race := jobs["test-container"], jobs["test-race"]
	require.Equal(t, normal.Container, race.Container)
	require.Equal(t, normal.Strategy, race.Strategy)
	require.Equal(t, normal.Env, race.Env)
	for _, fragment := range []string{"git config --global --add safe.directory", "mise run install:go", "sha256sum --check -"} {
		normalStep := normal.Steps[goJobsStepContaining(t, normal, fragment)]
		raceIndex := goJobsStepContaining(t, race, fragment)
		require.Equal(t, normalStep, race.Steps[raceIndex], "normal and race tests need identical native preparation")
		require.Less(t, raceIndex, goJobsStepContaining(t, race, "mise run test:go:race"))
	}
	asciinema := race.Steps[goJobsStepContaining(t, race, "sha256sum --check -")]
	require.Equal(t, "3.2.1", asciinema.Env["ASCIINEMA_VERSION"])
	require.Equal(t, "bec9781bc8f297a9d3d74ff60205599507f2abba1183578b8b2f22be4c999214", asciinema.Env["ASCIINEMA_SHA256"])
	require.Contains(t, asciinema.Run, `test "$("$RUNNER_TEMP/asciinema" --version)" = "asciinema ${ASCIINEMA_VERSION}"`)
	require.Contains(t, asciinema.Run, `echo "ASCIINEMA=$RUNNER_TEMP/asciinema" >> "$GITHUB_ENV"`)

	step := race.Steps[goJobsStepContaining(t, race, "mise run test:go:race")]
	require.Equal(t, "mise run test:go:race", step.Run, "do not narrow or replace the full race task")
	value, exists := step.Env["MISE_GITHUB_TOKEN"]
	require.True(t, exists)
	require.Empty(t, value)
}

func TestGoWorkflowPackageGateRequiresAllChecksButAllowsReleaseLintSkip(t *testing.T) {
	job := readGoJobsWorkflow(t)["package"]
	mandatory := map[string]string{
		"test-host":        "TEST_HOST_RESULT",
		"test-container":   "TEST_CONTAINER_RESULT",
		"test-race":        "TEST_RACE_RESULT",
		"binary-host":      "BINARY_HOST_RESULT",
		"binary-container": "BINARY_CONTAINER_RESULT",
	}
	lint := map[string]string{
		"lint-go-host":      "LINT_GO_HOST_RESULT",
		"lint-go-container": "LINT_GO_CONTAINER_RESULT",
	}
	var needs []string
	require.NoError(t, job.Needs.Decode(&needs))
	expectedEnv := map[string]string{"LINT_GO": "${{ inputs.lint_go }}"}
	var expectedNeeds []string
	for _, group := range []map[string]string{mandatory, lint} {
		for name, key := range group {
			expectedNeeds = append(expectedNeeds, name)
			expectedEnv[key] = "${{ needs." + name + ".result }}"
		}
	}
	require.ElementsMatch(t, expectedNeeds, needs)
	require.Equal(t, "Package", job.Name, "preserve the ruleset's required check name")
	require.Equal(t, "${{ !cancelled() }}", job.If, "dependency failures must run and fail Package, not skip it") //nolint:misspell // GitHub Actions status function.
	require.False(t, job.ContinueOnError)
	require.NotEmpty(t, job.Steps)
	gate := job.Steps[0]
	require.Empty(t, gate.Uses, "the gate runs before checkout or any other action")
	require.Empty(t, gate.If)
	require.False(t, gate.ContinueOnError)
	require.Equal(t, "bash", gate.Shell)
	require.Equal(t, expectedEnv, gate.Env)
	for _, step := range job.Steps[1:] {
		require.False(t, step.ContinueOnError)
		for _, bypass := range []string{"always(", "failure(", "cancelled("} { //nolint:misspell // GitHub Actions status function.
			require.NotContains(t, step.If, bypass, "later steps must not bypass a failed gate")
		}
	}

	// Execute the actual first step, not a second implementation of its logic.
	t.Run("bash", func(t *testing.T) {
		bash, err := goexec.LookPath("bash")
		if err != nil {
			t.Skip("Bash is unavailable; structural gate guards still run")
		}
		run := func(t *testing.T, values map[string]string) (string, error) {
			t.Helper()
			command := goexec.Command(bash, "-e", "-o", "pipefail", "-c", gate.Run)
			command.Env = gos.Environ()
			for key, value := range values {
				command.Env = append(command.Env, key+"="+value)
			}
			output, err := command.CombinedOutput()
			return string(output), err
		}
		for _, enabled := range []bool{false, true} {
			t.Run("lint="+strconv.FormatBool(enabled), func(t *testing.T) {
				values := map[string]string{"LINT_GO": strconv.FormatBool(enabled)}
				for _, key := range mandatory {
					values[key] = "success"
				}
				for _, key := range lint {
					values[key] = "success"
				}
				output, err := run(t, values)
				require.NoError(t, err, output)
				if !enabled {
					for _, key := range lint {
						values[key] = "skipped"
					}
					output, err = run(t, values)
					require.NoError(t, err, "release must allow skipped lint: %s", output)
				}
				required := []map[string]string{mandatory}
				if enabled {
					required = append(required, lint)
				}
				for _, group := range required {
					for name, key := range group {
						for _, status := range []string{"failure", "cancelled", "skipped", ""} { //nolint:misspell // GitHub Actions job result.
							values[key] = status
							output, err = run(t, values)
							var exit *goexec.ExitError
							require.ErrorAs(t, err, &exit, "%s=%s must fail Package", name, status)
							require.Equal(t, 1, exit.ExitCode())
							require.Contains(t, output, "::error::Required job "+name+" did not succeed")
						}
						values[key] = "success"
					}
				}
			})
		}
	})

	var workflow struct {
		On struct {
			Call struct {
				Inputs map[string]struct{ Default any } `yaml:"inputs"`
			} `yaml:"workflow_call"`
		} `yaml:"on"`
	}
	raw, err := gos.ReadFile("../../.github/workflows/build.yml")
	require.NoError(t, err)
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	require.Equal(t, false, workflow.On.Call.Inputs["lint_go"].Default)
	for path, enabled := range map[string]bool{"release.yml": false, "ci.yml": true} {
		var caller struct {
			Jobs map[string]struct {
				Name string
				With map[string]any
			} `yaml:"jobs"`
		}
		raw, err = gos.ReadFile("../../.github/workflows/" + path)
		require.NoError(t, err)
		require.NoError(t, yaml.Unmarshal(raw, &caller))
		value, exists := caller.Jobs["build"].With["lint_go"]
		if enabled || exists {
			require.Equal(t, enabled, value, path)
		}
		if path == "ci.yml" {
			require.Equal(t, "Build packages", caller.Jobs["build"].Name)
		}
	}
}

func TestGoWorkflowCachesFollowMiseAndIsolateBuildContexts(t *testing.T) {
	jobs := readGoJobsWorkflow(t)
	contexts := map[string]string{
		"browser":           "cgo0",
		"test-host":         "cgo0",
		"lint-go-host":      "cgo0",
		"test-policy":       "cgo0",
		"test-policy-oci":   "cgo0",
		"test-container":    "native-${{ matrix.image }}",
		"test-race":         "native-${{ matrix.image }}",
		"lint-go-container": "native-${{ matrix.image }}",
		"binary-host":       "${{ matrix.os }}-${{ matrix.arch }}-${{ matrix.edition }}",
		"binary-container":  "${{ matrix.image }}-${{ matrix.os }}-${{ matrix.arch }}-${{ matrix.edition }}",
		"package":           jobs["package"].Container.Image,
	}
	for name, context := range contexts {
		t.Run(name, func(t *testing.T) {
			mise, cache := -1, -1
			for i, step := range jobs[name].Steps {
				if strings.HasPrefix(step.Uses, "jdx/mise-action@") {
					mise = i
				}
				if step.Uses == "./.github/actions/cache-go" {
					require.Equal(t, -1, cache)
					cache = i
					require.Equal(t, name, step.With["scope"])
					require.Equal(t, context, step.With["context"])
					require.Empty(t, step.If)
					require.False(t, step.ContinueOnError)
				}
				if step.Uses != "" && step.With["path"] != "" {
					require.NotContains(t, step.With["path"], "go/pkg/mod", "the composite owns Go cache paths")
				}
			}
			require.NotEqual(t, -1, mise)
			require.Greater(t, cache, mise, "go env must come from the pinned MISE toolchain")
		})
	}
}

func goJobsStepContaining(t *testing.T, job goJobsWorkflowJob, fragment string) int {
	t.Helper()
	for i, step := range job.Steps {
		if strings.Contains(step.Run, fragment) {
			return i
		}
	}
	t.Fatalf("missing workflow command containing %q", fragment)
	return -1
}
