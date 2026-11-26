package main

import (
	gos "os"
	goexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type goJobsWorkflowStep struct {
	Name            string            `yaml:"name"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	If              string            `yaml:"if"`
	Shell           string            `yaml:"shell"`
	TimeoutMinutes  int               `yaml:"timeout-minutes"`
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
	return readGoJobsWorkflowFile(t, "build.yml")
}

func readGoJobsWorkflowFile(t *testing.T, file string) map[string]goJobsWorkflowJob {
	t.Helper()
	raw, err := gos.ReadFile("../../.github/workflows/" + file)
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
		"test-host":         {"mise run test:go:native", "test_host_matrix", false, false},
		"test-container":    {"mise run test:go:coverage", "test_container_matrix", false, true},
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

			checkout, dependencies, command := -1, -1, -1
			for i, step := range job.Steps {
				require.False(t, step.ContinueOnError)
				if name == "test-host" && step.Name == "Stress management channel completion on Windows" {
					require.Equal(t, "runner.os == 'Windows'", step.If)
				} else if step.If != "" {
					require.Equal(t, "always()", step.If, "only failure diagnostics may have a conditional")
					if step.Uses != "" {
						require.True(t, strings.HasPrefix(step.Uses, "actions/upload-artifact@"))
						require.Contains(t, step.With["path"], "var/test-report/")
					} else {
						require.Contains(t, step.Run, "GITHUB_STEP_SUMMARY")
					}
				}
				if check.native {
					require.NotEqual(t, "0", step.Env["CGO_ENABLED"])
				}
				if strings.HasPrefix(step.Uses, "actions/checkout@") && step.With["path"] == "" {
					checkout = i
					require.Equal(t, "${{ inputs.commit || inputs.ref }}", step.With["ref"])
					require.Equal(t, "false", step.With["persist-credentials"])
				}
				if strings.Contains(step.Run, "mise run install:go") {
					dependencies = i
					require.Equal(t, jobs["test-host"].Steps[goJobsStepContaining(t, jobs["test-host"], "mise run install:go")], step)
				}
				if strings.Contains(step.Run, check.command) {
					require.Equal(t, -1, command, "run each check once")
					require.Empty(t, step.If, "test execution must remain mandatory")
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
		"assemble":         "ASSEMBLE_RESULT",
		"browser":          "BROWSER_RESULT",
		"test-static":      "TEST_STATIC_RESULT",
		"test-web":         "TEST_WEB_RESULT",
		"test-browser":     "TEST_BROWSER_RESULT",
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

	// Run every case in one Bash invocation, using the actual first step verbatim.
	t.Run("bash", func(t *testing.T) {
		bash, err := goexec.LookPath("bash")
		if err != nil {
			t.Skip("Bash is unavailable; structural gate guards still run")
		}
		var script strings.Builder
		script.WriteString("actual_gate() (\n")
		script.WriteString(gate.Run)
		script.WriteString("\n)\n")
		script.WriteString(`assert_gate() {
  local expected_status="$1" expected_job="$2" case_name="$3"
  local status=0 output
  output="$(actual_gate 2>&1)" || status=$?
  if [ "$status" -ne "$expected_status" ]; then
    printf '%s: expected exit %s, got %s\n%s\n' "$case_name" "$expected_status" "$status" "$output" >&2
    exit 1
  fi
  if [ "$expected_status" -ne 0 ] && [[ "$output" != *"::error::Required job $expected_job did not succeed"* ]]; then
    printf '%s: missing error annotation for %s\n%s\n' "$case_name" "$expected_job" "$output" >&2
    exit 1
  fi
}
`)
		cases := 0
		addCase := func(values map[string]string, expectedStatus int, expectedJob, name string) {
			for key, value := range values {
				script.WriteString(key + "=" + strconv.Quote(value) + "\n")
			}
			script.WriteString("assert_gate " + strconv.Itoa(expectedStatus) + " " + strconv.Quote(expectedJob) + " " + strconv.Quote(name) + "\n")
			cases++
		}
		for _, enabled := range []bool{false, true} {
			label := "lint=" + strconv.FormatBool(enabled)
			values := map[string]string{"LINT_GO": strconv.FormatBool(enabled)}
			for _, key := range mandatory {
				values[key] = "success"
			}
			for _, key := range lint {
				values[key] = "success"
			}
			addCase(values, 0, "", label+"/all-success")
			if !enabled {
				for _, key := range lint {
					values[key] = "skipped"
				}
				addCase(values, 0, "", label+"/skipped-lint")
			}
			required := []map[string]string{mandatory}
			if enabled {
				required = append(required, lint)
			}
			for _, group := range required {
				for name, key := range group {
					for _, status := range []string{"failure", "cancelled", "skipped", ""} { //nolint:misspell // GitHub Actions job result.
						values[key] = status
						addCase(values, 1, name, label+"/"+name+"="+status)
					}
					values[key] = "success"
				}
			}
		}
		// Keep the full matrix out of Windows' native command-line quoting and length limits.
		scriptPath := filepath.Join(t.TempDir(), "package-gate.sh")
		require.NoError(t, gos.WriteFile(scriptPath, []byte(script.String()), 0o600))
		command := goexec.Command(bash, "--noprofile", "--norc", "-e", "-o", "pipefail", filepath.ToSlash(scriptPath))
		output, err := command.CombinedOutput()
		require.NoError(t, err, string(output))
		t.Logf("checked %d gate cases in one Bash invocation", cases)
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
		"test-static":       "cgo0",
		"test-web":          "cgo0",
		"test-browser":      "cgo0",
		"test-host":         "cgo0",
		"lint-go-host":      "cgo0",
		"test-policy":       "cgo0",
		"test-policy-oci":   "cgo0",
		"test-container":    "native-${{ matrix.image }}",
		"test-race":         "native-${{ matrix.image }}",
		"lint-go-container": "native-${{ matrix.image }}",
		"binary-host":       "${{ matrix.os }}-${{ matrix.arch }}",
		"binary-container":  "${{ matrix.image }}-${{ matrix.os }}-${{ matrix.arch }}",
		"package":           jobs["package"].Container.Image,
		"assemble":          jobs["assemble"].Container.Image,
	}
	for name, context := range contexts {
		t.Run(name, func(t *testing.T) {
			scope := name
			switch name {
			case "browser":
				scope = "browser-assets"
			case "test-static", "test-browser":
				scope = "browser"
			case "assemble":
				scope = "package"
			}
			requireGoWorkflowSourceCache(t, jobs[name], "${{ inputs.commit || inputs.ref }}", scope, context)
		})
	}
}

func TestGoWorkflowReleaseCacheUsesSelectedSourceRevision(t *testing.T) {
	job := readGoJobsWorkflowFile(t, "release.yml")["evaluate"]
	requireGoWorkflowSourceCache(t, job, "${{ steps.release-version.outputs.release_tag }}", "build-tools", "")
	evaluated := false
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "mise run ci:evaluate-environment") {
			evaluated = true
			require.Equal(t, "${{ steps.release-version.outputs.release_tag }}", step.Env["GITHUB_REF_NAME"])
			require.Contains(t, step.Run, `GITHUB_SHA="$(git rev-parse HEAD)"`, "evaluate the selected source checkout")
			require.Contains(t, step.Run, "export GITHUB_SHA")
		}
	}
	require.True(t, evaluated)
}

func requireGoWorkflowSourceCache(t *testing.T, job goJobsWorkflowJob, sourceRef, scope, context string) {
	t.Helper()
	condition := ""
	if job.Name == "Package" {
		condition = "needs.assemble.outputs.publish == 'true' || inputs.upload_dist"
	}
	source, mise, cache := -1, -1, -1
	for i, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			require.Equal(t, "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", step.Uses)
			require.Equal(t, -1, source, "one source checkout owns tasks, versions, scripts and local actions")
			source = i
			require.Equal(t, sourceRef, step.With["ref"])
			require.Empty(t, step.With["path"])
			require.Empty(t, step.With["sparse-checkout"])
			require.Equal(t, condition, step.If)
			require.False(t, step.ContinueOnError)
		}
		if strings.HasPrefix(step.Uses, "jdx/mise-action@") {
			require.Equal(t, condition, step.If)
			mise = i
		}
		if step.Uses == "./.github/actions/cache-go" {
			require.Equal(t, -1, cache)
			cache = i
			require.Equal(t, scope, step.With["scope"])
			require.Equal(t, context, step.With["context"])
			require.Equal(t, condition, step.If)
			require.False(t, step.ContinueOnError)
		}
		if step.Uses != "" && step.With["path"] != "" {
			require.NotContains(t, step.With["path"], "go/pkg/mod", "the composite owns Go cache paths")
		}
	}
	require.NotEqual(t, -1, source)
	require.Greater(t, mise, source, "MISE reads the selected source checkout's pins")
	require.Greater(t, cache, mise, "the source's cache action provisions its task-scoped Go after installing MISE")
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
