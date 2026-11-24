package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	gos "os"
	"regexp"
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
	mandatory := []string{"test-host", "test-container", "test-race", "binary-host", "binary-container"}
	lint := []string{"lint-go-host", "lint-go-container"}
	var needs []string
	require.NoError(t, job.Needs.Decode(&needs))
	require.ElementsMatch(t, append(append([]string{}, mandatory...), lint...), needs)
	require.Contains(t, job.If, "cancelled()", "an explicit status function prevents Actions' implicit success() from skipping release packaging") //nolint:misspell // GitHub Actions status function.

	// Parse the small boolean gate rather than snapshotting its formatting.
	expression := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(job.If), "${{"), "}}"))
	expression = regexp.MustCompile(`needs\.([a-z0-9-]+)\.result`).ReplaceAllString(expression, `needs["$1"]`)
	expression = strings.ReplaceAll(expression, "inputs.lint_go", "lintGo")
	expression = regexp.MustCompile(`'([^']*)'`).ReplaceAllString(expression, `"$1"`)
	gate, err := parser.ParseExpr(expression)
	require.NoError(t, err)
	for _, enabled := range []bool{false, true} {
		label := "release"
		if enabled {
			label = "ci"
		}
		t.Run(label, func(t *testing.T) {
			results := make(map[string]string, len(needs))
			for _, name := range needs {
				results[name] = "success"
			}
			if !enabled {
				for _, name := range lint {
					results[name] = "skipped"
				}
			}
			require.Equal(t, true, evalGoJobsGate(t, gate, results, enabled, false))
			require.Equal(t, false, evalGoJobsGate(t, gate, results, enabled, true), "canceled runs must not package")
			required := mandatory
			if enabled {
				required = append(append([]string{}, mandatory...), lint...)
			}
			for _, name := range required {
				for _, status := range []string{"failure", "cancelled", "skipped"} { //nolint:misspell // GitHub Actions job result.
					results[name] = status
					require.Equal(t, false, evalGoJobsGate(t, gate, results, enabled, false), "%s=%s must block packaging", name, status)
				}
				results[name] = "success"
			}
		})
	}

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
			Jobs map[string]struct{ With map[string]any } `yaml:"jobs"`
		}
		raw, err = gos.ReadFile("../../.github/workflows/" + path)
		require.NoError(t, err)
		require.NoError(t, yaml.Unmarshal(raw, &caller))
		value, exists := caller.Jobs["build"].With["lint_go"]
		if enabled || exists {
			require.Equal(t, enabled, value, path)
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

// Evaluate only the boolean/string subset used by the package job's condition.
func evalGoJobsGate(t *testing.T, expression ast.Expr, results map[string]string, lint, canceled bool) any {
	t.Helper()
	eval := func(child ast.Expr) any { return evalGoJobsGate(t, child, results, lint, canceled) }
	switch expression := expression.(type) {
	case *ast.ParenExpr:
		return eval(expression.X)
	case *ast.UnaryExpr:
		require.Equal(t, token.NOT, expression.Op)
		return !eval(expression.X).(bool)
	case *ast.BinaryExpr:
		left, right := eval(expression.X), eval(expression.Y)
		switch expression.Op {
		case token.LAND:
			return left.(bool) && right.(bool)
		case token.LOR:
			return left.(bool) || right.(bool)
		case token.EQL:
			return left == right
		}
	case *ast.Ident:
		require.Equal(t, "lintGo", expression.Name)
		return lint
	case *ast.CallExpr:
		require.Empty(t, expression.Args)
		name, ok := expression.Fun.(*ast.Ident)
		require.True(t, ok)
		require.Equal(t, "cancelled", name.Name) //nolint:misspell // GitHub Actions status function.
		return canceled
	case *ast.IndexExpr:
		name, ok := expression.X.(*ast.Ident)
		require.True(t, ok)
		require.Equal(t, "needs", name.Name)
		key := eval(expression.Index).(string)
		value, exists := results[key]
		require.True(t, exists, "gate references undeclared need %q", key)
		return value
	case *ast.BasicLit:
		require.Equal(t, token.STRING, expression.Kind)
		value, err := strconv.Unquote(expression.Value)
		require.NoError(t, err)
		return value
	}
	t.Fatalf("unsupported package gate expression: %#v", expression)
	return nil
}
