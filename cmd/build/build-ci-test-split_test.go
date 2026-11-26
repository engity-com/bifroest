package main

import (
	"encoding/json"
	gos "os"
	goexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBrowserShardsReceiveTheSeparatelyBuiltClientFixture(t *testing.T) {
	jobs := readGoJobsWorkflow(t)
	producer := jobs["browser"]
	build := goJobsStepContaining(t, producer, "mise -C web run build:web")
	uploads := 0
	for i, step := range producer.Steps {
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.With["name"] == "browser-test-core" {
			uploads++
			require.Greater(t, i, build)
			require.Equal(t, "var/webui-client-build", step.With["path"])
			require.Equal(t, "error", step.With["if-no-files-found"])
			require.Empty(t, step.If)
		}
	}
	require.Equal(t, 1, uploads, "build the fixture once, not in each shard")
	for name, job := range jobs {
		downloads := 0
		for i, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/download-artifact@") && step.With["name"] == "browser-test-core" {
				downloads++
				require.Equal(t, "test-browser", name, "test-only fixture must not enter release binaries")
				require.Equal(t, "var/webui-client-build", step.With["path"])
				require.Empty(t, step.If)
				require.Less(t, i, goJobsStepContaining(t, job, "-- --shard"))
			}
		}
		if name == "test-browser" {
			require.Equal(t, 1, downloads)
		}
	}
	raw, err := gos.ReadFile("../../web/package.json")
	require.NoError(t, err)
	var web struct {
		Scripts map[string]string `json:"scripts"`
	}
	require.NoError(t, json.Unmarshal(raw, &web))
	require.Contains(t, web.Scripts["build"], "bun run build:core")
	require.Contains(t, web.Scripts["build"], "bun run build:app")
}

func TestBrowserShardMatrixIsCompleteAndRetainsIndependentRunners(t *testing.T) {
	jobs := readGoJobsWorkflow(t)
	job := jobs["test-browser"]
	require.Equal(t, "ubuntu-latest", job.RunsOn)
	require.NotNil(t, job.Strategy.FailFast)
	require.False(t, *job.Strategy.FailFast)
	require.Equal(t, map[string]any{"shard": []any{"1/3", "2/3", "3/3"}}, job.Strategy.Matrix)
	require.False(t, job.ContinueOnError)
	require.Empty(t, job.If)
	test := job.Steps[goJobsStepContaining(t, job, "-- --shard")]
	require.Equal(t, "${{ matrix.shard }}", test.Env["SHARD"])
	require.Empty(t, test.If)
	require.False(t, test.ContinueOnError)
	for _, name := range []string{"browser", "test-static", "test-web", "test-browser"} {
		for _, step := range jobs[name].Steps {
			require.False(t, step.ContinueOnError)
			if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
				continue
			}
			if strings.Contains(step.Run, "GITHUB_STEP_SUMMARY") {
				require.Equal(t, "always()", step.If)
				continue
			}
			require.Empty(t, step.If, "asset creation and all separated tests remain mandatory")
		}
	}
}

func TestSplitWorkflowInvokesTasksDirectlyAndPropagatesFailures(t *testing.T) {
	bash, err := goexec.LookPath("bash")
	if err != nil {
		t.Skip("Bash is required to exercise the workflow's task selection")
	}
	jobs := readGoJobsWorkflow(t)
	for _, browser := range []bool{false, true} {
		job, fragment := jobs["test-container"], "mise run test:go:coverage"
		if browser {
			job, fragment = jobs["test-browser"], "-- --shard"
		}
		step := job.Steps[goJobsStepContaining(t, job, fragment)]
		for _, status := range []string{"0", "23"} {
			shards := []string{"1/3"}
			if browser {
				shards = []string{"1/3", "2/3", "3/3"}
			}
			for _, shard := range shards {
				directory := t.TempDir()
				script := `mise() {
  printf 'EXEC %s\n' "$*"
  return "$TEST_EXIT"
}
` + step.Run
				path := filepath.Join(directory, "run.sh")
				require.NoError(t, gos.WriteFile(path, []byte(script), 0o600))
				command := goexec.Command(bash, "--noprofile", "--norc", "-e", "-o", "pipefail", filepath.ToSlash(path))
				command.Dir = directory
				command.Env = append(gos.Environ(), "SHARD="+shard, "TEST_EXIT="+status)
				output, runErr := command.CombinedOutput()
				expected := "run test:go:coverage"
				if browser {
					expected = "-C web run test:go:browser -- --shard " + shard
				}
				require.Equal(t, "EXEC "+expected+"\n", string(output))
				if status == "0" {
					require.NoError(t, runErr)
				} else {
					var exit *goexec.ExitError
					require.ErrorAs(t, runErr, &exit)
					require.Equal(t, 23, exit.ExitCode())
				}
			}
		}
	}
}

func TestCoverageIsCollectedOnceWithoutNarrowingOtherSuites(t *testing.T) {
	raw, err := gos.ReadFile("../../mise.toml")
	require.NoError(t, err)
	for _, task := range []string{"test:go", "test:go:race", "test:go:browser"} {
		_, rest, found := strings.Cut(string(raw), `[tasks."`+task+`"]`)
		require.True(t, found)
		body, _, _ := strings.Cut(rest, "\n[tasks.")
		require.NotContains(t, body, "-cover", "only the dedicated native Linux task collects coverage")
	}
	require.Equal(t, 1, strings.Count(string(raw), "-coverprofile="))
	jobs := readGoJobsWorkflow(t)
	require.NotContains(t, jobs["test-container"].Steps[goJobsStepContaining(t, jobs["test-container"], "mise run test:go:coverage")].Run, "-run ")
	for _, name := range []string{"test-host", "test-container", "test-race", "test-static", "test-browser"} {
		job := jobs[name]
		summary := job.Steps[goJobsStepContaining(t, job, "GITHUB_STEP_SUMMARY")]
		require.Equal(t, "always()", summary.If)
		require.Contains(t, summary.Run, "var/test-report/*.jsonl")
		require.Contains(t, summary.Run, "mise run ci:go:slowest -- --num 15 --threshold 0s --jsonfile")
		require.NotContains(t, summary.Run, "--skip-stmt", "duration reports must never rewrite tests")
		found := false
		for _, step := range job.Steps {
			if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && strings.Contains(step.With["path"], "var/test-report/") {
				found = true
				require.Equal(t, "always()", step.If)
			}
		}
		require.True(t, found, "%s must retain reports even on failure", name)
	}
}
