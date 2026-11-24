package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoTestTasksBoundPackageParallelismWithoutReducingChecks(t *testing.T) {
	raw, err := os.ReadFile("../../mise.toml")
	require.NoError(t, err)
	for _, tt := range []struct {
		name     string
		commands []string
	}{
		{
			name: "test:go",
			commands: []string{
				`'go run ./cmd/testreport run --output var/test-report/core -- go test -p={{env.GO_TEST_PARALLELISM | default(value="2")}} -json ./...'`,
				`'go run ./cmd/testreport run --output var/test-report/alternatives -- go test -p={{env.GO_TEST_PARALLELISM | default(value="2")}} -json -tags=local_build,local_kind ./pkg/alternatives'`,
			},
		},
		{
			name: "test:go:coverage",
			commands: []string{
				`'go run ./cmd/testreport run --output var/test-report/core -- go test -p={{env.GO_TEST_PARALLELISM | default(value="2")}} -json -covermode atomic -coverprofile=var/profile.cov ./...'`,
				`'go run ./cmd/testreport run --output var/test-report/alternatives -- go test -p={{env.GO_TEST_PARALLELISM | default(value="2")}} -json -tags=local_build,local_kind ./pkg/alternatives'`,
			},
		},
		{
			name: "test:go:race",
			commands: []string{
				`'go run ./cmd/testreport run --output var/test-report/race -- go test -p={{env.GO_TEST_PARALLELISM | default(value="2")}} -json -race ./...'`,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, rest, found := strings.Cut(string(raw), `[tasks."`+tt.name+`"]`)
			require.True(t, found, "required MISE task %s", tt.name)
			body, _, _ := strings.Cut(rest, "\n[tasks.")
			require.Contains(t, body, `depends = ["build:var"]`)
			require.Equal(t, len(tt.commands), strings.Count(body, "go test "), "guard every Go test invocation, including the local_build/local_kind variant")
			for _, command := range tt.commands {
				require.Contains(t, body, command, "keep the bounded, overridable default and existing test scope/options")
			}
		})
	}
}

func TestGoWorkflowKeepsWindowsTestsSerialWithoutNarrowingTheSuite(t *testing.T) {
	jobs := readGoJobsWorkflow(t)
	require.Equal(t, "${{ matrix.os == 'windows' && '1' || '2' }}", jobs["test-host"].Env["GO_TEST_PARALLELISM"])
	for _, job := range []string{"test-container", "test-race", "test-static", "test-browser"} {
		configuration, found := jobs[job]
		require.True(t, found)
		require.Empty(t, configuration.Env["GO_TEST_PARALLELISM"], "%s must retain the bounded default", job)
	}
	step := jobs["test-host"].Steps[goJobsStepContaining(t, jobs["test-host"], "scripts/native-go-tests.ts")]
	require.Equal(t, "mise -C web exec -- node scripts/native-go-tests.ts", step.Run)
	require.Empty(t, step.If)
	require.False(t, step.ContinueOnError)
}
