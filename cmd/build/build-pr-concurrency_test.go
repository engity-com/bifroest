package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type prConcurrencyGroup struct {
	Group            string `yaml:"group"`
	CancelInProgress string `yaml:"cancel-in-progress"`
}

type prConcurrencyWorkflow struct {
	Name        string               `yaml:"name"`
	On          map[string]yaml.Node `yaml:"on"`
	Concurrency *prConcurrencyGroup  `yaml:"concurrency"`
	Jobs        map[string]struct {
		Uses        string              `yaml:"uses"`
		Concurrency *prConcurrencyGroup `yaml:"concurrency"`
	} `yaml:"jobs"`
}

func readPRConcurrencyWorkflow(t *testing.T, file string) prConcurrencyWorkflow {
	t.Helper()
	raw, err := os.ReadFile("../../.github/workflows/" + file)
	require.NoError(t, err)
	var workflow prConcurrencyWorkflow
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	return workflow
}

// These structured configuration guards do not execute GitHub's scheduler.
func TestPRWorkflowConcurrencyCancelsOnlySamePRAndWorkflow(t *testing.T) {
	names := map[string]bool{}
	for _, test := range []struct {
		file   string
		events []string
	}{
		{"ci.yml", []string{"pull_request"}},
		{"codeql.yml", []string{"push", "pull_request", "schedule"}},
		{"e2e.yml", []string{"pull_request", "schedule", "workflow_dispatch"}},
		{"nanoserver.yml", []string{"pull_request", "workflow_dispatch"}},
	} {
		t.Run(test.file, func(t *testing.T) {
			workflow := readPRConcurrencyWorkflow(t, test.file)
			require.NotEmpty(t, workflow.Name)
			name := strings.ToLower(workflow.Name)
			require.NotContains(t, names, name, "GitHub concurrency groups are case-insensitive")
			names[name] = true
			require.ElementsMatch(t, test.events, prConcurrencyEventNames(workflow))
			pullRequest, exists := workflow.On["pull_request"]
			require.True(t, exists)
			var trigger struct {
				Types []string `yaml:"types"`
			}
			require.NoError(t, pullRequest.Decode(&trigger))
			if test.file == "codeql.yml" {
				require.Empty(t, trigger.Types, "CodeQL keeps the default PR events, including synchronize")
			} else {
				require.Contains(t, trigger.Types, "synchronize", "new PR commits must supersede older runs")
			}
			require.NotNil(t, workflow.Concurrency, "cancel the entire stale run, not individual matrix jobs")
			require.Equal(t,
				"${{ github.workflow }}-${{ github.event_name }}-${{ github.event.pull_request.number || github.run_id }}",
				workflow.Concurrency.Group,
				"PR numbers separate forks with identical branch names; workflow/event namespaces prevent collisions; run IDs keep non-PR runs and their pending runs independent")
			require.Equal(t, "${{ github.event_name == 'pull_request' }}", workflow.Concurrency.CancelInProgress,
				"only PR runs may cancel an in-progress run")
		})
	}
}

func TestPRConcurrencyStaysInCallerWithoutCancellingReusableOrRelease(t *testing.T) {
	ci := readPRConcurrencyWorkflow(t, "ci.yml")
	release := readPRConcurrencyWorkflow(t, "release.yml")
	build := readPRConcurrencyWorkflow(t, "build.yml")
	require.ElementsMatch(t, []string{"workflow_call"}, prConcurrencyEventNames(build))
	require.Nil(t, build.Concurrency, "github.workflow in a reusable workflow names its caller; sharing its group would cancel the caller")
	for name, job := range build.Jobs {
		require.Nil(t, job.Concurrency, "reusable job %s must not compete with caller concurrency", name)
	}
	for _, caller := range []prConcurrencyWorkflow{ci, release} {
		job, exists := caller.Jobs["build"]
		require.True(t, exists)
		require.Equal(t, "./.github/workflows/build.yml", job.Uses)
		require.Nil(t, job.Concurrency, "the reusable call must not compete with workflow concurrency")
	}
	require.Nil(t, release.Concurrency, "new PR commits must never cancel release/publish runs")
	require.ElementsMatch(t, []string{"release", "workflow_dispatch"}, prConcurrencyEventNames(release))
	trigger := release.On["release"]
	var published struct {
		Types []string `yaml:"types"`
	}
	require.NoError(t, trigger.Decode(&published))
	require.Equal(t, []string{"published"}, published.Types)
}

func prConcurrencyEventNames(workflow prConcurrencyWorkflow) []string {
	names := make([]string, 0, len(workflow.On))
	for name := range workflow.On {
		names = append(names, name)
	}
	return names
}
