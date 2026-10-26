package main

import (
	gos "os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// These are configuration guards, not a claim that hosted Actions or native
// Windows/macOS release signing ran on this local Linux test host.
func TestBrowserReleaseWorkflowBuildsOnceBeforeAllBinaryJobs(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/workflows/build.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			Needs any              `yaml:"needs"`
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	job := workflow.Jobs["browser"]
	var commands []string
	for _, step := range job.Steps {
		if command, ok := step["run"].(string); ok {
			commands = append(commands, command)
		}
	}
	joined := strings.Join(commands, "\n")
	for _, command := range []string{"mise -C web install", "mise -C web run install:web", "mise -C web run lint:web", "mise -C web run build:web", "bun run test:release", "mise -C web run test:web", "mise -C web run test:go"} {
		require.Contains(t, joined, command)
	}
	require.Less(t, strings.Index(joined, "run build:web"), strings.Index(joined, "bun run test:release"))
	for _, name := range []string{"binary-host", "binary-container"} {
		binary := workflow.Jobs[name]
		require.Equal(t, "browser", binary.Needs)
		download, compile := -1, -1
		for index, step := range binary.Steps {
			if with, ok := step["with"].(map[string]any); ok && with["name"] == "browser-assets" {
				download = index
				require.Equal(t, "pkg/webui/assets", with["path"])
			}
			if command, ok := step["run"].(string); ok && strings.Contains(command, "run build:go:binary") {
				compile = index
			}
		}
		require.NotEqual(t, -1, download)
		require.Greater(t, compile, download)
	}
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if uses, ok := step["uses"].(string); ok && strings.HasPrefix(uses, "actions/checkout@") {
				with := step["with"].(map[string]any)
				require.Equal(t, "${{ inputs.commit || inputs.ref }}", with["ref"])
			}
		}
	}
	filters, err := gos.ReadFile("../../.github/filters.yml")
	require.NoError(t, err)
	require.Contains(t, string(filters), `"web/**"`)
	tools, err := gos.ReadFile("../../web/.tool-versions")
	require.NoError(t, err)
	require.Contains(t, string(tools), "nodejs 26.9.0")
	attributes, err := gos.ReadFile("../../.gitattributes")
	require.NoError(t, err)
	for _, rule := range []string{"/go.mod   text eol=lf", "/go.sum   text eol=lf", "/web/**   text=auto eol=lf"} {
		require.Contains(t, string(attributes), rule)
	}
}
