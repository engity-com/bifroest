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
			Needs any               `yaml:"needs"`
			Steps []map[string]any  `yaml:"steps"`
			Env   map[string]string `yaml:"env"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	job := workflow.Jobs["browser"]
	require.Equal(t, "0", job.Env["CGO_ENABLED"], "the plain browser runner does not provide native PAM headers")
	require.NotEqual(t, "0", workflow.Jobs["test-container"].Env["CGO_ENABLED"], "native PAM compilation stays in the prepared container test job")
	host := workflow.Jobs["test-host"]
	require.Equal(t, "-p=2", host.Env["GOFLAGS"])
	var hostCommands []string
	for _, step := range host.Steps {
		if command, ok := step["run"].(string); ok {
			hostCommands = append(hostCommands, command)
		}
	}
	hostJoined := strings.Join(hostCommands, "\n")
	require.Contains(t, hostJoined, "mise run test:go:native")
	var commands []string
	for _, step := range job.Steps {
		if command, ok := step["run"].(string); ok {
			commands = append(commands, command)
		}
	}
	joined := strings.Join(commands, "\n")
	for _, command := range []string{"mise -C web run install:web", "mise -C web run build:web", "mise run test:web:release"} {
		require.Contains(t, joined, command)
	}
	require.NotRegexp(t, `\brun test:web(\s|$)`, joined, "asset creation may only check the release inventory, not run the source suite")
	for _, command := range []string{"run test:go", "run lint:web", "install:web:browser"} {
		require.NotContains(t, joined, command, "asset production must not wait for test execution")
	}
	require.Less(t, strings.Index(joined, "run build:web"), strings.Index(joined, "run test:web:release"))
	for _, name := range []string{"test-static", "test-browser"} {
		test := workflow.Jobs[name]
		require.Equal(t, "browser", test.Needs)
		require.Equal(t, "0", test.Env["CGO_ENABLED"])
		downloads := 0
		for _, step := range test.Steps {
			if with, ok := step["with"].(map[string]any); ok && with["name"] == "browser-assets" {
				downloads++
				require.Equal(t, "pkg/webui/assets", with["path"], "tests and binaries must consume the same artifact")
			}
		}
		require.Equal(t, 1, downloads)
	}
	web := workflow.Jobs["test-web"]
	require.Empty(t, web.Needs, "source validation need not wait for release assets")
	var webCommands []string
	for _, step := range web.Steps {
		if command, ok := step["run"].(string); ok {
			webCommands = append(webCommands, command)
		}
	}
	for _, command := range []string{"run install:web", "run install:web:browser", "run lint:web", "run test:web"} {
		require.Contains(t, strings.Join(webCommands, "\n"), command)
	}
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
				require.Empty(t, with["path"])
				require.Equal(t, "${{ inputs.commit || inputs.ref }}", with["ref"])
			}
		}
	}
	filters, err := gos.ReadFile("../../.github/filters.yml")
	require.NoError(t, err)
	require.Contains(t, string(filters), `"web/**"`)
	tools, err := gos.ReadFile("../../mise.tools.yaml")
	require.NoError(t, err)
	catalog, err := parseDependencyToolCatalog(tools)
	require.NoError(t, err)
	require.Equal(t, "26.9.0", catalog.versions["node"].Value)
	attributes, err := gos.ReadFile("../../.gitattributes")
	require.NoError(t, err)
	for _, rule := range []string{"/.gitattributes text eol=lf", "/go.mod   text eol=lf", "/go.sum   text eol=lf", "/mise.toml text eol=lf", "/web/**   text=auto eol=lf"} {
		require.Contains(t, string(attributes), rule)
	}
}

func TestBrowserIntegrationHasSeparateBudgetWithoutExtendingCoreTests(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/workflows/build.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			Env   map[string]string `yaml:"env"`
			Steps []struct {
				Run string            `yaml:"run"`
				Env map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	job := workflow.Jobs["test-static"]
	for _, flag := range []string{"BIFROEST_TEST_BROWSER_UI", "BIFROEST_TEST_BROWSER_CLIENT"} {
		require.Empty(t, job.Env[flag])
	}
	core := -1
	for index, step := range job.Steps {
		if strings.Contains(step.Run, "mise run test:go:native") {
			core = index
			for _, flag := range []string{"BIFROEST_TEST_BROWSER_UI", "BIFROEST_TEST_BROWSER_CLIENT"} {
				require.Empty(t, step.Env[flag], "browser tests must not consume the core package timeout")
			}
		}
		require.NotContains(t, step.Run, "run test:go:browser")
	}
	require.NotEqual(t, -1, core)
	browser := workflow.Jobs["test-browser"]
	found := false
	for _, step := range browser.Steps {
		if strings.Contains(step.Run, "mise -C web run test:go:browser") {
			found = true
			require.Equal(t, `mise -C web run test:go:browser -- --shard "$SHARD"`, step.Run, "every shard must invoke its task directly")
		}
		require.NotContains(t, step.Run, "scripts/native-go-tests.ts", "shards must not repeat the full core suite")
	}
	require.True(t, found)

	raw, err = gos.ReadFile("../../mise.toml")
	require.NoError(t, err)
	_, rest, found := strings.Cut(string(raw), `[tasks."test:go:browser"]`)
	require.True(t, found)
	body, _, _ := strings.Cut(rest, "\n[tasks.")
	for _, value := range []string{`BIFROEST_TEST_BROWSER_UI = "1"`, `BIFROEST_TEST_BROWSER_CLIENT = "1"`, `dir = "web"`, "node scripts/browser-go-tests.ts"} {
		require.Contains(t, body, value)
	}
	require.NotContains(t, body, "-cover", "unused browser coverage must not trigger another instrumented build")
	_, rest, found = strings.Cut(string(raw), `[tasks."test:go"]`)
	require.True(t, found)
	body, _, _ = strings.Cut(rest, "\n[tasks.")
	require.NotContains(t, body, "-timeout=", "normal Go tests retain their default deadline")
}

func TestNanoServerBuildPreparesPinnedFrontendBeforeNativeBinary(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/workflows/nanoserver.yml")
	require.NoError(t, err)
	var workflow struct {
		Jobs map[string]struct {
			Steps []map[string]any `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &workflow))
	var commands []string
	for _, step := range workflow.Jobs["windows-local"].Steps {
		if command, ok := step["run"].(string); ok {
			commands = append(commands, command)
		}
	}
	joined := strings.Join(commands, "\n")
	for _, command := range []string{"mise -C web run install:web", "mise -C web run build:web", "mise run build:go:binary"} {
		require.Contains(t, joined, command)
	}
	require.NotContains(t, joined, "mise -C web install", "task tools own provisioning")
	require.Less(t, strings.Index(joined, "mise -C web run install:web"), strings.Index(joined, "mise -C web run build:web"))
	require.Less(t, strings.Index(joined, "mise -C web run build:web"), strings.Index(joined, "mise run build:go:binary"))
}
