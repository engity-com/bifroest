package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	gos "os"
	goexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

const testToolCatalog = "# Keep comments and precision.\ntool_version_node: \"22.0.0\"\ntool_version_python: \"3.14\" # Python series\ntool_version_go_licenses: \"2.0.1\"\n"

func testToolFiles() map[string][]byte {
	return map[string][]byte{
		dependencyToolsPath: []byte(testToolCatalog),
		dependencyMisePath:  []byte("[tool_alias]\ngo_licenses = \"go:github.com/google/go-licenses/v2\"\n[tasks.example]\nrun = \"must not execute\"\n"),
	}
}

func testToolResults() map[string]any {
	return map[string]any{
		"node":        map[string]any{"name": "node", "requested": "22.0.0", "bump": "26.13.1", "latest": "26.13.1"},
		"python":      map[string]any{"name": "python", "requested": "3.14", "bump": "3.15", "latest": "3.15.2"},
		"go_licenses": map[string]any{"name": "go_licenses", "requested": "2.0.1", "bump": nil, "latest": "2.0.1"},
	}
}

func TestParseDependencyToolCatalogRejectsInvalidEntries(t *testing.T) {
	for _, raw := range []string{
		"", "[]", "{}", "node: \"22.0.0\"", "tool_version_: \"1.0\"",
		"tool_version_node: 22", "tool_version_python: 3.14", "tool_version_node: null",
		"tool_version_node: [\"22.0.0\"]", "tool_version_node:\n  version: \"22.0.0\"",
		"tool_version_node: \"latest\"", "tool_version_node: \"^22\"", "tool_version_node: \"system\"",
		"tool_version_node: \"22.0.0\"\ntool_version_node: \"24.0.0\"",
		"tool_version_node: &version \"22.0.0\"\ntool_version_bun: *version",
		"tool_version_node: \"22.0.0\"\n---\ntool_version_bun: \"1.0.0\"",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := parseDependencyToolCatalog([]byte(raw))
			require.Error(t, err)
		})
	}
}

func TestApplyToolUpdatesUsesOnlyCatalogAndMiseBumps(t *testing.T) {
	files := testToolFiles()
	configuration := string(files[dependencyMisePath])
	var temporary string
	dependencies := &dependencies{miseCommand: func(_ context.Context, directory string, args ...string) ([]byte, error) {
		temporary = directory
		require.Equal(t, []string{"outdated", "--bump", "--json"}, args)
		raw, err := gos.ReadFile(filepath.Join(directory, "mise.toml"))
		require.NoError(t, err)
		var manifest map[string]any
		_, err = toml.Decode(string(raw), &manifest)
		require.NoError(t, err)
		require.Len(t, manifest, 2, "never copy tasks, environment, hooks, or settings into the temporary config")
		require.Equal(t, map[string]any{"go_licenses": "go:github.com/google/go-licenses/v2"}, manifest["tool_alias"])
		require.Equal(t, map[string]any{"node": "22.0.0", "python": "3.14", "go_licenses": "2.0.1"}, manifest["tools"])
		return json.Marshal(testToolResults())
	}}

	checks, err := dependencies.applyToolUpdates(t.Context(), files)

	require.NoError(t, err)
	require.Len(t, checks, 3)
	require.Equal(t, "go:github.com/google/go-licenses/v2", checks[0].source)
	require.False(t, checks[0].changed)
	require.True(t, checks[1].changed)
	require.True(t, checks[2].changed)
	require.Equal(t, strings.ReplaceAll(strings.ReplaceAll(testToolCatalog, `"22.0.0"`, `"26.13.1"`), `"3.14"`, `"3.15"`), string(files[dependencyToolsPath]))
	require.Equal(t, configuration, string(files[dependencyMisePath]))
	_, err = gos.Stat(temporary)
	require.ErrorIs(t, err, gos.ErrNotExist)
}

func TestApplyToolUpdatesNoOpRetainsExactBytes(t *testing.T) {
	files := testToolFiles()
	files[dependencyToolsPath] = []byte(strings.ReplaceAll(testToolCatalog, "\n", "\r\n"))
	previous := string(files[dependencyToolsPath])
	results := testToolResults()
	for _, value := range results {
		value.(map[string]any)["bump"] = nil
	}
	dependencies := &dependencies{miseCommand: func(context.Context, string, ...string) ([]byte, error) {
		return json.Marshal(results)
	}}
	checks, err := dependencies.applyToolUpdates(t.Context(), files)
	require.NoError(t, err)
	for _, check := range checks {
		require.False(t, check.changed)
	}
	require.Equal(t, previous, string(files[dependencyToolsPath]))
}

func TestApplyToolUpdatesRejectsPartialOrInvalidResultsAtomically(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(map[string]any)
		raw    string
		err    error
	}{
		{name: "missing", change: func(results map[string]any) { delete(results, "python") }},
		{name: "extra", change: func(results map[string]any) { results["other"] = results["node"] }},
		{name: "wrong-name", change: func(results map[string]any) { results["python"].(map[string]any)["name"] = "other" }},
		{name: "wrong-request", change: func(results map[string]any) { results["python"].(map[string]any)["requested"] = "3.13" }},
		{name: "empty-bump", change: func(results map[string]any) { results["python"].(map[string]any)["bump"] = "" }},
		{name: "invalid-bump", change: func(results map[string]any) { results["python"].(map[string]any)["bump"] = "{{ exec(command='bad') }}" }},
		{name: "empty-latest", change: func(results map[string]any) { results["python"].(map[string]any)["latest"] = "" }},
		{name: "invalid-json", raw: "not JSON"},
		{name: "null", raw: "null"},
		{name: "command-error", err: errors.New("metadata lookup failed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := testToolFiles()
			original := string(files[dependencyToolsPath])
			var temporary string
			dependencies := &dependencies{miseCommand: func(_ context.Context, directory string, _ ...string) ([]byte, error) {
				temporary = directory
				results := testToolResults()
				if tt.change != nil {
					tt.change(results)
				}
				if tt.raw != "" || tt.err != nil {
					return []byte(tt.raw), tt.err
				}
				return json.Marshal(results)
			}}
			_, err := dependencies.applyToolUpdates(t.Context(), files)
			require.Error(t, err)
			require.Equal(t, original, string(files[dependencyToolsPath]), "no partial catalog update")
			_, err = gos.Stat(temporary)
			require.ErrorIs(t, err, gos.ErrNotExist)
		})
	}
}

func TestToolResolutionFailureCannotPublishAnyDependencyUpdate(t *testing.T) {
	writes := 0
	client := newDependencyTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writes++
			t.Errorf("unexpected write: %s %s", request.Method, request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/repos/owner/repository":
			_, _ = response.Write([]byte(`{"default_branch":"main"}`))
		case request.URL.Path == "/repos/owner/repository/git/ref/heads/main":
			_, _ = response.Write([]byte(`{"object":{"sha":"base"}}`))
		case strings.HasPrefix(request.URL.Path, "/repos/owner/repository/contents/"):
			name := strings.TrimPrefix(request.URL.Path, "/repos/owner/repository/contents/")
			require.Equal(t, "base", request.URL.Query().Get("ref"))
			raw, err := gos.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
			require.NoError(t, err)
			_, _ = fmt.Fprintf(response, `{"type":"file","encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString(raw))
		default:
			t.Errorf("unexpected request: %s", request.URL.Path)
			http.NotFound(response, request)
		}
	})
	dependencies := newDependencies(newDependencyTestRepo(client).base)
	dependencies.miseCommand = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("tool metadata unavailable")
	}
	err := dependencies.updatePrInRepository(t.Context(), "dependency-bot[bot]")
	require.ErrorContains(t, err, "tool metadata unavailable")
	require.Zero(t, writes, "no blobs, tree, branch, PR updates or closures after a tool lookup failure")
}

// Opt in explicitly: these checks use real upstream version metadata, not
// tool downloads. The ordinary suite remains offline and deterministic.
func TestToolUpdatesWithNativeMiseWithoutInstallingTools(t *testing.T) {
	if gos.Getenv("BIFROEST_TEST_MISE_UPDATES") != "1" {
		t.Skip("set BIFROEST_TEST_MISE_UPDATES=1 for native MISE metadata integration")
	}
	_, err := goexec.LookPath("mise")
	require.NoError(t, err)
	for _, name := range []string{"MISE_NODE_VERSION", "MISE_ENV", "MISE_CONFIG_FILE"} {
		t.Setenv(name, "must-not-affect-the-isolated-check")
	}
	files := testToolFiles()
	files[dependencyToolsPath] = append(files[dependencyToolsPath], []byte("tool_version_go: \"1.27.4\"\ntool_version_docker_cli: \"29.7.2\"\n")...)
	files[dependencyMisePath] = []byte("[tool_alias]\ngo_licenses = \"go:github.com/google/go-licenses/v2\"\ndocker_cli = \"docker-cli\"\n")
	dependencies := &dependencies{miseCommand: func(ctx context.Context, directory string, args ...string) ([]byte, error) {
		raw, err := runDependencyMise(ctx, directory, args...)
		_, statErr := gos.Stat(filepath.Join(directory, "data", "installs"))
		require.ErrorIs(t, statErr, gos.ErrNotExist, "outdated must never install tools")
		return raw, err
	}}
	checks, err := dependencies.applyToolUpdates(t.Context(), files)
	require.NoError(t, err)
	require.Len(t, checks, 5, "include unchanged tools and aliased backends")
}
