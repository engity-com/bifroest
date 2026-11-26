package main

import (
	"crypto/sha256"
	"fmt"
	gos "os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type goCacheAction struct {
	Inputs map[string]struct {
		Required bool `yaml:"required"`
		Default  any  `yaml:"default"`
	} `yaml:"inputs"`
	Runs struct {
		Using string `yaml:"using"`
		Steps []struct {
			ID              string            `yaml:"id"`
			Uses            string            `yaml:"uses"`
			Shell           string            `yaml:"shell"`
			Run             string            `yaml:"run"`
			If              string            `yaml:"if"`
			ContinueOnError bool              `yaml:"continue-on-error"`
			Env             map[string]string `yaml:"env"`
			With            map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"runs"`
}

func readGoCacheAction(t *testing.T) goCacheAction {
	t.Helper()
	raw, err := gos.ReadFile("../../.github/actions/cache-go/action.yml")
	require.NoError(t, err)
	var action goCacheAction
	require.NoError(t, yaml.Unmarshal(raw, &action))
	return action
}

// These guards cover the composite action, not hosted cache-service execution.
func TestGoCacheActionUsesPinnedCachesAndCompatibleRollingBuildKeys(t *testing.T) {
	action := readGoCacheAction(t)
	require.Len(t, action.Inputs, 3)
	require.True(t, action.Inputs["scope"].Required)
	context, ok := action.Inputs["context"]
	require.True(t, ok)
	require.False(t, context.Required)
	require.Empty(t, context.Default)
	buildCache, ok := action.Inputs["build-cache"]
	require.True(t, ok)
	require.False(t, buildCache.Required)
	require.Equal(t, "false", buildCache.Default, "build caching must default to the string false, not a YAML boolean")
	require.Equal(t, "composite", action.Runs.Using)
	require.Len(t, action.Runs.Steps, 4)
	for _, step := range action.Runs.Steps {
		require.False(t, step.ContinueOnError)
	}
	detect := action.Runs.Steps[0]
	require.Empty(t, detect.If)
	require.Equal(t, "go", detect.ID)
	require.Equal(t, "bash", detect.Shell)
	require.Empty(t, detect.Uses)
	require.Equal(t, map[string]string{
		"CACHE_SCOPE": "${{ inputs.scope }}", "CACHE_CONTEXT": "${{ inputs.context }}",
	}, detect.Env)
	require.Contains(t, detect.Run, "mise exec -- go env GOCACHE GOMODCACHE GOVERSION GOOS GOARCH CGO_ENABLED")
	require.NotContains(t, detect.Run, "${{", "inputs must be passed as data, not interpolated into shell commands")
	modules, build := action.Runs.Steps[1], action.Runs.Steps[2]
	require.Empty(t, modules.If, "module caching remains enabled without the build-cache opt-in")
	require.Equal(t, "${{ inputs.build-cache == 'true' }}", build.If, "only an explicit true may restore and save build results")
	for _, step := range action.Runs.Steps[1:3] {
		require.Equal(t, "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9", step.Uses)
		require.Empty(t, step.Run)
	}
	require.Equal(t, "${{ steps.go.outputs.gomodcache }}", modules.With["path"])
	require.Equal(t, "${{ steps.go.outputs.gocache }}", build.With["path"], "never cache fixtures, credentials, sessions or external executables")
	modulePrefix := "${{ runner.os }}-go-"
	require.Equal(t, modulePrefix+"${{ hashFiles('**/go.sum') }}", modules.With["key"])
	require.Equal(t, modulePrefix+"\n", modules.With["restore-keys"])
	require.NotContains(t, modules.With["key"], "context-hash", "module downloads remain reusable across job scopes")
	buildPrefix := "go-build-v1-${{ runner.os }}-${{ runner.arch }}-${{ steps.go.outputs.goversion }}-${{ steps.go.outputs.goos }}-${{ steps.go.outputs.goarch }}-cgo${{ steps.go.outputs.cgo-enabled }}-${{ steps.go.outputs.context-hash }}-"
	dependencyPrefix := buildPrefix + "${{ hashFiles('**/go.sum') }}-"
	require.Equal(t, dependencyPrefix+"${{ github.sha }}", build.With["key"], "reruns and parallel callers must reuse the same immutable snapshot per commit")
	require.Equal(t, dependencyPrefix+"\n"+buildPrefix+"\n", build.With["restore-keys"], "fallbacks must not cross toolchain, platform, CGO or scope/context boundaries")
	restore := action.Runs.Steps[3]
	require.Equal(t, "${{ inputs.build-cache == 'restore-only' }}", restore.If)
	require.Equal(t, "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9", restore.Uses)
	require.Equal(t, build.With, restore.With, "readers must use the writer's exact cache identity and paths")
	require.Empty(t, restore.Run)
}

func TestGoCacheCompositeActionDoesNotUseYAMLAnchors(t *testing.T) {
	raw, err := gos.ReadFile("../../.github/actions/cache-go/action.yml")
	require.NoError(t, err)
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(raw, &root))
	var visit func(*yaml.Node)
	visit = func(node *yaml.Node) {
		require.Empty(t, node.Anchor, "GitHub supports anchors in workflows, not composite action manifests")
		require.NotEqual(t, yaml.AliasNode, node.Kind)
		for _, child := range node.Content {
			visit(child)
		}
	}
	visit(&root)
}

func runGoCacheDetection(t *testing.T, goEnv, scope, context, status string) (map[string]string, string, error) {
	t.Helper()
	return runGoCacheDetectionForSource(t, goEnv, scope, context, status, false)
}

func runGoCacheDetectionForSource(t *testing.T, goEnv, scope, context, status string, modern bool) (map[string]string, string, error) {
	t.Helper()
	bash, err := osexec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required to exercise the composite action's detection step")
	}
	directory := t.TempDir()
	if modern {
		require.NoError(t, gos.WriteFile(filepath.Join(directory, "mise.tools.yaml"), nil, 0o600))
	}
	output := filepath.Join(directory, "github.output")
	require.NoError(t, gos.WriteFile(output, nil, 0o600))
	// Stub only MISE/Go; run the actual action shell code and checksum utility.
	script := `mise() {
  if [ -f mise.tools.yaml ]; then
    [ "$*" = "run --quiet ci:go:env" ] || return 42
  else
    [ "$*" = "exec -- go env GOCACHE GOMODCACHE GOVERSION GOOS GOARCH CGO_ENABLED" ] || return 42
  fi
  printf '%s' "$GO_CACHE_TEST_ENV"
  return "$GO_CACHE_TEST_STATUS"
}
` + readGoCacheAction(t).Runs.Steps[0].Run
	// Like the Actions runner, use a file so Windows command-line quoting cannot alter Bash escapes.
	scriptPath := filepath.Join(directory, "cache-detection.sh")
	require.NoError(t, gos.WriteFile(scriptPath, []byte(script), 0o600))
	cmd := osexec.CommandContext(t.Context(), bash, "--noprofile", "--norc", "-e", "-o", "pipefail", filepath.ToSlash(scriptPath))
	cmd.Dir = directory
	cmd.Env = append(gos.Environ(),
		"GITHUB_OUTPUT="+filepath.ToSlash(output),
		"CACHE_SCOPE="+scope, "CACHE_CONTEXT="+context,
		"GO_CACHE_TEST_ENV="+goEnv, "GO_CACHE_TEST_STATUS="+status,
	)
	log, runErr := cmd.CombinedOutput()
	raw, err := gos.ReadFile(output)
	require.NoError(t, err)
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		require.True(t, ok)
		require.NotContains(t, values, key)
		values[key] = value
	}
	return values, string(log), runErr
}

func TestGoCacheActionUsesTaskGoAndNeverFallsBackAfterTaskFailure(t *testing.T) {
	goEnv := "/cache/build\n/cache/mod\ngo1.27.4\nlinux\namd64\n0\n"
	for _, status := range []string{"0", "23"} {
		legacy, legacyLog, legacyErr := runGoCacheDetectionForSource(t, goEnv, "test", "", status, false)
		modern, modernLog, modernErr := runGoCacheDetectionForSource(t, goEnv, "test", "", status, true)
		require.Equal(t, legacy, modern)
		if status == "0" {
			require.NoError(t, legacyErr, legacyLog)
			require.NoError(t, modernErr, modernLog)
			require.Equal(t, "go1.27.4", modern["goversion"])
		} else {
			require.Empty(t, modern, "failed task provisioning must not publish cache paths")
			for _, err := range []error{legacyErr, modernErr} {
				var exit *osexec.ExitError
				require.ErrorAs(t, err, &exit)
				require.Equal(t, 23, exit.ExitCode())
			}
		}
	}
}

func TestGoCacheActionDetectsPlatformPathsAndHashesScopeContextAsData(t *testing.T) {
	for _, tt := range []struct {
		name, cache, modules, goos, goarch, cgo, newline string
	}{
		{"linux-container", "/root/.cache/go-build", "/root/go/pkg/mod", "linux", "amd64", "1", "\n"},
		{"macos", "/Users/runner/Library/Caches/go-build", "/Users/runner/go/pkg/mod", "darwin", "arm64", "0", "\n"},
		{"windows", `C:\Users\Runner User\AppData\Local\go-build`, `D:\Go Modules\pkg\mod`, "windows", "amd64", "0", "\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", "/unrelated/cache-test-home")
			t.Setenv("USERPROFILE", `Z:\Unrelated Home`)
			goEnv := strings.Join([]string{tt.cache, tt.modules, "go1.27.4", tt.goos, tt.goarch, tt.cgo, ""}, tt.newline)
			scope, context := "test, $(exit 19)", "image@sha256:abc\nedition=enterprise"
			values, log, err := runGoCacheDetection(t, goEnv, scope, context, "0")
			require.NoError(t, err, log)
			identity := sha256.Sum256([]byte(scope + "\x00" + context + "\x00"))
			require.Equal(t, map[string]string{
				"gocache": strings.ReplaceAll(tt.cache, `\`, "/"), "gomodcache": strings.ReplaceAll(tt.modules, `\`, "/"),
				"goversion": "go1.27.4", "goos": tt.goos, "goarch": tt.goarch, "cgo-enabled": tt.cgo,
				"context-hash": fmt.Sprintf("%x", identity),
			}, values)
		})
	}
}

func TestGoCacheActionAcceptsEmptyContextAndSeparatesScopeContextPairs(t *testing.T) {
	goEnv := "/cache/build\n/cache/mod\ngo1.27.4\nlinux\namd64\n1\n"
	identities := map[string]bool{}
	for _, pair := range [][2]string{{"test", ""}, {"race", ""}, {"ab", "c"}, {"a", "bc"}, {"test", strings.Repeat("container-image", 128)}} {
		values, log, err := runGoCacheDetection(t, goEnv, pair[0], pair[1], "0")
		require.NoError(t, err, log)
		identity := values["context-hash"]
		require.Regexp(t, `^[a-f0-9]{64}$`, identity)
		require.False(t, identities[identity], "scope/context boundaries must remain distinct")
		identities[identity] = true
	}
}

func TestGoCacheActionPreservesEquivalentLegacyModuleCachePaths(t *testing.T) {
	for _, tt := range []struct {
		name, home, profile, modules, goos string
	}{
		{"Linux", "/home/runner", "", "/home/runner/go/pkg/mod", "linux"},
		{"macOS", "/Users/runner", "", "/Users/runner/go/pkg/mod", "darwin"},
		{"Windows", "/c/Users/Runner User", `C:\Users\Runner User`, `C:\Users\Runner User\go\pkg\mod`, "windows"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("RUNNER_OS", tt.name)
			t.Setenv("HOME", tt.home)
			t.Setenv("USERPROFILE", tt.profile)
			goEnv := strings.Join([]string{"/cache/build", tt.modules, "go1.27.4", tt.goos, "amd64", "0", ""}, "\n")
			values, log, err := runGoCacheDetection(t, goEnv, "test", "", "0")
			require.NoError(t, err, log)
			require.Equal(t, "~/go/pkg/mod", values["gomodcache"], "cache service versions include the literal path, not just the key")
		})
	}
}

func TestGoCacheActionRejectsMissingScopeDisabledCachesAndFailedGoEnv(t *testing.T) {
	goEnv := "/cache/build\n/cache/mod\ngo1.27.4\nlinux\namd64\n1\n"
	for _, tt := range []struct {
		name, env, scope, status string
	}{
		{"missing-scope", goEnv, "", "0"},
		{"disabled-cache", strings.Replace(goEnv, "/cache/build", "off", 1), "test", "0"},
		{"empty-module-cache", strings.Replace(goEnv, "/cache/mod", "", 1), "test", "0"},
		{"unexpected-lines", goEnv + "extra\n", "test", "0"},
		{"failed-go-env", goEnv, "test", "17"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			values, _, err := runGoCacheDetection(t, tt.env, tt.scope, "", tt.status)
			require.Error(t, err)
			require.Empty(t, values, "failed environment detection must not publish cache paths or keys")
		})
	}
}
