package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthorizationE2EWarmBuildPreservesRuntimeBudgetAndFreshFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../mise.toml")
	require.NoError(t, err)
	section := func(name string) string {
		_, rest, found := strings.Cut(string(raw), "[tasks.\""+name+"\"]")
		require.True(t, found, "required MISE task %s", name)
		body, _, _ := strings.Cut(rest, "\n[tasks.")
		return body
	}
	test := section("test:e2e:authorization")
	require.Contains(t, test, `"build:e2e:authorization"`)
	require.Contains(t, test, "-count=1 -tags=e2e -timeout=5m")
	require.Contains(t, test, "^Test(HtpasswdAuthorization|OIDC.*|SimpleRememberMe)$")
	build := section("build:e2e:authorization")
	for _, value := range []string{`CGO_ENABLED = "0"`, "-tags local_build,local_kind -trimpath", "-tags e2e -trimpath", "./cmd/bifroest", "./test/e2e/helper"} {
		require.Contains(t, build, value)
	}
	harness, err := os.ReadFile("../../test/e2e/harness_test.go")
	require.NoError(t, err)
	require.NotContains(t, string(harness), "authorization-build-cache", "warm outputs are never test inputs")
	require.Contains(t, string(harness), `bifroestVersion: "e2e-" + unique`)
	require.Contains(t, string(harness), `"-s -w -X main.version=" + f.bifroestVersion`)
	require.Contains(t, string(harness), `result := runCommand(ctx, f.repoRoot, build.environment, f.goTool, args...)`)
}

func TestDarwinE2EKeepsNativeIntegrationsAndFixtureRegressions(t *testing.T) {
	raw, err := os.ReadFile("../../mise.toml")
	require.NoError(t, err)
	_, task, found := strings.Cut(string(raw), "[tasks.\"test:e2e:darwin\"]")
	require.True(t, found)
	task, _, _ = strings.Cut(task, "\n[tasks.")
	require.Contains(t, task, "-count=1 -tags=e2e -timeout=30m")
	match := regexp.MustCompile(`-run '([^']+)'`).FindStringSubmatch(task)
	require.Len(t, match, 2)
	selection, err := regexp.Compile(match[1])
	require.NoError(t, err)
	for _, name := range []string{
		"TestOpenSSHLocalNative", "TestDarwinLocalAccountLifecycle", "TestDarwinLaunchDaemon",
		"TestFixtureBinarySelection", "TestFixtureBuildFailure", "TestFixtureRejectsUnknownBuildMode",
	} {
		require.True(t, selection.MatchString(name), "Darwin task must execute %s", name)
	}
	require.False(t, selection.MatchString("TestOpenSSHDockerEnvironment"))
}
