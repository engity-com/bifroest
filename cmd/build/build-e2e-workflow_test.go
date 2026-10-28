package main

import (
	"os"
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
