package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEnvironmentIsAllowlistedAndBuildCannotCrossCompile(t *testing.T) {
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN", "MISE_GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "AWS_SECRET_ACCESS_KEY", "UNRELATED_PRIVATE_FACT", "GOFLAGS", "GOCOVERDIR"} {
		t.Setenv(key, "not-a-test-input")
	}
	t.Setenv("GOOS", "foreign-os")
	t.Setenv("GOARCH", "foreign-arch")
	t.Setenv("CGO_ENABLED", "0")
	for _, build := range []bool{false, true} {
		env := strings.Join(processEnvironment(build), "\n")
		require.NotContains(t, env, "not-a-test-input")
		require.NotContains(t, env, "foreign-")
		if build {
			require.Contains(t, env, "GOOS="+runtime.GOOS)
			require.Contains(t, env, "GOARCH="+runtime.GOARCH)
			require.Contains(t, env, "GOTOOLCHAIN=local")
			require.Contains(t, env, "CGO_ENABLED=0")
		} else {
			require.NotContains(t, env, "CGO_ENABLED")
		}
	}
}

func TestFreshOutputAndExclusiveFileProtection(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	root := t.TempDir()
	path := filepath.Join(root, "sentinel.txt")
	require.NoError(t, createFile(path, []byte("original")))
	require.Error(t, createFile(path, []byte("replacement")))
	require.ErrorContains(t, run(t.Context(), root), "output must be a new directory")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original", string(raw))
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestBuildFailureStillProducesLogsAndFailureManifest(t *testing.T) {
	t.Chdir(filepath.Join("..", ".."))
	t.Setenv("PATH", t.TempDir()) // Deliberately missing compiler, not a hidden skip.
	root := filepath.Join(t.TempDir(), "new-output")
	require.ErrorContains(t, run(t.Context(), root), "native CLI build failed")
	data, err := os.ReadFile(filepath.Join(root, "reports", "manifest.json"))
	require.NoError(t, err)
	var record manifest
	require.NoError(t, json.Unmarshal(data, &record))
	require.False(t, record.Passed)
	require.Equal(t, -1, record.Build.ExitCode)
	require.NotEmpty(t, record.Build.Error)
	require.Empty(t, record.Cases)
	for _, name := range []string{"build.stdout.txt", "build.stderr.txt"} {
		_, err := os.Stat(filepath.Join(root, "reports", name))
		require.NoError(t, err)
	}
}

// The subprocess runs the test executable itself; it does not need a shell or
// platform-specific commands to provide real process exit/logging behavior.
func TestPolicyCIProcessHelper(t *testing.T) {
	if os.Getenv("POLICYCI_PROCESS_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "wait" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	code, err := strconv.Atoi(mode)
	if err != nil {
		os.Exit(99)
	}
	fmt.Fprint(os.Stdout, "helper stdout")
	fmt.Fprint(os.Stderr, "helper stderr")
	os.Exit(code)
}

func TestProcessPreservesExpectedExitCodesAndLogs(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	for _, code := range []int{0, 1, 2} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			folder := t.TempDir()
			env := processHelperEnvironment(t)
			result, err := runProcess(t.Context(), folder, "cli", executable, []string{"-test.run=^TestPolicyCIProcessHelper$", "--", strconv.Itoa(code)}, env)
			require.NoError(t, err)
			require.Equal(t, code, result.ExitCode)
			for _, stream := range []string{"stdout", "stderr"} {
				data, err := os.ReadFile(filepath.Join(folder, "cli."+stream+".txt"))
				require.NoError(t, err)
				require.Equal(t, "helper "+stream, string(data))
			}
			_, err = runProcess(t.Context(), folder, "cli", executable, nil, env)
			require.Error(t, err, "existing logs must not be replaced")
		})
	}
}

func TestProcessCancellationCannotMasqueradeAsExpectedExit(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	env := processHelperEnvironment(t)
	_, err = runProcess(ctx, t.TempDir(), "cli", executable, []string{"-test.run=^TestPolicyCIProcessHelper$", "--", "wait"}, env)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func processHelperEnvironment(t *testing.T) []string {
	t.Helper()
	// The helper reexecutes an optionally coverage-instrumented test binary.
	// Use a test-owned output directory, never caller-supplied environment or
	// filtered stderr: exact child output remains part of the assertion.
	return append(processEnvironment(false), "POLICYCI_PROCESS_HELPER=1", "GOCOVERDIR="+t.TempDir())
}
