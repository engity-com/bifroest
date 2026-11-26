package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBrowserSuiteSelection(t *testing.T) {
	for _, tt := range []struct {
		name, timeout, workload string
	}{
		{"docker-browser", "15m", "TestOpenSSHDockerBrowserSharedWorkload"},
		{"kubernetes-browser", "30m", "TestOpenSSHKubernetesBrowserSharedWorkload"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			suite, err := selectSuite(tt.name)
			require.NoError(t, err)
			require.Equal(t, []string{"TestSharedBrowserNetworkArguments", "TestSharedBrowserNetworkIsolation", tt.workload}, suite.required)
			args := suite.arguments()
			require.Equal(t, []string{"test", "-json", "-count=1", "-tags=e2e", "-timeout=" + tt.timeout}, args[:5])
			require.Equal(t, "-run", args[5])
			require.Equal(t, "./test/e2e", args[7])
			selection, err := regexp.Compile(args[6])
			require.NoError(t, err)
			for _, test := range suite.required {
				require.True(t, selection.MatchString(test))
				require.False(t, selection.MatchString(test+"Unrelated"))
			}
			require.False(t, selection.MatchString("TestOpenSSHDockerEnvironment"))
		})
	}
	_, err := selectSuite("unknown")
	require.ErrorContains(t, err, "unknown browser suite")
}

func resultJSON(action, pkg, test string) string {
	raw, err := json.Marshal(map[string]string{"Action": action, "Package": pkg, "Test": test})
	if err != nil {
		panic(err)
	}
	return string(raw) + "\n"
}

func successfulResults(suite browserSuite) string {
	var result strings.Builder
	for _, test := range suite.required {
		result.WriteString(resultJSON("pass", e2ePackage, test))
	}
	result.WriteString(resultJSON("pass", e2ePackage, ""))
	return result.String()
}

func TestMandatoryResultsRejectMissingSkippedFailedAndMalformedExecution(t *testing.T) {
	suite, err := selectSuite("docker-browser")
	require.NoError(t, err)
	good := successfulResults(suite)
	for _, tt := range []struct {
		name, results, failure string
	}{
		{"success", good, ""},
		{"empty", "", "passed 0 times"},
		{"no-matching-tests", resultJSON("pass", e2ePackage, ""), "passed 0 times"},
		{"missing-workload", strings.ReplaceAll(good, resultJSON("pass", e2ePackage, suite.required[2]), ""), suite.required[2]},
		{"other-package", strings.ReplaceAll(good, e2ePackage, "unrelated/package"), "passed 0 times"},
		{"incomplete-package", strings.TrimSuffix(good, resultJSON("pass", e2ePackage, "")), "did not complete"},
		{"duplicate", good + resultJSON("pass", e2ePackage, suite.required[0]), "passed 2 times"},
		{"skipped-test", resultJSON("skip", e2ePackage, suite.required[2]) + good, "reported skip"},
		{"skipped-subtest", good + resultJSON("skip", e2ePackage, suite.required[2]+"/child"), "reported skip"},
		{"failed-test", good + resultJSON("fail", e2ePackage, suite.required[2]), "reported fail"},
		{"failed-package", good + resultJSON("fail", e2ePackage, ""), "reported fail"},
		{"build-failure", resultJSON("build-fail", e2ePackage, ""), "reported build-fail"},
		{"malformed", good + "{", "decode Go test JSON"},
		{"non-json", "not JSON\n" + good, "decode Go test JSON"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyResults(strings.NewReader(tt.results), suite.required)
			if tt.failure == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.failure)
			}
		})
	}
}

func TestRunnerRejectsInvalidArgumentsAndImplicitRuntime(t *testing.T) {
	for _, args := range [][]string{nil, {"--suite=unknown"}, {"--suite=docker-browser", "extra"}, {"--unknown"}} {
		require.Error(t, run(t.Context(), args, &bytes.Buffer{}, &bytes.Buffer{}))
	}
	for _, runtime := range []string{"", "auto", "../other", "unsupported"} {
		t.Setenv("BIFROEST_E2E_RUNTIME", runtime)
		require.ErrorContains(t, run(t.Context(), []string{"--suite=docker-browser"}, &bytes.Buffer{}, &bytes.Buffer{}), "explicitly select docker or podman")
	}
}

// A real child process tests exit handling and streaming without requiring a
// shell, Chromium, a container runtime or a second Go compiler invocation.
func TestRunnerProcessHelper(t *testing.T) {
	mode := os.Getenv("E2ERUNNER_PROCESS_HELPER")
	if mode == "" {
		return
	}
	if mode == "wait" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" || os.Getenv("BIFROEST_TEST_NODE") != "owned-node" {
		os.Exit(99)
	}
	suite, err := selectSuite("docker-browser")
	if err != nil {
		os.Exit(98)
	}
	output := successfulResults(suite)
	if mode == "skip" {
		output += resultJSON("skip", e2ePackage, suite.required[2]+"/child")
	}
	_, _ = fmt.Fprint(os.Stdout, output)
	_, _ = fmt.Fprint(os.Stderr, "owned diagnostics")
	if mode == "nonzero" {
		os.Exit(23)
	}
	os.Exit(0)
}

func TestRunnerStreamsAndRetainsSeparateLogsWithoutHidingFailures(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	suite, err := selectSuite("docker-browser")
	require.NoError(t, err)
	root := t.TempDir()
	for _, runtime := range []string{"docker", "podman"} {
		for _, mode := range []string{"success", "skip", "nonzero"} {
			t.Run(runtime+"/"+mode, func(t *testing.T) {
				t.Setenv("E2ERUNNER_PROCESS_HELPER", mode)
				t.Setenv("GOCOVERDIR", t.TempDir())
				factory := func(ctx context.Context, name string, args ...string) *exec.Cmd {
					require.Equal(t, "owned-go", name)
					require.Equal(t, suite.arguments(), args)
					return exec.CommandContext(ctx, executable, "-test.run=^TestRunnerProcessHelper$")
				}
				var stdout, stderr bytes.Buffer
				err := runSuite(t.Context(), suite, runtime, "owned-node", root, "owned-go", &stdout, &stderr, factory)
				switch mode {
				case "success":
					require.NoError(t, err)
				case "skip":
					require.ErrorContains(t, err, "reported skip")
				case "nonzero":
					var exit *exec.ExitError
					require.ErrorAs(t, err, &exit)
					require.Equal(t, 23, exit.ExitCode())
				}
				log, readErr := os.ReadFile(filepath.Join(root, "var", "e2e", runtime, "docker-browser.json"))
				require.NoError(t, readErr)
				require.Equal(t, stdout.String(), string(log))
				require.Contains(t, string(log), suite.required[2])
				require.Equal(t, "owned diagnostics", stderr.String())
			})
		}
	}
	for _, runtime := range []string{"docker", "podman"} {
		_, err := os.Stat(filepath.Join(root, "var", "e2e", runtime, "docker-browser.json"))
		require.NoError(t, err)
	}
}

func TestRunnerCancellationIsFailure(t *testing.T) {
	t.Setenv("E2ERUNNER_PROCESS_HELPER", "wait")
	t.Setenv("GOCOVERDIR", t.TempDir())
	executable, err := os.Executable()
	require.NoError(t, err)
	suite, err := selectSuite("docker-browser")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	factory := func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, executable, "-test.run=^TestRunnerProcessHelper$")
	}
	err = runSuite(ctx, suite, "docker", "owned-node", t.TempDir(), "owned-go", &bytes.Buffer{}, &bytes.Buffer{}, factory)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
