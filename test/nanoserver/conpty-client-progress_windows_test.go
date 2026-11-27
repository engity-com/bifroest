//go:build windows && nanoserver_integration && conpty_probe

package nanoserver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Fixed independent cold-container cases, not retries. Observation is compared
// off/on in the same executable; neither configuration changes native calls,
// 20-second roundtrip deadlines, SID/geometry/output checks or failure results.
func TestConPTYClientProgressProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 16*time.Minute)
	defer cancel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate diagnostic checkout")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	work := t.TempDir()
	logs := filepath.Join(root, "var", "e2e")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(name string, args ...string) string {
		t.Helper()
		command := exec.CommandContext(ctx, name, args...)
		command.Dir = root
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
		}
		return string(output)
	}
	images, err := windowsContainerImagesFor(os.Getenv("BIFROEST_TEST_NANOSERVER_VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if output := strings.TrimSpace(run("docker", "info", "--format", "{{.OSType}}")); output != "windows" {
		t.Fatalf("probe requires Windows containers, got %q", output)
	}
	run("go", "test", "-c", "-tags=nanoserver_integration", "-o", filepath.Join(work, "environment.test.exe"), "./pkg/environment")
	dockerfile := fmt.Sprintf("FROM %s\nUSER ContainerAdministrator\nWORKDIR C:/probe\nCOPY environment.test.exe C:/probe/\n", images.nano)
	if err := os.WriteFile(filepath.Join(work, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatal(err)
	}
	image := fmt.Sprintf("bifroest-conpty-client-probe:%d", time.Now().UnixNano())
	cleanup := func(t *testing.T, args ...string) {
		t.Helper()
		cleanupCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		output, err := exec.CommandContext(cleanupCtx, "docker", args...).CombinedOutput()
		if err != nil && !strings.Contains(string(output), "No such container") {
			t.Errorf("probe cleanup docker %s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	t.Cleanup(func() { cleanup(t, "image", "rm", image) })
	run("docker", "build", "--isolation=process", "--tag", image, work)
	const originalSmoke = "^(TestLocalNanoServerDLLExports|TestLocalConPTYRelayRoundTrip|TestLocalConPTYOutputReadKeepsEmptyMessagesDistinctFromEOF|TestLocalConPTYOutputPipeKeepsEmptyWritesAndBinaryOutput|TestLocalConPTYClientProgressEventsAreIndependentOfConsoleOutput|TestLocalConPTYProcessSnapshotObservesWithoutWaiting)$"
	for index, observed := range []bool{false, true, true, false, false, true, true, false} {
		t.Run(fmt.Sprintf("case=%d/observed=%t", index, observed), func(t *testing.T) {
			container := fmt.Sprintf("bifroest-conpty-client-probe-%d", time.Now().UnixNano())
			t.Cleanup(func() { cleanup(t, "container", "rm", "-f", container) })
			enabled := "0"
			if observed {
				enabled = "1"
			}
			command := exec.CommandContext(ctx, "docker", "run", "--rm", "--name", container,
				"--isolation=process", "--user", "ContainerUser",
				"--env", "BIFROEST_TEST_NANOSERVER_IN_CONTAINER=1",
				"--env", "BIFROEST_TEST_CONPTY_CLIENT_PROGRESS="+enabled,
				image, `C:\probe\environment.test.exe`, "-test.run="+originalSmoke, "-test.v", "-test.timeout=90s")
			command.Dir = root
			started := time.Now()
			output, err := command.CombinedOutput()
			filename := filepath.Join(logs, fmt.Sprintf("conpty-client-probe-%d-observed-%t.log", index, observed))
			if writeErr := os.WriteFile(filename, output, 0o600); writeErr != nil {
				t.Error(writeErr)
			}
			t.Logf("observed=%t elapsed=%s error=%v\n%s", observed, time.Since(started), err, output)
			if err != nil {
				t.Errorf("original ConPTY smoke test failed: %v", err)
			}
			for _, required := range []string{
				"TestLocalConPTYRelayRoundTrip",
				"TestLocalConPTYClientProgressEventsAreIndependentOfConsoleOutput",
				"TestLocalConPTYProcessSnapshotObservesWithoutWaiting",
				"TestLocalNanoServerDLLExports",
				"TestLocalConPTYOutputReadKeepsEmptyMessagesDistinctFromEOF",
				"TestLocalConPTYOutputPipeKeepsEmptyWritesAndBinaryOutput",
			} {
				if !strings.Contains(string(output), "--- PASS: "+required+" ") {
					t.Errorf("required original/native test %s did not pass", required)
				}
			}
		})
	}
}
