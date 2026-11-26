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

// Diagnostic only: no production source is edited. The observed executable uses
// Go's build overlay to add stderr milestones around the existing native calls.
// Instrumentation can perturb timing; the baseline executable is unmodified.
func TestConPTYColdStartProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 14*time.Minute)
	defer cancel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate diagnostic checkout")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	work := t.TempDir()
	runnerTemp := os.Getenv("RUNNER_TEMP")
	if runnerTemp == "" || strings.EqualFold(filepath.VolumeName(os.TempDir()), filepath.VolumeName(runnerTemp)) {
		t.Fatalf("probe requires distinct default and runner temp volumes: default=%q runner=%q", os.TempDir(), runnerTemp)
	}
	t.Logf("host default temp=%q runner temp=%q", os.TempDir(), runnerTemp)
	logs := filepath.Join(root, "var", "e2e")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, name string, args ...string) string {
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
	if output := strings.TrimSpace(run(t, "docker", "info", "--format", "{{.OSType}}")); output != "windows" {
		t.Fatalf("probe requires Windows containers, got %q", output)
	}
	overlay := writeConPTYProbeOverlay(t, root, work)
	for _, variant := range []string{"baseline", "observed"} {
		args := []string{"test", "-c", "-tags=nanoserver_integration", "-o", filepath.Join(work, variant+".exe")}
		if variant == "observed" {
			args = append(args, "-overlay", overlay)
		}
		run(t, "go", append(args, "./pkg/environment")...)
	}
	dockerfile := fmt.Sprintf("FROM %s\nUSER ContainerAdministrator\nWORKDIR C:/probe\nCOPY baseline.exe observed.exe C:/probe/\n", images.nano)
	if err := os.WriteFile(filepath.Join(work, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		t.Fatal(err)
	}
	image := fmt.Sprintf("bifroest-conpty-probe:%d", time.Now().UnixNano())
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
	run(t, "docker", "build", "--isolation=process", "--tag", image, work)
	// Fixed baseline/observed phases, each with a fresh-container A-B-B-A temp
	// comparison. Every failure is retained. These are not attempts until green.
	for _, variant := range []string{"baseline", "observed"} {
		for index, location := range []string{"default", "runner-temp", "runner-temp", "default"} {
			t.Run(fmt.Sprintf("%s/%d-%s", variant, index, location), func(t *testing.T) {
				container := fmt.Sprintf("bifroest-conpty-probe-%d", time.Now().UnixNano())
				args := []string{"run", "--rm", "--name", container, "--isolation=process", "--user", "ContainerUser",
					"--env", "BIFROEST_TEST_NANOSERVER_IN_CONTAINER=1"}
				if location == "runner-temp" {
					storage, err := os.MkdirTemp(runnerTemp, "conpty-probe-")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := os.RemoveAll(storage); err != nil {
							t.Error(err)
						}
					})
					// Only this disposable test mount is writable by container users.
					// The production DLL still receives its protected private DACL.
					run(t, "icacls", storage, "/grant", "*S-1-5-32-545:(OI)(CI)M")
					t.Logf("host temp mount=%s", storage)
					args = append(args, "--mount", "type=bind,source="+storage+`,target=C:\probe-temp`,
						"--env", `TMP=C:\probe-temp`, "--env", `TEMP=C:\probe-temp`)
				}
				args = append(args, image, `C:\probe\`+variant+".exe",
					"-test.run=^TestLocalConPTYRelayRoundTrip$", "-test.v", "-test.timeout=90s")
				t.Cleanup(func() { cleanup(t, "container", "rm", "-f", container) })
				command := exec.CommandContext(ctx, "docker", args...)
				command.Dir = root
				started := time.Now()
				output, err := command.CombinedOutput()
				filename := filepath.Join(logs, fmt.Sprintf("conpty-probe-%s-%d-%s.log", variant, index, location))
				if writeErr := os.WriteFile(filename, output, 0o600); writeErr != nil {
					t.Error(writeErr)
				}
				t.Logf("variant=%s location=%s elapsed=%s error=%v\n%s", variant, location, time.Since(started), err, output)
				if err != nil {
					t.Errorf("original ConPTY smoke test failed: %v", err)
				}
				if !strings.Contains(string(output), "--- PASS: TestLocalConPTYRelayRoundTrip ") {
					t.Error("required original ConPTY smoke test did not pass")
				}
			})
		}
	}
}
