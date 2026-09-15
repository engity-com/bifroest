//go:build e2e && linux

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProbeRuntimeRetriesPodmanOnce(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "probe.log")
	podman := writeRuntimeStub(t, "podman", `
printf '%s\n' "$*" >> "$PROBE_LOG"
if [ ! -e "$PROBE_STATE" ]; then
    : > "$PROBE_STATE"
    sleep 10
fi
`)
	t.Setenv("PROBE_LOG", logPath)
	t.Setenv("PROBE_STATE", filepath.Join(t.TempDir(), "probe.state"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := probeRuntime(ctx, podman)

	if result.err != nil {
		t.Fatalf("probe Podman: %v\nstderr:\n%s", result.err, result.stderr)
	}
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("probe attempts: got %d, want 2", len(lines))
	}
	for _, line := range lines {
		if line != "ps --all --quiet" {
			t.Fatalf("probe arguments: got %q, want %q", line, "ps --all --quiet")
		}
	}
}

func TestSelectRuntimeReportsExplicitProbeFailure(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "probe.log")
	writeRuntimeStubAt(t, filepath.Join(dir, "podman"), `
printf '%s\n' "$*" >> "$PROBE_LOG"
printf 'podman socket unavailable\n' >&2
exit 23
`)
	t.Setenv("PATH", dir)
	t.Setenv("PROBE_LOG", logPath)
	t.Setenv("BIFROEST_E2E_RUNTIME", "podman")

	actual, err := selectRuntime()

	if actual != "" {
		t.Fatalf("selected runtime: got %q, want none", actual)
	}
	if err == nil {
		t.Fatal("expected explicit Podman probe to fail")
	}
	for _, diagnostic := range []string{"exit status 23", "podman socket unavailable"} {
		if !strings.Contains(err.Error(), diagnostic) {
			t.Fatalf("probe error %q does not contain %q", err, diagnostic)
		}
	}
	content, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("probe attempts: got %d, want 2", len(lines))
	}
}

func TestRunCommandKillsProcessGroupOnTimeout(t *testing.T) {
	if role, pidPath, ok := processGroupHelperArgs(); ok {
		runProcessGroupHelper(role, pidPath)
		return
	}

	pidPath := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := runCommand(ctx, "", nil, os.Args[0], "-test.run=^TestRunCommandKillsProcessGroupOnTimeout$", "--", "parent", pidPath)

	if !errors.Is(result.err, context.DeadlineExceeded) {
		t.Fatalf("runCommand error: got %v, want context deadline exceeded", result.err)
	}
	if !strings.Contains(result.stderr, "child ready") {
		t.Fatalf("runCommand stderr: got %q, want child readiness diagnostic", result.stderr)
	}
	content, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(content))
	if err != nil {
		t.Fatalf("parse child PID %q: %v", content, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	deadline := time.Now().Add(2 * time.Second)
	for processRunning(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processRunning(pid) {
		t.Fatalf("child process %d survived command timeout", pid)
	}
}

func TestRunCommandKillsProcessGroupAfterLeaderExits(t *testing.T) {
	if role, pidPath, ok := processGroupHelperArgs(); ok {
		runProcessGroupHelper(role, pidPath)
		return
	}

	pidPath := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := runCommand(ctx, "", nil, os.Args[0], "-test.run=^TestRunCommandKillsProcessGroupAfterLeaderExits$", "--", "detached-parent", pidPath)

	if result.err != nil {
		t.Fatalf("runCommand error: %v", result.err)
	}
	content, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(content))
	if err != nil {
		t.Fatalf("parse child PID %q: %v", content, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	requireProcessStops(t, pid)
}

func TestRunCommandKillsProcessGroupAfterLeaderFails(t *testing.T) {
	if role, pidPath, ok := processGroupHelperArgs(); ok {
		runProcessGroupHelper(role, pidPath)
		return
	}

	pidPath := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := runCommand(ctx, "", nil, os.Args[0], "-test.run=^TestRunCommandKillsProcessGroupAfterLeaderFails$", "--", "detached-parent-error", pidPath)

	var exitErr *exec.ExitError
	if !errors.As(result.err, &exitErr) || exitErr.ExitCode() != 23 {
		t.Fatalf("runCommand error: got %v, want exit status 23", result.err)
	}
	content, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(content))
	if err != nil {
		t.Fatalf("parse child PID %q: %v", content, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	requireProcessStops(t, pid)
}

func writeRuntimeStub(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	writeRuntimeStubAt(t, path, body)
	return path
}

func writeRuntimeStubAt(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
}

func processGroupHelperArgs() (string, string, bool) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "--" {
		return "", "", false
	}
	return os.Args[len(os.Args)-2], os.Args[len(os.Args)-1], true
}

func runProcessGroupHelper(role, pidPath string) {
	switch role {
	case "parent", "detached-parent", "detached-parent-error":
		cmd := exec.Command(os.Args[0], "-test.run=^TestRunCommandKillsProcessGroupOnTimeout$", "--", "child", pidPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "start child: %v\n", err)
			os.Exit(2)
		}
		for {
			if _, err := os.Stat(pidPath); err == nil {
				fmt.Fprintln(os.Stderr, "child ready")
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if role == "detached-parent" {
			return
		}
		if role == "detached-parent-error" {
			os.Exit(23)
		}
		_ = cmd.Wait()
	case "child":
		if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write child PID: %v\n", err)
			os.Exit(2)
		}
		for {
			time.Sleep(time.Hour)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown helper role %q\n", role)
		os.Exit(2)
	}
}

func requireProcessStops(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for processRunning(pid) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if processRunning(pid) {
		t.Fatalf("child process %d survived command cleanup", pid)
	}
}

func processRunning(pid int) bool {
	content, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	commandEnd := strings.LastIndex(string(content), ") ")
	return commandEnd < 0 || len(content) <= commandEnd+2 || content[commandEnd+2] != 'Z'
}
