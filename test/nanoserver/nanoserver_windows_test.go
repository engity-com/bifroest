//go:build windows && nanoserver_integration

package nanoserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	bib "github.com/engity-com/bifroest/internal/build"
)

func TestPinnedNanoServerLocalEnvironment(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_NANOSERVER") != "1" {
		t.Skip("set BIFROEST_TEST_NANOSERVER=1 on a Windows-container Docker host")
	}
	isolation := os.Getenv("BIFROEST_TEST_NANOSERVER_ISOLATION")
	if isolation == "" {
		isolation = "hyperv"
	}
	if isolation != "hyperv" && isolation != "process" {
		t.Fatalf("unsupported Windows container isolation %q", isolation)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source checkout")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	dir := t.TempDir()
	run := func(t *testing.T, workdir, name string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Dir = workdir
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
		}
		return string(output)
	}
	if got := strings.TrimSpace(run(t, root, "docker", "info", "--format", "{{.OSType}}")); got != "windows" {
		t.Fatalf("Nano Server integration requires a Windows Docker daemon, got %q", got)
	}
	binaries, err := filepath.Glob(filepath.Join(root, "var", "dist", "*", "bifroest-windows-amd64-generic.exe"))
	if err != nil || len(binaries) != 1 {
		t.Fatalf("expected exactly one native Windows binary from mise run build:go:binary, got %v: %v", binaries, err)
	}
	binarySource, err := os.Open(binaries[0])
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Create(filepath.Join(dir, "bifroest.exe"))
	if err != nil {
		_ = binarySource.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(target, binarySource)
	if err := errors.Join(copyErr, target.Close(), binarySource.Close()); err != nil {
		t.Fatal(err)
	}
	run(t, root, "go", "build", "-o", filepath.Join(dir, "s4u-probe.exe"), "./test/manual/s4u-probe")
	run(t, root, "go", "test", "-c", "-tags=nanoserver_integration", "-o", filepath.Join(dir, "environment.test.exe"), "./pkg/environment")
	buildImage := func(base, kind string) string {
		t.Helper()
		dockerfile := fmt.Sprintf("FROM %s\nUSER ContainerAdministrator\nWORKDIR C:/smoke\nCOPY bifroest.exe C:/smoke/bifroest.exe\nCOPY environment.test.exe C:/smoke/environment.test.exe\nCOPY s4u-probe.exe C:/smoke/s4u-probe.exe\n", base)
		if kind == "servercore" {
			dockerfile += "RUN cmd /C \"echo bifroest-servercore-integration > C:/smoke/servercore-container.marker\"\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0600); err != nil {
			t.Fatal(err)
		}
		image := fmt.Sprintf("bifroest-%s-smoke:%d", kind, time.Now().UnixNano())
		run(t, root, "docker", "build", "--isolation="+isolation, "--tag", image, dir)
		t.Cleanup(func() {
			cmd := exec.Command("docker", "image", "rm", image)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("cannot remove temporary image %q: %v: %s", image, err, output)
			}
		})
		return image
	}
	dockerRun := func(t *testing.T, image string, extra []string, args ...string) string {
		t.Helper()
		container := fmt.Sprintf("bifroest-container-smoke-%d", time.Now().UnixNano())
		t.Cleanup(func() {
			cmd := exec.Command("docker", "container", "rm", "-f", container)
			if output, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(output), "No such container") {
				t.Logf("cannot remove temporary container %q: %v: %s", container, err, output)
			}
		})
		command := []string{"run", "--rm", "--name", container, "--isolation=" + isolation}
		command = append(command, extra...)
		command = append(command, image)
		command = append(command, args...)
		return run(t, root, "docker", command...)
	}
	nanoImage := buildImage(bib.DefaultWindowsContainerBaseImage(), "nanoserver")
	t.Run("nanoserver-bifroest-starts", func(t *testing.T) {
		result := dockerRun(t, nanoImage, []string{"--user", "ContainerUser"}, `C:\smoke\bifroest.exe`, "version")
		if strings.TrimSpace(result) == "" {
			t.Errorf("unexpected version output: %s", result)
		}
	})
	t.Run("nanoserver-dlls-and-conpty", func(t *testing.T) {
		result := dockerRun(t, nanoImage, []string{"--user", "ContainerUser", "--env", "BIFROEST_TEST_NANOSERVER_IN_CONTAINER=1"},
			`C:\smoke\environment.test.exe`, "-test.run=^(TestLocalNanoServerDLLExports|TestLocalConPTYRelayRoundTrip)$", "-test.v", "-test.timeout=90s")
		for _, test := range []string{"TestLocalNanoServerDLLExports", "TestLocalConPTYRelayRoundTrip"} {
			if !strings.Contains(result, "--- PASS: "+test+" ") {
				t.Errorf("required container test %s did not pass:\n%s", test, result)
			}
		}
	})
	t.Run("nanoserver-local-sam-lifecycle", func(t *testing.T) {
		result := dockerRun(t, nanoImage, []string{"--user", "ContainerAdministrator", "--env", "BIFROEST_TEST_NANO_SAM_IN_CONTAINER=1"},
			`C:\smoke\environment.test.exe`, "-test.run=^TestLocalNanoServerSAMLifecycle$", "-test.v", "-test.timeout=90s")
		if !strings.Contains(result, "--- PASS: TestLocalNanoServerSAMLifecycle ") {
			t.Errorf("required Nano Server SAM lifecycle test did not pass:\n%s", result)
		}
	})
	serverCoreImage := buildImage("mcr.microsoft.com/windows/servercore:ltsc2022@sha256:76cf422c98ca437b308374d0498280541fa42ac7061bb44015a6c8b70cf4db6a", "servercore")
	t.Run("servercore-fixture-apis", func(t *testing.T) {
		result := dockerRun(t, serverCoreImage, []string{"--user", "ContainerAdministrator", "--env", "BIFROEST_TEST_SERVERCORE_IN_CONTAINER=1"},
			`C:\smoke\environment.test.exe`, "-test.run=^TestLocalServerCoreAccountFixtureAPIs$", "-test.v")
		if !strings.Contains(result, "--- PASS: TestLocalServerCoreAccountFixtureAPIs ") {
			t.Errorf("required Server Core fixture API test did not pass:\n%s", result)
		}
	})
	t.Run("servercore-s4u-and-local-pty", func(t *testing.T) {
		dockerRun(t, serverCoreImage, []string{"--user", "ContainerAdministrator", "--env", "BIFROEST_TEST_LOCAL_SAM_IN_CONTAINER=1"},
			`C:\smoke\s4u-probe.exe`, "run-container-test", `C:\smoke\environment.test.exe`)
	})
}
