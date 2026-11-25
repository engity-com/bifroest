//go:build e2e

package e2e_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestFixtureBinarySelection(t *testing.T) {
	publicKeys := make(map[string]bool)
	for _, mode := range []fixtureBuildMode{fixtureBuildNative, fixtureBuildAll} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			f, logPath := fixtureWithBuildStub(t)
			keygen, err := exec.LookPath("ssh-keygen")
			if err != nil {
				t.Fatal(err)
			}
			f.tools = map[string]string{"ssh-keygen": keygen}
			f.clientKey = filepath.Join(f.tempDir, "client_ed25519")
			f.wrongKey = filepath.Join(f.tempDir, "wrong_ed25519")
			f.agentKey = filepath.Join(f.tempDir, "agent_ed25519")
			f.hostKey = filepath.Join(f.tempDir, "host_ed25519")
			if err := f.prepareCommon(mode); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{f.clientKey, f.wrongKey, f.agentKey, f.hostKey} {
				info, err := os.Stat(key)
				if err != nil {
					t.Fatal(err)
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if info.Mode().Perm() != 0600 || !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() {
					t.Fatalf("private key %s has incorrect mode or ownership: %+v", key, info)
				}
				publicKey, err := os.ReadFile(key + ".pub")
				if err != nil {
					t.Fatal(err)
				}
				fields := strings.Fields(string(publicKey))
				if len(fields) < 2 || fields[0] != "ssh-ed25519" || publicKeys[fields[1]] {
					t.Fatalf("expected fresh Ed25519 key: %s", publicKey)
				}
				publicKeys[fields[1]] = true
			}

			outputs := []string{f.bifroest, f.helper, f.targetBifroest, f.targetHelper}
			packages := []string{"./cmd/bifroest", "./test/e2e/helper", "./cmd/bifroest", "./test/e2e/helper"}
			calls := readFixtureBuildCalls(t, logPath)
			wantCount := 4
			if mode == fixtureBuildNative {
				wantCount = 1
			}
			if len(calls) != wantCount {
				t.Fatalf("build count = %d, want %d: %v", len(calls), wantCount, calls)
			}
			for i, call := range calls {
				goos, goarch := runtime.GOOS, runtime.GOARCH
				if i >= 2 {
					goos, goarch = f.targetGOOS, f.targetGOARCH
				}
				tags, ldflags := "local_build,local_kind", "-s -w -X main.version="+f.bifroestVersion
				if i%2 == 1 {
					tags, ldflags = "e2e", "-s -w"
				}
				want := []string{"0", goos, goarch, os.Getenv("GOCACHE"), "build", "-tags", tags, "-trimpath", "-ldflags=" + ldflags, "-o", outputs[i], packages[i]}
				if !reflect.DeepEqual(call, want) {
					t.Fatalf("build %d = %q, want %q", i, call, want)
				}
			}
			for i, output := range outputs {
				_, err := os.Stat(output)
				if i < wantCount && err != nil {
					t.Fatalf("missing selected binary %s: %v", output, err)
				}
				if i >= wantCount && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unneeded binary %s was built: %v", output, err)
				}
			}
		})
	}
}

func TestFixtureBuildFailure(t *testing.T) {
	for _, mode := range []fixtureBuildMode{fixtureBuildNative, fixtureBuildAll} {
		outputs := []string{"bifroest", "e2e-helper", "bifroest-target", "e2e-helper-target"}
		if mode == fixtureBuildNative {
			outputs = outputs[:1]
		}
		for i, output := range outputs {
			t.Run(fmt.Sprintf("%d/%s", mode, output), func(t *testing.T) {
				f, logPath := fixtureWithBuildStub(t)
				t.Setenv("FIXTURE_BUILD_FAIL", output)
				err := f.prepareBinaries(mode)
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 || !strings.Contains(err.Error(), "fixture compiler failed") {
					t.Fatalf("build failure not preserved: %v", err)
				}
				if calls := readFixtureBuildCalls(t, logPath); len(calls) != i+1 {
					t.Fatalf("build did not stop at failure: %v", calls)
				}
			})
		}
	}
}

func TestFixtureRejectsUnknownBuildMode(t *testing.T) {
	f, logPath := fixtureWithBuildStub(t)
	if err := f.prepareBinaries(fixtureBuildMode(255)); err == nil {
		t.Fatal("unknown build mode accepted")
	}
	if _, err := os.Stat(logPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown build mode started compiler: %v", err)
	}
}

func fixtureWithBuildStub(t *testing.T) (*fixture, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "build.log")
	goTool := filepath.Join(dir, "go-stub")
	const script = `#!/bin/sh
set -eu
printf '%s\t' "$CGO_ENABLED" "$GOOS" "$GOARCH" "$GOCACHE" "$@" >> "$FIXTURE_BUILD_LOG"
printf '\n' >> "$FIXTURE_BUILD_LOG"
while [ "$1" != '-o' ]; do shift; done
shift
if [ "${1##*/}" = "${FIXTURE_BUILD_FAIL:-}" ]; then
    printf 'fixture compiler failed\n' >&2
    exit 23
fi
: > "$1"
`
	if err := os.WriteFile(goTool, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIXTURE_BUILD_LOG", logPath)
	t.Setenv("FIXTURE_BUILD_FAIL", "")
	// Explicit build settings must override the caller's target, but not its cache.
	t.Setenv("GOOS", "inherited-os")
	t.Setenv("GOARCH", "inherited-arch")
	t.Setenv("CGO_ENABLED", "1")
	t.Setenv("GOCACHE", filepath.Join(dir, "isolated-cache"))
	return &fixture{
		t: t, repoRoot: dir, tempDir: dir, goTool: goTool,
		bifroestVersion: "e2e-" + filepath.Base(dir), targetGOOS: "linux", targetGOARCH: "arm64",
	}, logPath
}

func readFixtureBuildCalls(t *testing.T, path string) [][]string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		calls = append(calls, strings.Split(strings.TrimSuffix(line, "\t"), "\t"))
	}
	return calls
}
