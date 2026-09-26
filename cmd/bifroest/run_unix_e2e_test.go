//go:build unix

package main

import (
	"fmt"
	"io/fs"
	goos "os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	logrecording "github.com/echocat/slf4g/testing/recording"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestDoRunDefaultRemovesRepositoryLocksOnShutdown(t *testing.T) {
	root := t.TempDir()
	ref := runDefaultLockTestConfiguration(t, root)
	lockPaths := []string{
		filepath.Join(root, ".sessions.bifroest.lock"),
		filepath.Join(root, "journal", ".bifroest.lock"),
		filepath.Join(root, "recordings", ".bifroest-recording.lock"),
	}
	provider := logrecording.NewProvider()
	defer provider.HookGlobally()()

	for range 2 {
		runDefaultUntilInterrupted(t, ref, lockPaths, provider)
		for _, lockPath := range lockPaths {
			require.NoFileExists(t, lockPath)
		}
		requireNoLockFiles(t, root)
	}

	messageKey := provider.GetFieldKeysSpec().GetMessage()
	for _, event := range provider.GetAll() {
		message, exists := event.Get(messageKey)
		if exists {
			require.NotEqual(t, "found existing unlocked session repository lock file; lock was taken over", message)
		}
	}
}

func runDefaultUntilInterrupted(t *testing.T, ref configuration.Ref, lockPaths []string, provider *logrecording.Provider) {
	t.Helper()
	firstEvent := provider.Len()
	done := make(chan error, 1)
	stopped := false
	go func() {
		done <- doRunDefault(ref)
	}()
	t.Cleanup(func() {
		if stopped {
			return
		}
		select {
		case <-done:
			return
		default:
		}
		process, err := goos.FindProcess(goos.Getpid())
		if err == nil {
			_ = process.Signal(syscall.SIGINT)
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	require.Eventually(t, func() bool {
		for _, lockPath := range lockPaths {
			if _, err := goos.Stat(lockPath); err != nil {
				return false
			}
		}
		return true
	}, 10*time.Second, 10*time.Millisecond)
	var address string
	require.Eventually(t, func() bool {
		events := provider.GetAll()
		messageKey := provider.GetFieldKeysSpec().GetMessage()
		for _, event := range events[firstEvent:] {
			if message, exists := event.Get(messageKey); exists && message == "listening..." {
				if value, exists := event.Get("address"); exists {
					address = fmt.Sprint(value)
					return address != ""
				}
			}
		}
		return false
	}, 10*time.Second, 10*time.Millisecond)
	client, err := gossh.Dial("tcp", address, &gossh.ClientConfig{
		User:            "test-user",
		Auth:            []gossh.AuthMethod{gossh.Password("test-password")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // The server and host key are test-local.
		Timeout:         5 * time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, client.Close())

	process, err := goos.FindProcess(goos.Getpid())
	require.NoError(t, err)
	require.NoError(t, process.Signal(syscall.SIGINT))
	select {
	case err := <-done:
		stopped = true
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("doRunDefault did not stop after SIGINT")
	}
}

func requireNoLockFiles(t *testing.T, root string) {
	t.Helper()
	var lockFiles []string
	require.NoError(t, filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.Contains(strings.ToLower(entry.Name()), ".lock") {
			lockFiles = append(lockFiles, path)
		}
		return nil
	}))
	require.Empty(t, lockFiles)
}

func runDefaultLockTestConfiguration(t *testing.T, root string) configuration.Ref {
	t.Helper()
	var result configuration.Ref
	err := result.Get().LoadFromYaml(strings.NewReader(fmt.Sprintf(`
ssh:
  addresses: ["127.0.0.1:0"]
  keys:
    hostKeys: ["%s"]
  banner: ""
session:
  type: fs
  storage: "%s"
flows:
  - name: lock-test
    authorization:
      type: none
    environment:
      type: dummy
`, filepath.ToSlash(filepath.Join(root, "host-key")), filepath.ToSlash(filepath.Join(root, "sessions")))), "run-lock-test.yaml")
	require.NoError(t, err)
	auditlog := &result.Get().Auditlogs[0]
	auditlog.Enabled = true
	auditlog.IdentityFile = filepath.Join(root, "audit-identity")
	auditlog.Directory = filepath.Join(root, "journal")
	auditlog.Recording.Enabled = true
	auditlog.Recording.Directory = filepath.Join(root, "recordings")
	return result
}
