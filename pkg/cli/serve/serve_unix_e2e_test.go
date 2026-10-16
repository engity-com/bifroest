//go:build unix

package serve_test

import (
	"fmt"
	"io/fs"
	goos "os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	logrecording "github.com/echocat/slf4g/testing/recording"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/serve"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/service"
	"github.com/engity-com/bifroest/pkg/sys"
)

type serveTestVersion struct{}

func (serveTestVersion) Title() string                 { return "Bifröst" }
func (serveTestVersion) Version() string               { return "test" }
func (serveTestVersion) Revision() string              { return "test" }
func (serveTestVersion) Edition() sys.Edition          { return sys.EditionGeneric }
func (serveTestVersion) BuildAt() time.Time            { return time.Now() }
func (serveTestVersion) Vendor() string                { return "test" }
func (serveTestVersion) GoVersion() string             { return "test" }
func (serveTestVersion) Os() sys.Os                    { return sys.OsLinux }
func (serveTestVersion) Arch() sys.Arch                { return sys.ArchAmd64 }
func (serveTestVersion) Features() sys.VersionFeatures { return serveTestFeatures{} }

type serveTestFeatures struct{}

func (serveTestFeatures) ForEach(func(sys.VersionFeatureCategory)) {}

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
	requirement := cli.NewSimpleApplication().
		WithName("bifroest").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(true, true))
	serve.Register(requirement, serveTestVersion{}, service.Run)
	application, err := requirement.Create()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, application.Close()) })
	firstEvent := provider.Len()
	done := make(chan error, 1)
	stopped := false
	go func() {
		done <- application.ParseAndExecute(t.Context(), &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}},
			"serve", "--configuration="+ref.String())
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
	content := fmt.Sprintf(`
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
auditlog:
  - enabled: true
    identityFile: "%s"
    directory: "%s"
    recording:
      enabled: true
      directory: "%s"
`, filepath.ToSlash(filepath.Join(root, "host-key")), filepath.ToSlash(filepath.Join(root, "sessions")),
		filepath.ToSlash(filepath.Join(root, "audit-identity")), filepath.ToSlash(filepath.Join(root, "journal")),
		filepath.ToSlash(filepath.Join(root, "recordings")))
	path := filepath.Join(root, "run-lock-test.yaml")
	require.NoError(t, goos.WriteFile(path, []byte(content), 0600))
	var result configuration.Ref
	require.NoError(t, result.Set(path))
	return result
}
