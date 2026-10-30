//go:build windows && nanoserver_integration

package nanoserver

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/test/nanoserver/browserfixture"
)

func exerciseNativePasswordRemember(t *testing.T, ctx context.Context, h windowsBrowserHarness, address, fixtureFile string, fixture browserfixture.Fixture, dir string, client *http.Client) {
	t.Helper()
	require.True(t, fixture.PasswordResume)
	secret, err := bfcrypto.CreateProtectedTempFile(dir, ".owned-password-*", 0400)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = secret.Close()
		if err := os.Remove(secret.Name()); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove owned primary credential fixture: %v", err)
		}
	})
	// Docker streams the archive straight into the already owner-protected open
	// handle. There is no initial ordinary host-file copy or raw-secret log.
	copyCommand := exec.CommandContext(ctx, "docker", "cp", h.container+`:C:\smoke\browser-password.txt`, "-")
	stream, err := copyCommand.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, copyCommand.Start())
	defer func() {
		_ = stream.Close()
		if copyCommand.ProcessState == nil {
			_ = copyCommand.Process.Kill()
			_ = copyCommand.Wait()
		}
	}()
	archive := tar.NewReader(stream)
	header, err := archive.Next()
	require.NoError(t, err)
	require.Equal(t, "browser-password.txt", filepath.Base(header.Name))
	require.True(t, header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA)
	require.True(t, header.Size > 16 && header.Size <= 4096, "owned primary credential archive must be a bounded regular file")
	_, err = io.CopyN(secret, archive, header.Size)
	require.NoError(t, err)
	_, err = archive.Next()
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, copyCommand.Wait())
	require.NoError(t, secret.Close())
	node := os.Getenv("BIFROEST_TEST_NODE")
	if node == "" {
		node, err = exec.LookPath("node")
		require.NoError(t, err)
	}
	command := exec.CommandContext(ctx, node, filepath.Join(h.root, "web", "test", "windows-remember-ui.mjs"), address, fixtureFile, secret.Name())
	command.Dir = filepath.Join(h.root, "web")
	input, err := command.StdinPipe()
	require.NoError(t, err)
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	command.Cancel = input.Close
	command.WaitDelay = 5 * time.Second
	require.NoError(t, command.Start())
	defer func() {
		_ = input.Close()
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	var results struct {
		Executions    []browserfixture.Probe `json:"executions"`
		PrimaryLogins int                    `json:"primaryLogins"`
		Resumes       int                    `json:"resumes"`
		Denied        int                    `json:"denied"`
		GroupDenied   int                    `json:"groupDenied"`
	}
	checkpoints := []string{"restart-password", "drop-group-password", "add-group-password", "disable-password", "restore-password", "restart-interactive", "drop-group-interactive", "add-group-interactive", "disable-interactive", "restore-interactive"}
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		var message struct {
			Checkpoint string `json:"checkpoint"`
		}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &message))
		if message.Checkpoint == "" {
			require.Empty(t, results.Executions)
			require.NoError(t, json.Unmarshal(scanner.Bytes(), &results))
			continue
		}
		require.NotEmpty(t, checkpoints)
		require.Equal(t, checkpoints[0], message.Checkpoint)
		checkpoints = checkpoints[1:]
		switch {
		case strings.HasPrefix(message.Checkpoint, "restart-"):
			h.mustDocker("exec", h.container, `C:\smoke\s4u-probe.exe`, "browser-restart")
			h.ready(func() error {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://app.example.org:8443/Work", nil)
				if err != nil {
					return err
				}
				response, err := client.Do(request)
				if err != nil {
					return err
				}
				defer response.Body.Close()
				if response.StatusCode != 200 {
					return fmt.Errorf("restarted fixture status%d", response.StatusCode)
				}
				return nil
			})
		case strings.HasPrefix(message.Checkpoint, "disable-"):
			h.mustDocker("exec", h.container, `C:\smoke\s4u-probe.exe`, "browser-disable-owned-account")
		case strings.HasPrefix(message.Checkpoint, "restore-"):
			h.mustDocker("exec", h.container, `C:\smoke\s4u-probe.exe`, "browser-restore-owned-account")
		case strings.HasPrefix(message.Checkpoint, "drop-group-"):
			h.mustDocker("exec", h.container, `C:\smoke\s4u-probe.exe`, "browser-remove-owned-group")
		case strings.HasPrefix(message.Checkpoint, "add-group-"):
			h.mustDocker("exec", h.container, `C:\smoke\s4u-probe.exe`, "browser-add-owned-group")
		default:
			t.Fatal("unknown owned remember fixture checkpoint")
		}
		_, err := fmt.Fprintf(input, "{\"checkpoint\":%q,\"success\":true}\n", message.Checkpoint)
		require.NoError(t, err)
	}
	require.NoError(t, scanner.Err())
	require.NoError(t, command.Wait(), "native password RememberMe: %s", diagnostics.String())
	require.Empty(t, checkpoints)
	require.Len(t, results.Executions, 10)
	require.Equal(t, 2, results.PrimaryLogins)
	require.Equal(t, 8, results.Resumes)
	require.Equal(t, 2, results.Denied)
	require.Equal(t, 2, results.GroupDenied)
	expectations := map[string]nativeExecutionExpectation{}
	for _, execution := range results.Executions {
		requireNativeIdentity(t, fixture, execution, true)
		require.Equal(t, "remember-owned", execution.Content)
		require.Equal(t, results.Executions[0].Session, execution.Session)
		_, duplicate := expectations[execution.Connection]
		require.False(t, duplicate)
		expectations[execution.Connection] = nativeExecutionExpectation{task: audit.SessionTaskShell, pty: true, exit: nativeExit(0)}
	}
	h.mustDocker("exec", h.container, `C:\smoke\s4u-probe.exe`, "browser-stop")
	require.Equal(t, "0", strings.TrimSpace(h.mustDocker("wait", h.container)))
	for _, kind := range []string{"auditlog", "recordings", "sessions"} {
		h.mustDocker("cp", h.container+":"+filepath.Join(fixture.Root, kind), filepath.Join(dir, kind))
	}
	verifyNativeWindowsEvidence(t, dir, fixture, results.Executions[0].Session, expectations)
	t.Log("NATIVE_WINDOWS_PASSWORD_REMEMBER password/interactive primary once each; profile/service restart resume, same-bearer group removal/restoration, disabled-account denial, ten fresh executions and signed artifact correlation")
}
