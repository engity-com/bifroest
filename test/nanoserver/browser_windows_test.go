//go:build windows && nanoserver_integration

package nanoserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/test/nanoserver/browserfixture"
)

func prepareServerCoreBrowserKey(t *testing.T, imageContext string) string {
	t.Helper()
	// Private material must not even enter the Docker build context.
	path := filepath.Join(t.TempDir(), "browser-client-key")
	key, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(nil, path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(imageContext, "browser-authorized-key"), bfcrypto.MarshalPublicKey(key.PublicKey()), 0644))
	return path
}

type windowsBrowserHarness struct {
	t               *testing.T
	ctx             context.Context
	root, container string
}

func (this windowsBrowserHarness) docker(args ...string) (string, error) {
	command := exec.CommandContext(this.ctx, "docker", args...)
	command.Dir = this.root
	raw, err := command.CombinedOutput()
	return string(raw), err
}

func (this windowsBrowserHarness) mustDocker(args ...string) string {
	this.t.Helper()
	raw, err := this.docker(args...)
	require.NoError(this.t, err, "owned Docker command %v: %s", args, raw)
	return raw
}

func (this windowsBrowserHarness) ready(check func() error) {
	this.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if last = check(); last == nil {
			return
		}
		status, err := this.docker("inspect", "--format", "{{.State.Running}}", this.container)
		if err == nil && strings.TrimSpace(status) == "false" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	logs, _ := this.docker("logs", this.container)
	this.t.Fatalf("owned Windows browser service did not become ready: %v\n%s", last, logs)
}

func canonicalNativeID(t *testing.T, value string) {
	t.Helper()
	id, err := uuid.Parse(value)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, id)
	require.Equal(t, id.String(), value)
}

func requireNativeIdentity(t *testing.T, fixture browserfixture.Fixture, probe browserfixture.Probe, pty bool) {
	t.Helper()
	require.Equal(t, fixture.SID, probe.SID)
	require.Equal(t, strings.ToLower(fixture.User), strings.ToLower(probe.User))
	require.Equal(t, pty, probe.Pty)
	require.Positive(t, probe.PID)
	require.NotEmpty(t, probe.Profile)
	canonicalNativeID(t, probe.Session)
	canonicalNativeID(t, probe.Connection)
	canonicalNativeID(t, probe.Execution)
}

type nativeSSHProbe struct {
	connection net.Conn
	session    *ssh.Session
	input      io.WriteCloser
	scanner    *bufio.Scanner
}

func startNativeSSH(t *testing.T, ctx context.Context, address string, fixture browserfixture.Fixture, keyFile, command string, pty bool) *nativeSSHProbe {
	t.Helper()
	raw, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	key, err := ssh.ParsePrivateKey(raw)
	require.NoError(t, err)
	host, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fixture.HostKey))
	require.NoError(t, err)
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(address, "2222"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	require.NoError(t, connection.SetDeadline(time.Now().Add(15*time.Second)))
	transport, channels, requests, err := ssh.NewClientConn(connection, net.JoinHostPort(address, "2222"), &ssh.ClientConfig{User: fixture.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(host)})
	require.NoError(t, err)
	client := ssh.NewClient(transport, channels, requests)
	t.Cleanup(func() { _ = client.Close() })
	current, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = current.Close() })
	input, err := current.StdinPipe()
	require.NoError(t, err)
	output, err := current.StdoutPipe()
	require.NoError(t, err)
	current.Stderr = os.Stderr
	if pty {
		require.NoError(t, current.RequestPty("xterm", 25, 4096, ssh.TerminalModes{}))
	}
	require.NoError(t, current.Start(fixture.Probe+" "+command))
	return &nativeSSHProbe{connection: connection, session: current, input: input, scanner: bufio.NewScanner(output)}
}

func (this *nativeSSHProbe) observe(t *testing.T, marker string) browserfixture.Probe {
	t.Helper()
	require.NoError(t, this.connection.SetDeadline(time.Now().Add(15*time.Second)))
	defer func() { _ = this.connection.SetDeadline(time.Time{}) }()
	for range 32 {
		if !this.scanner.Scan() {
			break
		}
		probe, err := browserfixture.Decode(this.scanner.Text(), marker)
		if err == nil {
			return probe
		}
	}
	t.Fatalf("missing native SSH probe %q: %v", marker, this.scanner.Err())
	return browserfixture.Probe{}
}

func exerciseServerCoreBrowser(t *testing.T, parent context.Context, root, image, isolation, keyFile string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	name := fmt.Sprintf("bifroest-servercore-browser-%d", time.Now().UnixNano())
	h := windowsBrowserHarness{t: t, ctx: ctx, root: root, container: name}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(cleanup, "docker", "container", "rm", "--force", name)
		if raw, err := command.CombinedOutput(); err != nil {
			t.Errorf("remove owned browser container: %v: %s", err, raw)
		}
	})
	diagnosticDirectory := filepath.Join(root, "var", "e2e")
	require.NoError(t, os.MkdirAll(diagnosticDirectory, 0700))
	var diagnostics, trace bytes.Buffer
	var fixture browserfixture.Fixture
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		_ = os.WriteFile(filepath.Join(diagnosticDirectory, "windows-browser-ui.stderr.log"), diagnostics.Bytes(), 0600)
		_ = os.WriteFile(filepath.Join(diagnosticDirectory, "windows-browser-checkpoints.jsonl"), trace.Bytes(), 0600)
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		raw, _ := exec.CommandContext(cleanup, "docker", "logs", name).CombinedOutput()
		_ = os.WriteFile(filepath.Join(diagnosticDirectory, "windows-browser-container.log"), raw, 0600)
		if fixture.Service != "" {
			events, err := exec.CommandContext(cleanup, "docker", "exec", name, `C:\smoke\s4u-probe.exe`, "browser-events").CombinedOutput()
			_ = os.WriteFile(filepath.Join(diagnosticDirectory, "windows-browser-service-events.log"), events, 0600)
			t.Logf("owned native service diagnostics (read error %v): %s", err, events)
			if raw, err := exec.CommandContext(cleanup, "docker", "exec", name, `C:\smoke\s4u-probe.exe`, "browser-stop").CombinedOutput(); err == nil {
				_, _ = exec.CommandContext(cleanup, "docker", "wait", name).CombinedOutput()
				copyPath := filepath.Join(diagnosticDirectory, "windows-browser-failed-audit")
				if raw, err = exec.CommandContext(cleanup, "docker", "cp", name+":"+filepath.Join(fixture.Root, "auditlog"), copyPath).CombinedOutput(); err == nil {
					var producer audit.ProducerId
					if producer.Set(fixture.Producer) == nil {
						journal, err := audit.VerifyJournals(cleanup, []audit.JournalSource{{Name: "default", Directory: copyPath, ExpectedProducerId: producer, WithSensitive: true}})
						if err != nil {
							t.Logf("failure audit unavailable: %v", err)
						} else {
							for _, record := range journal.Records() {
								event := record.Event
								if event.Name == audit.EventNameSessionTaskStarted || event.Name == audit.EventNameSessionTaskCompleted {
									raw, _ := json.Marshal(event)
									t.Logf("verified native task observation: %s", raw)
								}
							}
						}
					}
				} else {
					t.Logf("failure audit copy unavailable: %v: %s", err, raw)
				}
			} else {
				t.Logf("failure service stop unavailable: %v: %s", err, raw)
			}
		}
	})
	h.mustDocker("run", "--detach", "--name", name, "--isolation="+isolation, "--user", "ContainerAdministrator", "--env", "BIFROEST_TEST_LOCAL_SAM_IN_CONTAINER=1", "--env", "BIFROEST_TEST_SERVERCORE_BROWSER=1", image, `C:\smoke\s4u-probe.exe`, "browser-serve", `C:\smoke\bifroest.exe`)
	dir := t.TempDir()
	fixtureFile := filepath.Join(dir, "fixture.json")
	h.ready(func() error {
		if _, err := h.docker("cp", name+`:C:\smoke\browser-fixture.json`, fixtureFile); err != nil {
			return err
		}
		raw, err := os.ReadFile(fixtureFile)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, &fixture)
	})
	require.True(t, strings.HasPrefix(fixture.Service, "bifroest-browser-"))
	targetSID, err := windows.StringToSid(fixture.SID)
	require.NoError(t, err)
	require.True(t, targetSID.IsValid())
	require.NotContains(t, []string{"S-1-5-18", "S-1-5-93-2-1", "S-1-5-93-2-2"}, fixture.SID, "must target the new local SAM user, not a container or system identity")
	var networks map[string]struct{ IPAddress string }
	raw := h.mustDocker("inspect", "--format", "{{json .NetworkSettings.Networks}}", name)
	require.NoError(t, json.Unmarshal([]byte(raw), &networks))
	var addresses []string
	for _, network := range networks {
		address, err := netip.ParseAddr(network.IPAddress)
		if err == nil && address.Is4() && address.IsPrivate() {
			addresses = append(addresses, address.String())
		}
	}
	require.Len(t, addresses, 1, "the owned container needs one private native IPv4 address; do not publish host ports")
	address := addresses[0]
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM([]byte(fixture.Certificate)))
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(address, "8443"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
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
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTPS discovery status %d", response.StatusCode)
		}
		if response.ProtoMajor != 2 {
			return fmt.Errorf("native HTTPS endpoint did not negotiate HTTP/2")
		}
		return nil
	})
	held := startNativeSSH(t, ctx, address, fixture, keyFile, "browser-hold", false)
	first := held.observe(t, "ssh-initial")
	requireNativeIdentity(t, fixture, first, false)
	require.Equal(t, "ssh-owned", first.Content)
	// Exercise the real executable's ConPTY relay through SSH too. The existing
	// environment.test.exe relay oracle alone does not cover CLI registration.
	reference := startNativeSSH(t, ctx, address, fixture, keyFile, "browser-probe ssh-pty", true)
	ptyReference := reference.observe(t, "ssh-pty")
	t.Logf("actual native SSH PTY child observation: %+v", ptyReference)
	requireNativeIdentity(t, fixture, ptyReference, true)
	require.Equal(t, first.Session, ptyReference.Session)
	require.NoError(t, reference.connection.SetDeadline(time.Now().Add(15*time.Second)))
	require.NoError(t, reference.session.Wait())
	require.NoError(t, reference.connection.Close(), "the completed reference transport must not retain a quota slot")
	node := os.Getenv("BIFROEST_TEST_NODE")
	if node == "" {
		var err error
		node, err = exec.LookPath("node")
		require.NoError(t, err)
	}
	command := exec.CommandContext(ctx, node, filepath.Join(root, "web", "test", "windows-native-ui.mjs"), address, fixtureFile, keyFile)
	command.Dir = filepath.Join(root, "web")
	input, err := command.StdinPipe()
	require.NoError(t, err)
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	command.Stderr = &diagnostics
	command.Cancel = input.Close
	command.WaitDelay = 5 * time.Second
	require.NoError(t, command.Start())
	defer func() {
		if command.ProcessState == nil {
			_ = input.Close()
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-done:
			case <-timer.C:
				_ = command.Process.Kill()
				<-done
			}
		}
	}()
	var browser struct {
		Executions []struct {
			browserfixture.Probe
			Exit *uint32 `json:"exit"`
		} `json:"executions"`
	}
	checkpoints := []string{"after-close", "after-reload", "after-logout"}
	scanner := bufio.NewScanner(output)
	for scanner.Scan() {
		_, _ = trace.Write(scanner.Bytes())
		_ = trace.WriteByte('\n')
		var message struct {
			Checkpoint string `json:"checkpoint"`
		}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &message))
		if message.Checkpoint != "" {
			require.NotEmpty(t, checkpoints)
			require.Equal(t, checkpoints[0], message.Checkpoint)
			checkpoints = checkpoints[1:]
			_, err := fmt.Fprintf(held.input, "check %s\n", message.Checkpoint)
			require.NoError(t, err)
			current := held.observe(t, message.Checkpoint)
			requireNativeIdentity(t, fixture, current, false)
			require.Equal(t, first.Session, current.Session)
			require.Equal(t, first.Connection, current.Connection)
			require.Equal(t, first.PID, current.PID)
			require.Equal(t, first.Execution, current.Execution)
			require.Equal(t, "web-owned", current.Content, "browser action must not replace/dispose the SSH workload")
			require.Equal(t, "web-owned", strings.TrimSpace(h.mustDocker("exec", name, `C:\smoke\s4u-probe.exe`, "browser-inspect")), "independent container/profile probe")
			_, err = fmt.Fprintf(input, "{\"checkpoint\":%q,\"success\":true}\n", message.Checkpoint)
			require.NoError(t, err)
		} else {
			require.Empty(t, browser.Executions, "one final browser result only")
			require.NoError(t, json.Unmarshal(scanner.Bytes(), &browser))
		}
	}
	require.NoError(t, scanner.Err())
	require.NoError(t, command.Wait(), "native browser: %s", diagnostics.String())
	require.Empty(t, checkpoints)
	require.Len(t, browser.Executions, 5)
	expectations := map[string]nativeExecutionExpectation{first.Connection: {task: audit.SessionTaskExec, exit: nativeExit(0)}}
	require.NotEqual(t, first.Connection, ptyReference.Connection)
	expectations[ptyReference.Connection] = nativeExecutionExpectation{task: audit.SessionTaskExec, pty: true, exit: nativeExit(0)}
	for _, execution := range browser.Executions {
		requireNativeIdentity(t, fixture, execution.Probe, true)
		require.Equal(t, first.Session, execution.Session)
		_, exists := expectations[execution.Connection]
		require.False(t, exists, "no reattached connection")
		expectations[execution.Connection] = nativeExecutionExpectation{task: audit.SessionTaskShell, pty: true, exit: execution.Exit}
	}
	_, err = fmt.Fprintln(held.input, "exit")
	require.NoError(t, err)
	require.NoError(t, held.connection.SetDeadline(time.Now().Add(15*time.Second)))
	require.NoError(t, held.input.Close())
	require.NoError(t, held.session.Wait())
	last := startNativeSSH(t, ctx, address, fixture, keyFile, "browser-probe ssh-final", false)
	final := last.observe(t, "ssh-final")
	requireNativeIdentity(t, fixture, final, false)
	require.Equal(t, first.Session, final.Session)
	require.Equal(t, "web-owned", final.Content)
	require.NoError(t, last.connection.SetDeadline(time.Now().Add(15*time.Second)))
	require.NoError(t, last.session.Wait())
	_, exists := expectations[final.Connection]
	require.False(t, exists)
	expectations[final.Connection] = nativeExecutionExpectation{task: audit.SessionTaskExec, exit: nativeExit(0)}
	h.mustDocker("exec", name, `C:\smoke\s4u-probe.exe`, "browser-stop")
	require.Equal(t, "0", strings.TrimSpace(h.mustDocker("wait", name)), "real Windows service and foreground fixture must stop cleanly")
	for _, kind := range []string{"auditlog", "recordings", "sessions"} {
		h.mustDocker("cp", name+":"+filepath.Join(fixture.Root, kind), filepath.Join(dir, kind))
	}
	verifyNativeWindowsEvidence(t, dir, fixture, first.Session, expectations)
}

type nativeExecutionExpectation struct {
	task audit.SessionTask
	pty  bool
	exit *uint32
}

func nativeExit(value uint32) *uint32 { return &value }

func verifyNativeWindowsEvidence(t *testing.T, dir string, fixture browserfixture.Fixture, id string, wanted map[string]nativeExecutionExpectation) {
	t.Helper()
	var producer audit.ProducerId
	require.NoError(t, producer.Set(fixture.Producer))
	files, err := os.ReadDir(filepath.Join(dir, "recordings", "sealed"))
	require.NoError(t, err)
	operations := map[string]string{}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".bcast") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "recordings", "sealed", file.Name()))
		require.NoError(t, err)
		var cast bytes.Buffer
		_, err = recording.ExportNativeRecordingCast(bytes.NewReader(raw), int64(len(raw)), nil, &cast, recording.NativeRecordingVerifyOptions{ExpectedProducerId: producer})
		require.NoError(t, err)
		verified, err := recording.VerifyCast(bytes.NewReader(cast.Bytes()), recording.CastVerifyOptions{ExpectedProducerId: producer})
		require.NoError(t, err)
		connection := verified.Metadata.ConnectionId.String()
		expect, found := wanted[connection]
		require.True(t, found)
		require.Empty(t, operations[connection])
		operations[connection] = verified.Metadata.OperationId.String()
		require.True(t, verified.Trusted)
		require.Equal(t, id, verified.Metadata.SessionId.String())
		require.Equal(t, browserfixture.Flow, verified.Metadata.Flow.String())
		require.Equal(t, expect.task, verified.Metadata.Task)
		require.Equal(t, expect.pty, verified.Metadata.Pty)
		require.Equal(t, expect.exit, verified.ExitStatus)
		if expect.exit != nil {
			require.Equal(t, recording.CastStatusCompleted, verified.Result.Status)
		} else {
			require.NotEqual(t, recording.CastStatusCompleted, verified.Result.Status, "transport loss must not invent a successful shell exit")
		}
	}
	require.Len(t, operations, len(wanted), "every real execution needs one independently verified signed recording")
	journal, err := audit.VerifyJournals(t.Context(), []audit.JournalSource{{Name: "default", Directory: filepath.Join(dir, "auditlog"), ExpectedProducerId: producer, WithSensitive: true}})
	require.NoError(t, err)
	starts, finishes := map[string]bool{}, map[string]bool{}
	for _, record := range journal.Records() {
		event := record.Event
		if event.Name != audit.EventNameSessionTaskStarted && event.Name != audit.EventNameSessionTaskCompleted {
			continue
		}
		expect, found := wanted[event.ConnectionId]
		require.True(t, found, "no extra executions")
		require.Equal(t, id, event.SessionId)
		require.Equal(t, browserfixture.Flow, event.Flow)
		require.Equal(t, operations[event.ConnectionId], event.OperationId)
		require.Equal(t, expect.task, event.SessionTask)
		if event.Name == audit.EventNameSessionTaskStarted {
			require.False(t, starts[event.ConnectionId])
			starts[event.ConnectionId] = true
			require.NotNil(t, event.Pty)
			require.Equal(t, expect.pty, *event.Pty)
		} else {
			require.False(t, finishes[event.ConnectionId])
			finishes[event.ConnectionId] = true
			if expect.exit != nil {
				require.Equal(t, audit.EventOutcomeSuccess, event.Outcome)
				require.NotNil(t, event.ExitCode)
				require.EqualValues(t, *expect.exit, *event.ExitCode)
			} else {
				require.Nil(t, event.ExitCode)
				require.Contains(t, []audit.EventOutcome{audit.EventOutcomeCanceled, audit.EventOutcomeFailure}, event.Outcome)
			}
		}
	}
	require.Len(t, starts, len(wanted))
	require.Len(t, finishes, len(wanted))
	conf := &configuration.SessionFs{}
	require.NoError(t, conf.SetDefaults())
	conf.Storage = filepath.Join(dir, "sessions")
	repository, err := session.NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	defer repository.Close()
	var storedID session.Id
	require.NoError(t, storedID.Set(id))
	stored, err := repository.FindBy(t.Context(), browserfixture.Flow, storedID, nil)
	require.NoError(t, err)
	info, err := stored.Info(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, session.StateDisposed, info.State())
	association, err := session.AssociationOf(t.Context(), stored)
	require.NoError(t, err)
	require.NotNil(t, association)
	require.Equal(t, "local", association.Issuer)
	require.Equal(t, fixture.SID, association.Subject)
	count := 0
	require.NoError(t, repository.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	require.Equal(t, 1, count, "SSH/key-WASM/reloads must retain exactly one associated native session")
	t.Logf("native Windows browser: SID=%s session=%s eight fresh connections, five real ConPTY shells plus native SSH PTY, exact exits7/0, close/reload/logout isolation and signed audit/recordings", fixture.SID, id)
}
