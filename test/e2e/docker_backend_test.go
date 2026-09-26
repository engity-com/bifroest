//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
)

func TestOpenSSHDockerEnvironment(t *testing.T) {
	f, err := newDockerEnvironmentFixture(t)
	if errors.Is(err, errNoRuntime) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime=%s host=%s network=%s port=%s", f.runtimeCLI, f.runtimeHost, f.networkID, f.port)

	t.Run("wrong key creates no environment", func(t *testing.T) {
		result := f.ssh(10*time.Second, f.wrongKey, "e2e", nil, "/usr/local/bin/e2e-helper", "ready")
		if result.err == nil {
			t.Fatalf("login unexpectedly succeeded: %s", result.stdout)
		}
		time.Sleep(500 * time.Millisecond)
		ids, err := f.containerIDs()
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 0 {
			t.Fatalf("rejected key created environment containers: %v", ids)
		}
	})

	t.Run("exec stdout stderr and exit status", func(t *testing.T) {
		result := f.ssh(3*time.Minute, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "streams", "audit-secret-command-argument")
		if code := exitCode(result.err); code != 23 {
			t.Fatalf("exit code: got %d, want 23 (error: %v)\nstdout:\n%s\nstderr:\n%s", code, result.err, result.stdout, result.stderr)
		}
		if result.stdout != "stdout-e2e\n" {
			t.Errorf("stdout: got %q", result.stdout)
		}
		if result.stderr != "stderr-e2e\n" {
			t.Errorf("stderr: got %q", result.stderr)
		}
		if err := f.waitForEnvironmentContainer(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("session and container reuse", func(t *testing.T) {
		first := f.ssh(20*time.Second, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "environment")
		if first.err != nil {
			t.Fatalf("first connection failed: %v\n%s", first.err, first.stderr)
		}
		firstIDs := parseEnvironmentIDs(t, first.stdout)
		containerBefore := f.containerID

		second := f.ssh(20*time.Second, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "environment")
		if second.err != nil {
			t.Fatalf("second connection failed: %v\n%s", second.err, second.stderr)
		}
		secondIDs := parseEnvironmentIDs(t, second.stdout)
		if firstIDs["session"] == "" || firstIDs["session"] != secondIDs["session"] {
			t.Fatalf("session ID changed: first=%q second=%q", firstIDs["session"], secondIDs["session"])
		}
		if firstIDs["connection"] == "" || secondIDs["connection"] == "" || firstIDs["connection"] == secondIDs["connection"] {
			t.Fatalf("connection IDs were not unique: first=%q second=%q", firstIDs["connection"], secondIDs["connection"])
		}
		ids, err := f.containerIDs()
		if err != nil {
			t.Fatal(err)
		}
		if len(ids) != 1 || ids[0] != containerBefore {
			t.Fatalf("container was not reused: before=%q after=%v", containerBefore, ids)
		}
	})

	t.Run("PTY allocation", func(t *testing.T) {
		result := f.sshWithEnv(20*time.Second, []string{"TERM=xterm-256color"}, f.clientKey, "e2e", []string{"-tt"}, "/usr/local/bin/e2e-helper", "pty")
		if result.err != nil {
			t.Fatalf("PTY command failed: %v\nstdout:\n%s\nstderr:\n%s", result.err, result.stdout, result.stderr)
		}
		output := strings.ReplaceAll(strings.TrimSpace(result.stdout), "\r", "")
		if output != "pty=true term=xterm-256color" {
			t.Fatalf("unexpected PTY output %q", output)
		}
	})

	t.Run("PTY fast exit preserves status", func(t *testing.T) {
		for attempt := 1; attempt <= 10; attempt++ {
			result := f.sshWithEnv(20*time.Second, nil, f.clientKey, "e2e", []string{"-tt"}, "/usr/local/bin/e2e-helper", "exit-after", "0", "23")
			if code := exitCode(result.err); code != 23 {
				t.Fatalf("attempt %d exit code: got %d, want 23 (error: %v)\nstdout:\n%s\nstderr:\n%s", attempt, code, result.err, result.stdout, result.stderr)
			}
		}
	})

	runContainerExecutionEnvironmentTest(t, f, 45*time.Second, "")

	runBackendProtocolTests(t, f, 45*time.Second, func(t *testing.T) {
		ensureContainerEchoServer(t, f)
	})

	t.Run("native SFTP lifecycle", func(t *testing.T) {
		source := filepath.Join(t.TempDir(), "source.bin")
		download := filepath.Join(t.TempDir(), "download.bin")
		payload := bytes.Repeat([]byte("docker-sftp-e2e\x00"), 4096)
		if err := os.WriteFile(source, payload, 0600); err != nil {
			t.Fatal(err)
		}
		batch := filepath.Join(t.TempDir(), "batch")
		commands := fmt.Sprintf("put %s audit-secret-upload.tmp\nrename audit-secret-upload.tmp audit-secret-renamed.bin\nget audit-secret-renamed.bin %s\nrm audit-secret-renamed.bin\n", source, download)
		if err := os.WriteFile(batch, []byte(commands), 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{
			"-F", "/dev/null",
			"-S", f.tools["ssh"],
			"-b", batch,
			"-P", f.port,
			"-i", f.clientKey,
			"-o", "BatchMode=yes",
			"-o", "IdentitiesOnly=yes",
			"-o", "UserKnownHostsFile=" + f.knownHosts,
			"-o", "StrictHostKeyChecking=yes",
			"-o", "ConnectTimeout=5",
			"-o", "LogLevel=ERROR",
			"e2e@" + f.host,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		result := runCommand(ctx, f.repoRoot, nil, f.tools["sftp"], args...)
		cancel()
		if result.err != nil {
			t.Fatalf("SFTP failed: %v\nstdout:\n%s\nstderr:\n%s", result.err, result.stdout, result.stderr)
		}
		actual, err := os.ReadFile(download)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, payload) {
			t.Fatalf("download differs: got %d bytes, want %d", len(actual), len(payload))
		}
	})

	t.Run("ssh -L transfer", func(t *testing.T) {
		ensureContainerEchoServer(t, f)
		socket := filepath.Join(t.TempDir(), "local-forward.sock")
		forward := startSSH(t, f, nil, []string{"-N", "-o", "ExitOnForwardFailure=yes", "-L", fmt.Sprintf("%s:127.0.0.1:%d", socket, echoPort)}, nil)
		defer forward.stop()
		if err := pollProcess(15*time.Second, forward, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := runCommand(ctx, f.repoRoot, nil, f.helper, "echo-client", "unix", socket, "262144")
			if result.err != nil {
				return fmt.Errorf("%w: %s", result.err, result.stderr)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ssh -D SOCKS5 transfer", func(t *testing.T) {
		ensureContainerEchoServer(t, f)
		port, err := unusedTCPPort()
		if err != nil {
			t.Fatal(err)
		}
		proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		forward := startSSH(t, f, nil, []string{"-N", "-o", "ExitOnForwardFailure=yes", "-D", proxy}, nil)
		defer forward.stop()
		if err := pollProcess(15*time.Second, forward, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := runCommand(ctx, f.repoRoot, nil, f.helper, "echo-client", "socks", proxy, fmt.Sprintf("127.0.0.1:%d", echoPort), "262144")
			if result.err != nil {
				return fmt.Errorf("%w: %s", result.err, result.stderr)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ssh -R transfer", func(t *testing.T) {
		hostEcho, address := startEchoServer(t, f.helper)
		defer hostEcho.stop()
		forward := startSSH(t, f, nil, []string{
			"-N", "-o", "ExitOnForwardFailure=yes",
			"-R", fmt.Sprintf("127.0.0.1:%d:%s", reversePort, address),
		}, nil)
		defer forward.stop()
		if err := pollProcess(15*time.Second, forward, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := runCommand(ctx, f.repoRoot, nil, f.helper, "echo-client", "tcp", fmt.Sprintf("127.0.0.1:%d", reversePort), "262144")
			if result.err != nil {
				return fmt.Errorf("%w: %s", result.err, result.stderr)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("agent forwarding", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "agent.sock")
		agentProcess := startProcess(t, nil, f.tools["ssh-agent"], "-D", "-a", socket)
		defer agentProcess.stop()
		if err := poll(5*time.Second, func() error {
			_, err := os.Stat(socket)
			return err
		}); err != nil {
			t.Fatalf("ssh-agent did not create socket: %v", err)
		}
		env := []string{"SSH_AUTH_SOCK=" + socket}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		result := runCommand(ctx, f.repoRoot, env, f.tools["ssh-add"], f.agentKey)
		cancel()
		if result.err != nil {
			t.Fatalf("ssh-add failed: %v\n%s", result.err, result.stderr)
		}
		result = f.sshWithEnv(20*time.Second, env, f.clientKey, "e2e", []string{"-A"}, "/usr/local/bin/e2e-helper", "agent-keys")
		if result.err != nil {
			t.Fatalf("agent forwarding failed: %v\nstderr:\n%s", result.err, result.stderr)
		}
		if got, want := normalizePublicKey(result.stdout), normalizePublicKey(string(mustRead(f.agentKey+".pub"))); got != want {
			t.Fatalf("forwarded keys: got %q, want %q", got, want)
		}
	})

	t.Run("abrupt disconnect cleans process", func(t *testing.T) {
		pidFile := "/tmp/bifroest-e2e-abrupt.pid"
		connection := startSSH(t, f, nil, nil, []string{"/usr/local/bin/e2e-helper", "wait-for-stop", pidFile})
		if err := waitForRemoteProcess(f, connection, pidFile); err != nil {
			connection.stop()
			t.Fatal(err)
		}
		if err := connection.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if err := connection.wait(5 * time.Second); err == nil {
			t.Fatal("abruptly killed SSH client exited successfully")
		} else if errors.Is(err, context.DeadlineExceeded) {
			connection.stop()
			t.Fatal("abruptly killed SSH client did not terminate")
		}
		if err := poll(10*time.Second, func() error {
			result := f.runtime(3*time.Second, "exec", f.containerID, "/usr/local/bin/e2e-helper", "process-alive", pidFile)
			if result.err == nil {
				return errors.New("remote process is still alive")
			}
			if exitCode(result.err) == 1 {
				return nil
			}
			return fmt.Errorf("cannot inspect remote process: %w: %s", result.err, result.stderr)
		}); err != nil {
			info := f.runtime(3*time.Second, "exec", f.containerID, "/usr/local/bin/e2e-helper", "process-info", pidFile)
			t.Fatalf("%v\nprocess info:\n%s\n%s", err, info.stdout, info.stderr)
		}
	})

	t.Run("target environment is absent from wrapper argv", func(t *testing.T) {
		const secretName = "BIFROEST_E2E_ARGV_SECRET"
		const secretValue = "target-environment-must-not-be-in-wrapper-argv"
		pidFile := "/tmp/bifroest-e2e-argv.pid"
		client := f.newSSHClient(t, 20*time.Second)
		defer client.Close()
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if err := session.Setenv(secretName, secretValue); err != nil {
			t.Fatalf("set target environment: %v", err)
		}
		if err := session.Start("/usr/local/bin/e2e-helper wait-for-stop " + pidFile); err != nil {
			t.Fatalf("start remote process: %v", err)
		}
		if err := poll(5*time.Second, func() error {
			result := f.runtime(3*time.Second, "exec", f.containerID, "/usr/local/bin/e2e-helper", "process-alive", pidFile)
			if result.err != nil {
				return fmt.Errorf("remote process is not ready: %w: %s", result.err, result.stderr)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		result := f.runtime(3*time.Second, "exec", f.containerID, "/usr/local/bin/e2e-helper", "process-command-lines")
		if result.err != nil {
			t.Fatalf("inspect process command lines: %v\n%s", result.err, result.stderr)
		}
		if strings.Contains(result.stdout, secretName) || strings.Contains(result.stdout, secretValue) {
			t.Fatalf("target environment leaked into execution argv:\n%s", result.stdout)
		}
		if err := session.Signal(gossh.Signal("KILL")); err != nil {
			t.Fatalf("stop remote process: %v", err)
		}
		if got := sshExitCode(session.Wait()); got != 137 {
			t.Fatalf("remote process exit status: got %d, want 137", got)
		}
	})

	// This must remain the final SSH-producing subtest: the session and its only environment are expected to disappear.
	t.Run("session expiry cleans container", func(t *testing.T) {
		if err := poll(45*time.Second, func() error {
			ids, err := f.containerIDs()
			if err != nil {
				return err
			}
			if len(ids) != 0 {
				return fmt.Errorf("environment containers still exist: %v", ids)
			}
			entries, err := os.ReadDir(f.sessionStorage)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if len(entries) != 0 {
				return fmt.Errorf("session files still exist: %d", len(entries))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("audit journal verifies events and privacy", func(t *testing.T) {
		runDockerAuditE2E(t, f, filepath.Join(f.tempDir, "docker-environment.yaml"))
	})
}

func TestOpenSSHDockerEnvironmentSessionRecording(t *testing.T) {
	f, err := newDockerEnvironmentRecordingFixture(t)
	if errors.Is(err, errNoRuntime) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	producerID := f.recordingProducerID
	t.Logf("runtime=%s host=%s network=%s port=%s producer=%s", f.runtimeCLI, f.runtimeHost, f.networkID, f.port, producerID)

	result := f.ssh(3*time.Minute, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "streams")
	if code := exitCode(result.err); code != 23 {
		t.Fatalf("recorded command exit code: got %d, want 23 (error: %v)\nstdout:\n%s\nstderr:\n%s", code, result.err, result.stdout, result.stderr)
	}
	if result.stdout != "stdout-e2e\n" || result.stderr != "stderr-e2e\n" {
		t.Fatalf("recorded command output: stdout=%q stderr=%q", result.stdout, result.stderr)
	}
	if err := f.waitForEnvironmentContainer(); err != nil {
		t.Fatal(err)
	}

	artifact := sealedSessionRecordingArtifact(t, filepath.Join(f.tempDir, "recordings"))
	stopHostBifroest(t, f)
	if finalArtifact := sealedSessionRecordingArtifact(t, filepath.Join(f.tempDir, "recordings")); finalArtifact != artifact {
		t.Fatalf("sealed recording changed during shutdown: before=%q after=%q", artifact, finalArtifact)
	}
	verifySessionRecordingArtifact(t, f, artifact, producerID)
}

type exportedAuditRecord struct {
	Event exportedAuditEvent `json:"event"`
}

type exportedAuditEvent struct {
	Name                 string `json:"name"`
	Domain               string `json:"domain"`
	Outcome              string `json:"outcome"`
	Flow                 string `json:"flow"`
	ConnectionId         string `json:"connectionId"`
	SessionId            string `json:"sessionId"`
	OperationId          string `json:"operationId"`
	AuthenticationMethod string `json:"authenticationMethod"`
	AuthorizationKind    string `json:"authorizationKind"`
	SessionTask          string `json:"sessionTask"`
	ExitCode             *int   `json:"exitCode"`
	BytesRead            *int64 `json:"bytesRead"`
	BytesWritten         *int64 `json:"bytesWritten"`
	DurationMillis       *int64 `json:"durationMillis"`
}

func runDockerAuditE2E(t *testing.T, f *fixture, configurationPath string) {
	t.Helper()
	if f.bifroestProc == nil {
		t.Fatal("Bifroest process is not running")
	}
	if exited, err := f.bifroestProc.collect(); exited {
		t.Fatalf("Bifroest exited before audit verification: %v", err)
	}
	if err := f.bifroestProc.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal Bifroest: %v", err)
	}
	if err := f.bifroestProc.wait(10 * time.Second); err != nil {
		t.Fatalf("wait for graceful Bifroest shutdown: %v\nstdout:\n%s\nstderr:\n%s", err, f.bifroestProc.stdout.String(), f.bifroestProc.stderr.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	verify := runCommand(ctx, f.repoRoot, nil, f.bifroest, "audit", "verify", "--configuration="+configurationPath, "default")
	cancel()
	if verify.err != nil {
		t.Fatalf("verify audit journal: %v\nstdout:\n%s\nstderr:\n%s", verify.err, verify.stdout, verify.stderr)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	exported := runCommand(ctx, f.repoRoot, nil, f.bifroest, "audit", "export", "--configuration="+configurationPath, "--output=-", "default")
	cancel()
	if exported.err != nil {
		t.Fatalf("export audit journal: %v\nstdout:\n%s\nstderr:\n%s", exported.err, exported.stdout, exported.stderr)
	}
	redacted := exported.stdout
	redactedRecords := decodeExportedAuditRecords(t, redacted)
	if len(redactedRecords) == 0 {
		t.Fatal("redacted audit export contains no records")
	}
	for _, line := range strings.Split(strings.TrimSpace(redacted), "\n") {
		var record struct {
			Event map[string]json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode redacted audit event: %v", err)
		}
		for field := range record.Event {
			switch field {
			case "name", "domain", "outcome":
			default:
				t.Fatalf("default audit export exposed private event field %q", field)
			}
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	exported = runCommand(ctx, f.repoRoot, nil, f.bifroest, "audit", "export", "--configuration="+configurationPath, "--with-sensitive", "--output=-", "default")
	cancel()
	if exported.err != nil {
		t.Fatalf("export sensitive audit journal: %v\nstdout:\n%s\nstderr:\n%s", exported.err, exported.stdout, exported.stderr)
	}
	records := decodeExportedAuditRecords(t, exported.stdout)
	if len(records) == 0 {
		t.Fatal("audit export contains no records")
	}
	if len(records) != len(redactedRecords) {
		t.Fatalf("redacted audit export has %d records, sensitive export has %d", len(redactedRecords), len(records))
	}

	var authentication, pty, agentForwarding, reverseDecision, connectionClosed, housekeepingDispose, housekeepingDelete bool
	taskStarts := make(map[string]exportedAuditEvent)
	taskCompletions := make(map[string]exportedAuditEvent)
	directDecisions := make(map[string]exportedAuditEvent)
	directStarts := make(map[string]exportedAuditEvent)
	directCompletions := make(map[string]exportedAuditEvent)
	for _, record := range records {
		event := record.Event
		if event.Flow != "" && event.Flow != f.flowName {
			t.Fatalf("event %q has flow %q, want %q", event.Name, event.Flow, f.flowName)
		}
		switch event.Name {
		case audit.EventNameAuthenticationCompleted:
			if event.Domain == "authentication" && event.Outcome == "success" && event.AuthenticationMethod == "public-key" &&
				event.AuthorizationKind == "simple" && event.ConnectionId != "" && event.SessionId != "" {
				authentication = true
			}
		case audit.EventNameSessionPtyDecided:
			pty = pty || event.Outcome == "success"
		case audit.EventNameSessionAgentForwardingDecided:
			agentForwarding = agentForwarding || event.Outcome == "success"
		case audit.EventNameSessionTaskStarted:
			if event.OperationId == "" {
				t.Fatalf("task start lacks operation ID: %#v", event)
			}
			taskStarts[event.OperationId] = event
		case audit.EventNameSessionTaskCompleted:
			taskCompletions[event.OperationId] = event
		case audit.EventNamePortForwardingDirectDecided:
			if event.Outcome == "success" {
				directDecisions[event.OperationId] = event
			}
		case audit.EventNamePortForwardingDirectStarted:
			directStarts[event.OperationId] = event
		case audit.EventNamePortForwardingDirectCompleted:
			directCompletions[event.OperationId] = event
		case audit.EventNamePortForwardingReverseDecided:
			reverseDecision = reverseDecision || event.Outcome == "success"
		case audit.EventNameConnectionClosed:
			connectionClosed = connectionClosed || event.ConnectionId != ""
		case audit.EventNameHousekeepingSessionDisposeCompleted:
			housekeepingDispose = housekeepingDispose || event.Outcome == "success"
		case audit.EventNameHousekeepingSessionDeleteCompleted:
			housekeepingDelete = housekeepingDelete || event.Outcome == "success"
		}
	}

	if !authentication || !pty || !agentForwarding || !reverseDecision || !connectionClosed || !housekeepingDispose || !housekeepingDelete {
		t.Fatalf("missing audit transitions: authentication=%v pty=%v agent=%v reverse=%v connection=%v dispose=%v delete=%v",
			authentication, pty, agentForwarding, reverseDecision, connectionClosed, housekeepingDispose, housekeepingDelete)
	}
	var execWithExpectedExit, sftpCompleted bool
	for operationId, started := range taskStarts {
		completed, ok := taskCompletions[operationId]
		if !ok {
			t.Fatalf("task %s (%s) has no completion", operationId, started.SessionTask)
		}
		if completed.Flow != started.Flow || completed.ConnectionId != started.ConnectionId || completed.SessionId != started.SessionId || completed.SessionTask != started.SessionTask {
			t.Fatalf("task %s correlation mismatch: start=%#v completion=%#v", operationId, started, completed)
		}
		if completed.SessionTask == "exec" && completed.Outcome == "success" && completed.ExitCode != nil && *completed.ExitCode == 23 {
			execWithExpectedExit = true
		}
		if completed.SessionTask == "sftp" && completed.Outcome == "success" {
			sftpCompleted = true
		}
	}
	if !execWithExpectedExit || !sftpCompleted {
		t.Fatalf("missing completed task audit: exec=%v sftp=%v", execWithExpectedExit, sftpCompleted)
	}
	directTransferred := false
	for operationId, completed := range directCompletions {
		decision, decisionOk := directDecisions[operationId]
		started, startedOk := directStarts[operationId]
		if !decisionOk || !startedOk {
			continue
		}
		if decision.ConnectionId != started.ConnectionId || started.ConnectionId != completed.ConnectionId ||
			decision.SessionId != started.SessionId || started.SessionId != completed.SessionId {
			t.Fatalf("direct forwarding %s correlation mismatch", operationId)
		}
		if completed.Outcome == "success" && completed.BytesRead != nil && *completed.BytesRead > 0 &&
			completed.BytesWritten != nil && *completed.BytesWritten > 0 && completed.DurationMillis != nil {
			directTransferred = true
		}
	}
	if !directTransferred {
		t.Fatal("no complete audited direct-forwarding transfer found")
	}

	privacyMarkers := []string{
		"audit-secret-command-argument",
		"BIFROEST_E2E_ARGV_SECRET",
		"target-environment-must-not-be-in-wrapper-argv",
		"audit-secret-upload.tmp",
		"audit-secret-renamed.bin",
		"docker-sftp-e2e",
		"xterm-256color",
		"127.0.0.1:31001",
		publicKeyBlob(t, f.clientKey+".pub"),
		publicKeyBlob(t, f.agentKey+".pub"),
	}
	for _, marker := range privacyMarkers {
		if marker != "" && strings.Contains(redacted, marker) {
			t.Fatalf("audit export contains private marker %q", marker)
		}
	}
}

func decodeExportedAuditRecords(t *testing.T, payload string) []exportedAuditRecord {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(payload))
	var result []exportedAuditRecord
	for {
		var record exportedAuditRecord
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			return result
		} else if err != nil {
			t.Fatalf("decode audit export: %v\npayload:\n%s", err, payload)
		}
		result = append(result, record)
	}
}

func publicKeyBlob(t *testing.T, path string) string {
	t.Helper()
	fields := strings.Fields(string(mustRead(path)))
	if len(fields) < 2 {
		t.Fatalf("public key file %s is malformed", path)
	}
	return fields[1]
}

func newDockerEnvironmentFixture(t *testing.T) (*fixture, error) {
	t.Helper()
	return newDockerEnvironmentFixtureWithRecording(t, false)
}

func newDockerEnvironmentRecordingFixture(t *testing.T) (*fixture, error) {
	t.Helper()
	return newDockerEnvironmentFixtureWithRecording(t, true)
}

func newDockerEnvironmentFixtureWithRecording(t *testing.T, recording bool) (*fixture, error) {
	t.Helper()
	f, err := newFixture(t)
	if err != nil {
		return f, err
	}
	if err := f.prepareRuntime(true); err != nil {
		return f, err
	}
	publicKey := strings.TrimSpace(string(mustRead(f.clientKey + ".pub")))
	if err := os.WriteFile(f.clientKey+".pub", []byte(`environment="PATH=/opt/bifroest-target/bin:/usr/local/bin" `+publicKey+"\n"), 0600); err != nil {
		return f, fmt.Errorf("add target PATH to authorized key: %w", err)
	}
	f.flowName = f.name
	f.networkName = f.name + "-network"

	result := f.runtime(20*time.Second, "network", "create", "--label", "org.engity.bifroest/e2e-run="+f.name, f.networkName)
	if result.err != nil {
		return f, fmt.Errorf("create dedicated network: %w\n%s", result.err, result.stderr)
	}
	f.networkID = strings.TrimSpace(result.stdout)
	if f.networkID == "" {
		return f, errors.New("runtime returned an empty network ID")
	}

	contextDir := filepath.Join(f.tempDir, "docker-environment-context")
	if err := os.MkdirAll(contextDir, 0755); err != nil {
		return f, err
	}
	files := map[string]struct {
		content []byte
		mode    os.FileMode
	}{
		"Containerfile": {[]byte(dockerEnvironmentContainerfile), 0644},
		"e2e-helper":    {mustRead(f.helper), 0755},
	}
	for name, file := range files {
		if err := os.WriteFile(filepath.Join(contextDir, name), file.content, file.mode); err != nil {
			return f, fmt.Errorf("write target image context file %s: %w", name, err)
		}
	}
	if err := f.buildImage(contextDir); err != nil {
		return f, err
	}
	if recording {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		result := runCommand(ctx, f.repoRoot, nil, f.bifroest, "key", "generate", "--identityFile", filepath.Join(f.tempDir, "auditlog-key"))
		cancel()
		if result.err != nil {
			return f, fmt.Errorf("generate audit identity: %w\n%s", result.err, result.stderr)
		}
		f.recordingProducerID = recordingProducerID(t, filepath.Join(f.tempDir, "auditlog-key"))
	}
	if err := f.startHostBifroest(recording); err != nil {
		return f, err
	}
	return f, nil
}

func (f *fixture) startHostBifroest(recording bool) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("reserve SSH listen port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	f.port = strconv.Itoa(port)

	if err := os.MkdirAll(f.sessionStorage, 0700); err != nil {
		_ = listener.Close()
		return err
	}
	configurationPath := filepath.Join(f.tempDir, "docker-environment.yaml")
	recordingConfiguration := ""
	if recording {
		recordingConfiguration = fmt.Sprintf(`    recording:
      enabled: true
      directory: %s
      maximumSpoolBytes: 16777216
      retainFor: 1h
      targets: false
`, yamlString(filepath.Join(f.tempDir, "recordings")))
	}
	configuration := fmt.Sprintf(dockerEnvironmentConfiguration,
		yamlString(filepath.Join(f.tempDir, "auditlog-key")),
		yamlString(filepath.Join(f.tempDir, "auditlog")),
		recordingConfiguration,
		yamlString(net.JoinHostPort(f.host, f.port)),
		yamlString(f.hostKey),
		yamlString(f.sessionStorage),
		yamlString(f.flowName),
		yamlString(f.clientKey+".pub"),
		yamlString(f.runtimeHost),
		yamlString(f.imageName),
		yamlString(f.networkName),
	)
	if err := os.WriteFile(configurationPath, []byte(configuration), 0600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("write Docker environment configuration: %w", err)
	}
	if err := f.writeKnownHosts(); err != nil {
		_ = listener.Close()
		return err
	}

	pathEnv := "PATH=" + filepath.Dir(f.goTool) + string(os.PathListSeparator) + os.Getenv("PATH")
	if err := listener.Close(); err != nil {
		return err
	}
	f.bifroestProc, err = f.launchLoggedProcess("bifroest", []string{pathEnv, "CGO_ENABLED=0"}, f.bifroest,
		"run", "--configuration="+configurationPath, "--log.level=DEBUG")
	if err != nil {
		return fmt.Errorf("start host Bifroest: %w", err)
	}
	if err := pollProcess(20*time.Second, f.bifroestProc, func() error {
		return probeSSHIdentification(f.host, f.port)
	}); err != nil {
		return fmt.Errorf("wait for host Bifroest: %w", err)
	}
	return nil
}

func (f *fixture) waitForEnvironmentContainer() error {
	return poll(20*time.Second, func() error {
		ids, err := f.containerIDs()
		if err != nil {
			return err
		}
		if len(ids) != 1 {
			return fmt.Errorf("got %d environment containers, want one: %v", len(ids), ids)
		}
		result := f.runtime(5*time.Second, "container", "inspect", "--format", "{{.State.Running}}", ids[0])
		if result.err != nil {
			return result.err
		}
		if strings.TrimSpace(result.stdout) != "true" {
			return fmt.Errorf("environment container is not running: %q", result.stdout)
		}
		f.containerID = ids[0]
		return nil
	})
}

func parseEnvironmentIDs(t *testing.T, output string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed environment ID line %q", line)
		}
		result[key] = value
	}
	return result
}

const dockerEnvironmentContainerfile = `FROM ` + alpineImage + `
ENV BIFROEST_IMAGE_VALUE=from-image BIFROEST_OVERRIDE_VALUE=from-image
COPY e2e-helper /usr/local/bin/e2e-helper
RUN addgroup -S -g 10001 e2e \
	&& addgroup -S -g 10002 supplemental \
	&& adduser -S -D -u 10001 -G e2e -h /home/e2e -s /bin/sh e2e \
	&& addgroup e2e supplemental \
	&& chmod 0755 /usr/local/bin/e2e-helper \
	&& mkdir -p /opt/bifroest-target/bin \
	&& printf '#!/bin/sh\nexec /bin/sh "$@"\n' > /opt/bifroest-target/bin/target-sh \
	&& chmod 0755 /opt/bifroest-target/bin/target-sh \
	&& ln -s /usr/bin/bifroest /opt/bifroest-target/bin/target-bifroest
USER 10001:10001
WORKDIR /home/e2e
`

const dockerEnvironmentConfiguration = `startMessage: '{{""}}'
housekeeping:
  every: 500ms
  initialDelay: 100ms
  autoRepair: true
  keepExpiredFor: 0s
auditlog:
  - enabled: true
    identityFile: %s
    directory: %s
%s
ssh:
  addresses:
    - %s
  keys:
    hostKeys:
      - %s
    rememberMeNotification: '{{""}}'
  banner: '{{""}}'
  idleTimeout: 30s
  maxTimeout: 3m
  gracefulShutdownTimeout: 3s
  handshakeTimeout: 5s
  sessionRequestTimeout: 2m
session:
  type: fs
  storage: %s
  idleTimeout: 20s
  maxTimeout: 3m
  maxConnections: 16
flows:
  - name: %s
    authorization:
      type: simple
      entries:
        - name: e2e
          authorizedKeysFile: %s
    environment:
      type: docker
      host: %s
      apiVersion: "1.41"
      image: %s
      imagePullPolicy: never
      shellCommand: [target-sh]
      execCommand: [target-sh, -c]
      sftpCommand: [target-bifroest, sftp-server]
      networks:
        - %s
      directory: "/home/e2e"
      banner: '{{""}}'
      portForwardingAllowed: true
      impPublishHost: "127.0.0.1"
      cleanOrphan: false
`
