//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestOpenSSHLocalBackend(t *testing.T) {
	f, err := newLocalFixture(t)
	if errors.Is(err, errNoRuntime) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime=%s container=%s port=%s", f.runtimeCLI, f.containerID, f.port)

	t.Run("public key login and local identity", func(t *testing.T) {
		result := f.ssh(10*time.Second, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "identity")
		if result.err != nil {
			t.Fatalf("SSH identity failed: %v\nstderr:\n%s", result.err, result.stderr)
		}
		actual := make(map[string]string)
		for _, line := range strings.Split(strings.TrimSpace(result.stdout), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("malformed identity line %q", line)
			}
			actual[key] = value
		}
		expected := map[string]string{
			"uid":   "10001",
			"name":  "e2e",
			"pwd":   "/home/e2e",
			"HOME":  "/home/e2e",
			"USER":  "e2e",
			"SHELL": "/bin/sh",
		}
		for key, value := range expected {
			if actual[key] != value {
				t.Errorf("%s: got %q, want %q", key, actual[key], value)
			}
		}
	})

	t.Run("stdout stderr and exit status", func(t *testing.T) {
		result := f.ssh(10*time.Second, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "streams")
		if code := exitCode(result.err); code != 23 {
			t.Fatalf("exit code: got %d, want 23 (error: %v)", code, result.err)
		}
		if result.stdout != "stdout-e2e\n" {
			t.Errorf("stdout: got %q", result.stdout)
		}
		if result.stderr != "stderr-e2e\n" {
			t.Errorf("stderr: got %q", result.stderr)
		}
	})

	t.Run("wrong key is rejected", func(t *testing.T) {
		result := f.ssh(10*time.Second, f.wrongKey, "e2e", nil, "/usr/local/bin/e2e-helper", "ready")
		if result.err == nil {
			t.Fatalf("login unexpectedly succeeded: %s", result.stdout)
		}
	})

	t.Run("unknown user is rejected", func(t *testing.T) {
		result := f.ssh(10*time.Second, f.clientKey, "missing-e2e-user", nil, "/usr/local/bin/e2e-helper", "ready")
		if result.err == nil {
			t.Fatalf("login unexpectedly succeeded: %s", result.stdout)
		}
	})

	t.Run("PTY allocation", func(t *testing.T) {
		result := f.sshWithEnv(10*time.Second, []string{"TERM=xterm-256color"}, f.clientKey, "e2e", []string{"-tt"}, "/usr/local/bin/e2e-helper", "pty")
		if result.err != nil {
			t.Fatalf("PTY command failed: %v\nstdout:\n%s\nstderr:\n%s", result.err, result.stdout, result.stderr)
		}
		output := strings.ReplaceAll(strings.TrimSpace(result.stdout), "\r", "")
		if output != "pty=true term=xterm-256color" {
			t.Fatalf("unexpected PTY output %q", output)
		}
	})

	runBackendProtocolTests(t, f, 30*time.Second, func(t *testing.T) {
		ensureContainerEchoServer(t, f)
	})

	t.Run("native SFTP lifecycle", func(t *testing.T) {
		source := filepath.Join(t.TempDir(), "source.bin")
		download := filepath.Join(t.TempDir(), "download.bin")
		payload := bytes.Repeat([]byte("native-sftp-e2e\x00"), 4096)
		if err := os.WriteFile(source, payload, 0600); err != nil {
			t.Fatal(err)
		}
		batch := filepath.Join(t.TempDir(), "batch")
		commands := fmt.Sprintf("put %s upload.tmp\nrename upload.tmp renamed.bin\nget renamed.bin %s\nrm renamed.bin\n", source, download)
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
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		result = f.ssh(10*time.Second, f.clientKey, "e2e", nil, "test ! -e /home/e2e/renamed.bin -a ! -e /home/e2e/upload.tmp")
		if result.err != nil {
			t.Fatalf("remote SFTP cleanup check failed: %v", result.err)
		}
	})

	t.Run("ssh -L bidirectional transfer", func(t *testing.T) {
		ensureContainerEchoServer(t, f)
		socket := filepath.Join(t.TempDir(), "local-forward.sock")
		forward := startSSH(t, f, nil, []string{"-N", "-o", "ExitOnForwardFailure=yes", "-L", fmt.Sprintf("%s:127.0.0.1:%d", socket, echoPort)}, nil)
		defer forward.stop()
		if err := pollProcess(10*time.Second, forward, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			result := runCommand(ctx, f.repoRoot, nil, f.helper, "echo-client", "unix", socket, "262144")
			if result.err != nil {
				return fmt.Errorf("%w: %s", result.err, result.stderr)
			}
			if result.stdout != "ok 262144\n" {
				return fmt.Errorf("unexpected output %q", result.stdout)
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
		if err := pollProcess(10*time.Second, forward, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
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

	t.Run("ssh -R bidirectional transfer", func(t *testing.T) {
		hostEcho, address := startEchoServer(t, f.helper)
		defer hostEcho.stop()
		forward := startSSH(t, f, nil, []string{
			"-N", "-o", "ExitOnForwardFailure=yes",
			"-R", fmt.Sprintf("127.0.0.1:%d:%s", reversePort, address),
		}, nil)
		defer forward.stop()
		if err := pollProcess(10*time.Second, forward, func() error {
			result := f.runtime(5*time.Second, "exec", f.containerID, "/usr/local/bin/e2e-helper", "echo-client", "tcp", fmt.Sprintf("127.0.0.1:%d", reversePort), "262144")
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
		result = f.sshWithEnv(10*time.Second, env, f.clientKey, "e2e", []string{"-A"}, "/usr/local/bin/e2e-helper", "agent-keys")
		if result.err != nil {
			t.Fatalf("agent forwarding failed: %v\nstderr:\n%s", result.err, result.stderr)
		}
		if got, want := normalizePublicKey(result.stdout), normalizePublicKey(string(mustRead(f.agentKey+".pub"))); got != want {
			t.Fatalf("forwarded keys: got %q, want %q", got, want)
		}
	})

	t.Run("abrupt client disconnect", func(t *testing.T) {
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
		if err := poll(8*time.Second, func() error {
			result := f.runtime(3*time.Second, "exec", f.containerID, "/usr/local/bin/e2e-helper", "process-alive", pidFile)
			if result.err == nil {
				return errors.New("remote process is still alive")
			}
			if exitCode(result.err) == 1 {
				return nil
			}
			return fmt.Errorf("cannot inspect remote process: %w: %s", result.err, result.stderr)
		}); err != nil {
			t.Fatal(err)
		}
	})

	// This must remain the final subtest because it deliberately stops Bifroest.
	t.Run("SIGTERM container stop with active connection", func(t *testing.T) {
		pidFile := "/tmp/bifroest-e2e-shutdown.pid"
		connection := startSSH(t, f, nil, nil, []string{"/usr/local/bin/e2e-helper", "wait-for-stop", pidFile})
		if err := waitForRemoteProcess(f, connection, pidFile); err != nil {
			connection.stop()
			t.Fatal(err)
		}
		result := f.runtime(12*time.Second, "stop", "--time", "5", f.containerID)
		if result.err != nil {
			connection.stop()
			t.Fatalf("container stop failed: %v\n%s", result.err, result.stderr)
		}
		if err := connection.wait(8 * time.Second); err == nil {
			t.Fatal("active SSH connection unexpectedly exited with status zero")
		} else if errors.Is(err, context.DeadlineExceeded) {
			connection.stop()
			t.Fatal("active SSH connection did not terminate after container stop")
		}
		result = f.runtime(5*time.Second, "container", "inspect", "--format", "{{.State.Running}}", f.containerID)
		if result.err != nil {
			t.Fatalf("inspect stopped container: %v\n%s", result.err, result.stderr)
		}
		if strings.TrimSpace(result.stdout) != "false" {
			t.Fatalf("container is still running: %q", result.stdout)
		}
	})
}

func TestOpenSSHLocalSessionRecording(t *testing.T) {
	f, err := newFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.prepareRuntime(false); errors.Is(err, errNoRuntime) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}

	auditIdentity := filepath.Join(f.tempDir, "audit_identity")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	result := runCommand(ctx, f.repoRoot, nil, f.bifroest, "key", "generate", "--identityFile", auditIdentity)
	cancel()
	if result.err != nil {
		t.Fatalf("generate audit identity: %v\nstderr:\n%s", result.err, result.stderr)
	}
	privateKey, err := bfcrypto.LoadSecurePrivateKeyFile(auditIdentity, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := audit.NewIdentity(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	producerID := identity.ProducerId().String()

	if err := f.prepareLocalRecording(auditIdentity); err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime=%s container=%s port=%s producer=%s", f.runtimeCLI, f.containerID, f.port, producerID)

	result = f.ssh(10*time.Second, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "streams")
	if code := exitCode(result.err); code != 23 {
		t.Fatalf("recorded command exit code: got %d, want 23 (error: %v)\nstderr:\n%s", code, result.err, result.stderr)
	}
	if result.stdout != "stdout-e2e\n" || result.stderr != "stderr-e2e\n" {
		t.Fatalf("recorded command output: stdout=%q stderr=%q", result.stdout, result.stderr)
	}

	result = f.runtime(5*time.Second, "exec", f.containerID, "/bin/sh", "-c", "find /var/lib/bifroest/recordings/sealed -maxdepth 1 -type f -name '*.cast.zst' -print")
	if result.err != nil {
		t.Fatalf("locate sealed recording: %v\nstderr:\n%s", result.err, result.stderr)
	}
	artifacts := strings.Fields(result.stdout)
	if len(artifacts) != 1 {
		t.Fatalf("sealed recordings: got %d, want 1: %q", len(artifacts), result.stdout)
	}

	result = f.runtime(12*time.Second, "stop", "--time", "5", f.containerID)
	if result.err != nil {
		t.Fatalf("stop recording container: %v\nstderr:\n%s", result.err, result.stderr)
	}
	artifact := filepath.Join(f.tempDir, "session.cast.zst")
	result = f.runtime(10*time.Second, "cp", f.containerID+":"+artifacts[0], artifact)
	if result.err != nil {
		t.Fatalf("copy sealed recording: %v\nstderr:\n%s", result.err, result.stderr)
	}

	wrongProducerID := strings.Repeat("f", 64)
	if wrongProducerID == producerID {
		wrongProducerID = strings.Repeat("e", 64)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	result = runCommand(ctx, f.repoRoot, nil, f.bifroest, "recording", "inspect", "--expectedProducerId", wrongProducerID, artifact)
	cancel()
	if result.err == nil || result.stdout != "" {
		t.Fatalf("inspection with wrong producer did not fail closed: error=%v stdout=%q", result.err, result.stdout)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	result = runCommand(ctx, f.repoRoot, nil, f.bifroest, "recording", "inspect", "--expectedProducerId", producerID, artifact)
	cancel()
	if result.err != nil {
		t.Fatalf("inspect sealed recording: %v\nstderr:\n%s", result.err, result.stderr)
	}
	var inspection struct {
		Schema            string `json:"schema"`
		Format            string `json:"format"`
		VerificationScope string `json:"verificationScope"`
		ProducerID        string `json:"producerId"`
		Status            string `json:"status"`
		Signature         struct {
			Valid   bool `json:"valid"`
			Trusted bool `json:"trusted"`
		} `json:"signature"`
		Cast *struct {
			ExitStatus   *uint32 `json:"exitStatus"`
			OutputEvents uint64  `json:"outputEvents"`
		} `json:"cast"`
	}
	if err := json.Unmarshal([]byte(result.stdout), &inspection); err != nil {
		t.Fatalf("decode recording inspection: %v\noutput:\n%s", err, result.stdout)
	}
	if inspection.Schema != "bifroest.session-recording-inspection/v1" || inspection.Format != "cast-zstd/v1" || inspection.VerificationScope != "full" {
		t.Fatalf("unexpected recording inspection: schema=%q format=%q scope=%q", inspection.Schema, inspection.Format, inspection.VerificationScope)
	}
	if inspection.ProducerID != producerID || !inspection.Signature.Valid || !inspection.Signature.Trusted {
		t.Fatalf("untrusted recording inspection: producer=%q valid=%v trusted=%v", inspection.ProducerID, inspection.Signature.Valid, inspection.Signature.Trusted)
	}
	if inspection.Status != "completed" || inspection.Cast == nil || inspection.Cast.ExitStatus == nil || *inspection.Cast.ExitStatus != 23 || inspection.Cast.OutputEvents == 0 {
		t.Fatalf("unexpected recorded result: status=%q cast=%+v", inspection.Status, inspection.Cast)
	}

	exported := filepath.Join(f.tempDir, "session.cast")
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	result = runCommand(ctx, f.repoRoot, nil, f.bifroest, "recording", "export", "--expectedProducerId", producerID, "--output", exported, artifact)
	cancel()
	if result.err != nil {
		t.Fatalf("export sealed recording: %v\nstderr:\n%s", result.err, result.stderr)
	}
	cast, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{[]byte("stdout-e2e"), []byte("stderr-e2e")} {
		if !bytes.Contains(cast, expected) {
			t.Errorf("exported Cast does not contain %q", expected)
		}
	}
}

func ensureContainerEchoServer(t *testing.T, f *fixture) {
	t.Helper()
	result := f.runtime(5*time.Second, "exec", "--detach", f.containerID, "/usr/local/bin/e2e-helper", "echo-server", "tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if result.err == nil {
		return
	}
	probe := f.runtime(4*time.Second, "exec", f.containerID, "/usr/local/bin/e2e-helper", "echo-client", "tcp", fmt.Sprintf("127.0.0.1:%d", echoPort), "16")
	if probe.err != nil {
		t.Fatalf("start container echo server: %v\n%s", result.err, result.stderr)
	}
}

func startEchoServer(t *testing.T, helper string) (*runningProcess, string) {
	t.Helper()
	p := &runningProcess{cmd: exec.Command(helper, "echo-server", "tcp", "127.0.0.1:0"), done: make(chan struct{})}
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p.cmd.Stderr = &p.stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := p.cmd.Wait()
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
	}()
	line := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			line <- scanner.Text()
			return
		}
		line <- ""
	}()
	select {
	case address := <-line:
		if _, _, err := net.SplitHostPort(address); err != nil {
			p.stop()
			t.Fatalf("invalid echo server address %q: %v", address, err)
		}
		return p, address
	case <-time.After(5 * time.Second):
		p.stop()
		t.Fatal("echo server did not report its address")
		return nil, ""
	}
}

func waitForRemoteProcess(f *fixture, connection *runningProcess, pidFile string) error {
	return pollProcess(8*time.Second, connection, func() error {
		result := f.runtime(3*time.Second, "exec", f.containerID, "/usr/local/bin/e2e-helper", "process-alive", pidFile)
		if result.err != nil {
			return result.err
		}
		return nil
	})
}
