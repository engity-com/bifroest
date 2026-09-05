//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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
		result := f.ssh(3*time.Minute, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "streams")
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

	// This must remain final: the session and its only environment are expected to disappear.
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
}

func newDockerEnvironmentFixture(t *testing.T) (*fixture, error) {
	t.Helper()
	f, err := newFixture(t)
	if err != nil {
		return f, err
	}
	if err := f.prepareRuntime(true); err != nil {
		return f, err
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
	if err := f.startHostBifroest(); err != nil {
		return f, err
	}
	return f, nil
}

func (f *fixture) startHostBifroest() error {
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
	configuration := fmt.Sprintf(dockerEnvironmentConfiguration,
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
	f.bifroestProc, err = launchProcess(f.repoRoot, []string{pathEnv, "CGO_ENABLED=0"}, f.bifroest,
		"run", "--configuration="+configurationPath, "--log.level=DEBUG")
	if err != nil {
		return fmt.Errorf("start host Bifroest: %w", err)
	}
	if err := pollProcess(20*time.Second, f.bifroestProc, func() error {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(f.host, f.port), 500*time.Millisecond)
		if err != nil {
			return err
		}
		return conn.Close()
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
	&& chmod 0755 /usr/local/bin/e2e-helper
USER 10001:10001
WORKDIR /home/e2e
`

const dockerEnvironmentConfiguration = `startMessage: '{{""}}'
housekeeping:
  every: 500ms
  initialDelay: 100ms
  autoRepair: true
  keepExpiredFor: 0s
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
      networks:
        - %s
      directory: "/home/e2e"
      banner: '{{""}}'
      portForwardingAllowed: true
      impPublishHost: "127.0.0.1"
      cleanOrphan: false
`
