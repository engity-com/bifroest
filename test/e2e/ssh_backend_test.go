//go:build e2e

package e2e_test

import (
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

type sshEnvironmentFixture struct {
	*fixture
	targetPort            string
	targetIdentity        string
	wrongTargetKnownHosts string
}

func TestOpenSSHSSHEnvironmentSessionRecording(t *testing.T) {
	f, err := newSSHEnvironmentRecordingFixture(t)
	if errors.Is(err, errNoRuntime) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime=%s targetPort=%s container=%s port=%s producer=%s", f.runtimeCLI, f.targetPort, f.containerID, f.port, f.recordingProducerID)

	result := f.ssh(30*time.Second, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "streams")
	if code := exitCode(result.err); code != 23 {
		t.Fatalf("recorded command exit code: got %d, want 23 (error: %v)\nstdout:\n%s\nstderr:\n%s", code, result.err, result.stdout, result.stderr)
	}
	if result.stdout != "stdout-e2e\n" || result.stderr != "stderr-e2e\n" {
		t.Fatalf("recorded command output: stdout=%q stderr=%q", result.stdout, result.stderr)
	}
	running := f.runtime(5*time.Second, "container", "inspect", "--format", "{{.State.Running}}", f.containerID)
	if running.err != nil || strings.TrimSpace(running.stdout) != "true" {
		t.Fatalf("SSH target container is not running: error=%v stdout=%q stderr=%q", running.err, running.stdout, running.stderr)
	}

	artifact := sealedSessionRecordingArtifact(t, filepath.Join(f.tempDir, "recordings"))
	stopHostBifroest(t, f.fixture)
	if finalArtifact := sealedSessionRecordingArtifact(t, filepath.Join(f.tempDir, "recordings")); finalArtifact != artifact {
		t.Fatalf("sealed recording changed during shutdown: before=%q after=%q", artifact, finalArtifact)
	}
	verifySessionRecordingArtifact(t, f.fixture, artifact, f.recordingProducerID)

	if err := f.startSSHEnvironmentBifroest(f.targetPort, f.wrongTargetKnownHosts, f.targetIdentity, false); err != nil {
		t.Fatal(err)
	}
	rejected := f.ssh(30*time.Second, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "ready")
	if rejected.err == nil {
		t.Fatalf("SSH environment accepted an untrusted target host key: stdout=%q stderr=%q", rejected.stdout, rejected.stderr)
	}
	stopHostBifroest(t, f.fixture)
	if finalArtifact := sealedSessionRecordingArtifact(t, filepath.Join(f.tempDir, "recordings")); finalArtifact != artifact {
		t.Fatalf("recording changed during rejected target connection: before=%q after=%q", artifact, finalArtifact)
	}
}

func newSSHEnvironmentRecordingFixture(t *testing.T) (*sshEnvironmentFixture, error) {
	t.Helper()
	f, err := newFixture(t)
	if err != nil {
		return nil, err
	}
	s := &sshEnvironmentFixture{fixture: f}
	if err := f.prepareRuntime(false); err != nil {
		return s, err
	}

	targetHostKey := filepath.Join(f.tempDir, "target_host_ed25519")
	targetIdentity := filepath.Join(f.tempDir, "target_identity")
	wrongTargetHostKey := filepath.Join(f.tempDir, "wrong_target_host_ed25519")
	auditIdentity := filepath.Join(f.tempDir, "auditlog-key")
	for _, path := range []string{targetHostKey, targetIdentity, wrongTargetHostKey, auditIdentity} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		result := runCommand(ctx, f.repoRoot, nil, f.bifroest, "key", "generate", "--identityFile", path, "--publicFile", path+".pub")
		cancel()
		if result.err != nil {
			return s, fmt.Errorf("generate %s: %w\n%s", filepath.Base(path), result.err, result.stderr)
		}
	}
	f.recordingProducerID = recordingProducerID(t, auditIdentity)

	targetPort, targetKnownHosts, err := f.prepareSSHEnvironmentTarget(targetHostKey, targetIdentity)
	if err != nil {
		return s, err
	}
	wrongTargetKnownHosts := filepath.Join(f.tempDir, "wrong_target_known_hosts")
	if err := writeSSHEnvironmentKnownHosts(wrongTargetKnownHosts, f.host, targetPort, wrongTargetHostKey+".pub"); err != nil {
		return s, err
	}
	s.targetPort = targetPort
	s.targetIdentity = targetIdentity
	s.wrongTargetKnownHosts = wrongTargetKnownHosts
	if err := f.startSSHEnvironmentBifroest(targetPort, targetKnownHosts, targetIdentity, true); err != nil {
		return s, err
	}
	return s, nil
}

func (f *fixture) prepareSSHEnvironmentTarget(hostKey, identity string) (string, string, error) {
	contextDir := filepath.Join(f.tempDir, "ssh-target-context")
	if err := os.MkdirAll(contextDir, 0755); err != nil {
		return "", "", err
	}
	files := map[string]struct {
		content []byte
		mode    os.FileMode
	}{
		"Containerfile":        {[]byte(localContainerfile), 0644},
		"bifroest":             {mustRead(f.bifroest), 0755},
		"e2e-helper":           {mustRead(f.helper), 0755},
		"configuration.yaml":   {[]byte(localConfiguration), 0644},
		"ssh_host_ed25519_key": {mustRead(hostKey), 0600},
		"authorized_keys":      {mustRead(identity + ".pub"), 0644},
	}
	for name, file := range files {
		if err := os.WriteFile(filepath.Join(contextDir, name), file.content, file.mode); err != nil {
			return "", "", fmt.Errorf("write SSH target context file %s: %w", name, err)
		}
	}
	if err := f.buildImage(contextDir); err != nil {
		return "", "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	result := runCommand(ctx, f.repoRoot, nil, f.runtimeCLI, "run", "--detach", "--name", f.name, "--publish", "127.0.0.1::2222", "--security-opt=no-new-privileges", f.imageName)
	cancel()
	if result.err != nil {
		return "", "", fmt.Errorf("start SSH target container: %w\n%s", result.err, result.stderr)
	}
	f.containerID = strings.TrimSpace(result.stdout)

	var port string
	if err := poll(20*time.Second, func() error {
		result := f.runtime(3*time.Second, "port", f.containerID, "2222/tcp")
		if result.err != nil {
			return result.err
		}
		for _, line := range strings.Split(strings.TrimSpace(result.stdout), "\n") {
			host, candidate, err := net.SplitHostPort(strings.TrimSpace(line))
			if err == nil && (host == f.host || host == "0.0.0.0" || host == "::") {
				port = candidate
				return nil
			}
		}
		return fmt.Errorf("runtime did not report an IPv4 published port: %q", result.stdout)
	}); err != nil {
		return "", "", fmt.Errorf("resolve SSH target port: %w", err)
	}
	if err := poll(25*time.Second, func() error { return probeSSHIdentification(f.host, port) }); err != nil {
		return "", "", fmt.Errorf("wait for SSH target readiness: %w", err)
	}

	knownHosts := filepath.Join(f.tempDir, "target_known_hosts")
	if err := writeSSHEnvironmentKnownHosts(knownHosts, f.host, port, hostKey+".pub"); err != nil {
		return "", "", err
	}
	return port, knownHosts, nil
}

func writeSSHEnvironmentKnownHosts(path, host, port, publicKeyPath string) error {
	publicKey := strings.Fields(string(mustRead(publicKeyPath)))
	if len(publicKey) < 2 {
		return errors.New("generated SSH target host public key is malformed")
	}
	entry := fmt.Sprintf("[%s]:%s %s %s\n", host, port, publicKey[0], publicKey[1])
	return os.WriteFile(path, []byte(entry), 0600)
}

func (f *fixture) startSSHEnvironmentBifroest(targetPort, targetKnownHosts, targetIdentity string, recording bool) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("reserve SSH listen port: %w", err)
	}
	f.port = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if err := os.MkdirAll(f.sessionStorage, 0700); err != nil {
		_ = listener.Close()
		return err
	}
	configurationPath := filepath.Join(f.tempDir, "ssh-environment.yaml")
	auditlogConfiguration := ""
	if recording {
		auditlogConfiguration = fmt.Sprintf(`auditlog:
  - name: default
    enabled: true
    identityFile: %s
    journal:
      directory: %s
      minimumFreeBytes: 1048576
    recording:
      enabled: true
      directory: %s
      maximumSpoolBytes: 16777216
      retainFor: 1h
      targets: false
`, yamlString(filepath.Join(f.tempDir, "auditlog-key")), yamlString(filepath.Join(f.tempDir, "auditlog")), yamlString(filepath.Join(f.tempDir, "recordings")))
	}
	configuration := fmt.Sprintf(sshEnvironmentRecordingConfiguration,
		auditlogConfiguration,
		yamlString(net.JoinHostPort(f.host, f.port)), yamlString(f.hostKey), yamlString(f.sessionStorage), yamlString(f.clientKey+".pub"),
		yamlString(net.JoinHostPort(f.host, targetPort)), yamlString(targetKnownHosts), yamlString(targetIdentity),
	)
	if err := os.WriteFile(configurationPath, []byte(configuration), 0600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("write SSH environment configuration: %w", err)
	}
	if err := f.writeKnownHosts(); err != nil {
		_ = listener.Close()
		return err
	}
	if err := listener.Close(); err != nil {
		return err
	}
	f.bifroestProc, err = f.launchLoggedProcess("bifroest", []string{"CGO_ENABLED=0"}, f.bifroest,
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

const sshEnvironmentRecordingConfiguration = `startMessage: '{{""}}'
housekeeping:
  every: 500ms
  initialDelay: 100ms
  autoRepair: true
  keepExpiredFor: 0s
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
  maxTimeout: 2m
  gracefulShutdownTimeout: 3s
  handshakeTimeout: 5s
  sessionRequestTimeout: 30s
session:
  type: fs
  storage: %s
  idleTimeout: 2m
  maxTimeout: 5m
  maxConnections: 4
flows:
  - name: ssh
    auditlog: default
    authorization:
      type: simple
      entries:
        - name: e2e
          authorizedKeysFile: %s
    environment:
      type: ssh
      address: %s
      user: e2e
      knownHostsFile: %s
      identityFiles:
        - %s
      connectTimeout: 10s
      banner: '{{""}}'
      portForwardingAllowed: false
`
