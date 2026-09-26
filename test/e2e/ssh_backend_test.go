//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
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

	if err := f.startSSHEnvironmentBifroest(f.targetPort, f.wrongTargetKnownHosts, f.targetIdentity, false, ""); err != nil {
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

func TestOpenSSHSSHEnvironmentSubsystem(t *testing.T) {
	f, err := newFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.prepareRuntime(false); errors.Is(err, errNoRuntime) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}

	targetHostKey := filepath.Join(f.tempDir, "target_host_ed25519")
	targetIdentity := filepath.Join(f.tempDir, "target_identity")
	for _, path := range []string{targetHostKey, targetIdentity} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		result := runCommand(ctx, f.repoRoot, nil, f.bifroest, "key", "generate", "--identityFile", path, "--publicFile", path+".pub")
		cancel()
		if result.err != nil {
			t.Fatalf("generate %s: %v\n%s", filepath.Base(path), result.err, result.stderr)
		}
	}
	targetPort, targetKnownHosts, err := f.prepareSSHEnvironmentTargetWithContainerfile(targetHostKey, targetIdentity, openSSHSubsystemContainerfile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	direct := runCommand(ctx, f.repoRoot, nil, f.tools["ssh"],
		"-F", "/dev/null", "-T", "-s", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
		"-o", "IdentityFile="+targetIdentity, "-o", "UserKnownHostsFile="+targetKnownHosts,
		"-o", "StrictHostKeyChecking=yes", "-p", targetPort, "e2e@"+f.host, "netconf")
	cancel()
	if code := exitCode(direct.err); code != 23 || direct.stdout != "stdout-e2e\n" {
		t.Fatalf("direct OpenSSH target subsystem: exit=%d (error: %v), stdout=%q, stderr=%q", code, direct.err, direct.stdout, direct.stderr)
	}
	if err := f.startSSHEnvironmentBifroest(targetPort, targetKnownHosts, targetIdentity, false, ""); err != nil {
		t.Fatal(err)
	}
	defaultClient := f.newSSHClient(t, 30*time.Second)
	defaultSession, err := defaultClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := defaultSession.RequestSubsystem("netconf"); err == nil {
		t.Fatal("Bifroest forwarded netconf without an explicit allowlist")
	}
	_ = defaultSession.Close()
	_ = defaultClient.Close()
	stopHostBifroest(t, f)
	if err := f.startSSHEnvironmentBifroest(targetPort, targetKnownHosts, targetIdentity, false, "^(sftp|netconf|echo-data|unsupported-e2e)$"); err != nil {
		t.Fatal(err)
	}

	result := f.ssh(30*time.Second, f.clientKey, "e2e", []string{"-T", "-s"}, "netconf")
	if code := exitCode(result.err); code != 23 || result.stdout != direct.stdout || result.stderr != direct.stderr {
		t.Fatalf("forwarded netconf subsystem: exit=%d (error: %v), stdout=%q, stderr=%q", code, result.err, result.stdout, result.stderr)
	}

	client := f.newSSHClient(t, 30*time.Second)
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	accepted, err := channel.SendRequest("subsystem", true, gossh.Marshal(&struct{ Name string }{"echo-data"}))
	if err != nil || !accepted {
		t.Fatalf("request duplex subsystem: accepted=%t, error=%v", accepted, err)
	}
	const size = 1024
	seed := []byte("bifroest-e2e\x00\xff")
	payload := bytes.Repeat(seed, size/len(seed)+1)[:size]
	if _, err := channel.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := channel.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(channel)
	if err != nil || !bytes.Equal(output, append(append([]byte(nil), payload...), []byte("ok\n")...)) {
		t.Fatalf("duplex subsystem output: error=%v, bytes=%d", err, len(output))
	}
	var exitCodes []uint32
	for request := range requests {
		if request.Type == "exit-status" {
			var status struct{ Code uint32 }
			if err := gossh.Unmarshal(request.Payload, &status); err != nil {
				t.Fatal(err)
			}
			exitCodes = append(exitCodes, status.Code)
		}
	}
	if len(exitCodes) != 1 || exitCodes[0] != 0 {
		t.Fatalf("duplex subsystem exit codes: %v", exitCodes)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.RequestSubsystem("unsupported-e2e"); err == nil {
		t.Fatal("Bifroest accepted a subsystem rejected by the OpenSSH target")
	}
	blocked, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()
	if err := blocked.RequestSubsystem("blocked-e2e"); err == nil {
		t.Fatal("Bifroest forwarded a subsystem not on the allowlist")
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
	if err := f.startSSHEnvironmentBifroest(targetPort, targetKnownHosts, targetIdentity, true, ""); err != nil {
		return s, err
	}
	return s, nil
}

func (f *fixture) prepareSSHEnvironmentTarget(hostKey, identity string) (string, string, error) {
	return f.prepareSSHEnvironmentTargetWithContainerfile(hostKey, identity, localContainerfile)
}

func (f *fixture) prepareSSHEnvironmentTargetWithContainerfile(hostKey, identity, containerfile string) (string, string, error) {
	contextDir := filepath.Join(f.tempDir, "ssh-target-context")
	if err := os.MkdirAll(contextDir, 0755); err != nil {
		return "", "", err
	}
	files := map[string]struct {
		content []byte
		mode    os.FileMode
	}{
		"Containerfile":        {[]byte(containerfile), 0644},
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

const openSSHSubsystemContainerfile = `FROM ` + alpineImage + `
RUN apk add --no-cache openssh-server \
 && addgroup -S -g 10001 e2e \
 && adduser -S -D -H -u 10001 -G e2e -h /home/e2e -s /bin/sh e2e \
 && echo 'e2e:unused-e2e-password' | chpasswd \
 && mkdir -p /home/e2e/.ssh /run/sshd \
 && chown -R e2e:e2e /home/e2e \
 && chmod 0700 /home/e2e/.ssh
COPY e2e-helper /usr/local/bin/e2e-helper
COPY ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
COPY authorized_keys /home/e2e/.ssh/authorized_keys
RUN chmod 0755 /usr/local/bin/e2e-helper \
 && chmod 0600 /etc/ssh/ssh_host_ed25519_key /home/e2e/.ssh/authorized_keys \
 && chown e2e:e2e /home/e2e/.ssh/authorized_keys
RUN printf 'Port 2222\nListenAddress 0.0.0.0\nHostKey /etc/ssh/ssh_host_ed25519_key\nAuthorizedKeysFile /home/e2e/.ssh/authorized_keys\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nSubsystem netconf /usr/local/bin/e2e-helper streams\nSubsystem echo-data /usr/local/bin/e2e-helper stream-duplex 1024\n' > /etc/ssh/sshd_config
EXPOSE 2222
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]
`

func writeSSHEnvironmentKnownHosts(path, host, port, publicKeyPath string) error {
	publicKey := strings.Fields(string(mustRead(publicKeyPath)))
	if len(publicKey) < 2 {
		return errors.New("generated SSH target host public key is malformed")
	}
	entry := fmt.Sprintf("[%s]:%s %s %s\n", host, port, publicKey[0], publicKey[1])
	return os.WriteFile(path, []byte(entry), 0600)
}

func (f *fixture) startSSHEnvironmentBifroest(targetPort, targetKnownHosts, targetIdentity string, recording bool, allowedSubsystems string) error {
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
	subsystemConfiguration := ""
	if allowedSubsystems != "" {
		subsystemConfiguration = fmt.Sprintf("      allowedSubsystems: %s\n", yamlString(allowedSubsystems))
	}
	configuration := fmt.Sprintf(sshEnvironmentRecordingConfiguration,
		auditlogConfiguration,
		yamlString(net.JoinHostPort(f.host, f.port)), yamlString(f.hostKey), yamlString(f.sessionStorage), yamlString(f.clientKey+".pub"),
		yamlString(net.JoinHostPort(f.host, targetPort)), yamlString(targetKnownHosts), yamlString(targetIdentity), subsystemConfiguration,
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
%s
`
