//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	alpineImage = "docker.io/library/alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
	echoPort    = 31001
	reversePort = 31002
	flowLabel   = "org.engity.bifroest/flow"
)

var errNoRuntime = errors.New("neither a working Docker daemon nor Podman is available")

type fixture struct {
	t        *testing.T
	repoRoot string
	tempDir  string
	name     string
	goTool   string
	tools    map[string]string

	clientKey  string
	wrongKey   string
	agentKey   string
	hostKey    string
	knownHosts string
	helper     string
	bifroest   string
	host       string
	port       string

	runtimeCLI     string
	runtimeHost    string
	runtimeService *runningProcess
	imageName      string
	imageID        string
	containerID    string
	networkName    string
	networkID      string
	flowName       string
	bifroestProc   *runningProcess
	sessionStorage string
}

type commandResult struct {
	stdout string
	stderr string
	err    error
}

func newFixture(t *testing.T) (*fixture, error) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, fmt.Errorf("the e2e suite requires a linux/amd64 host, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	repoRoot, err := findRepoRoot()
	if err != nil {
		return nil, err
	}
	goTool, err := findGoTool(repoRoot)
	if err != nil {
		return nil, err
	}
	tools := make(map[string]string)
	for _, tool := range []string{"ssh", "sftp", "ssh-keygen", "ssh-agent", "ssh-add"} {
		path, err := nativeOpenSSHTool(tool)
		if err != nil {
			return nil, err
		}
		tools[tool] = path
	}

	tempDir := t.TempDir()
	unique := fmt.Sprintf("bifroest-e2e-%d-%d", os.Getpid(), time.Now().UnixNano())
	f := &fixture{
		t:              t,
		repoRoot:       repoRoot,
		tempDir:        tempDir,
		name:           unique,
		goTool:         goTool,
		imageName:      "localhost/" + unique + ":latest",
		host:           "127.0.0.1",
		clientKey:      filepath.Join(tempDir, "client_ed25519"),
		wrongKey:       filepath.Join(tempDir, "wrong_ed25519"),
		agentKey:       filepath.Join(tempDir, "agent_ed25519"),
		hostKey:        filepath.Join(tempDir, "host_ed25519"),
		knownHosts:     filepath.Join(tempDir, "known_hosts"),
		sessionStorage: filepath.Join(tempDir, "sessions"),
		tools:          tools,
	}
	t.Cleanup(f.cleanup)
	if err := f.prepareCommon(); err != nil {
		return f, err
	}
	return f, nil
}

func newLocalFixture(t *testing.T) (*fixture, error) {
	t.Helper()
	f, err := newFixture(t)
	if err != nil {
		return f, err
	}
	if err := f.prepareRuntime(false); err != nil {
		return f, err
	}
	if err := f.prepareLocal(); err != nil {
		return f, err
	}
	return f, nil
}

func nativeOpenSSHTool(name string) (string, error) {
	for _, candidate := range []string{name, name + ".exe"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("required OpenSSH tool %q (or %q) is unavailable", name, name+".exe")
}

func findGoTool(repoRoot string) (string, error) {
	if path, err := exec.LookPath("go"); err == nil {
		return path, nil
	}
	mise, err := exec.LookPath("mise")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		result := runCommand(ctx, repoRoot, nil, mise, "which", "go")
		if result.err == nil {
			if path := strings.TrimSpace(result.stdout); path != "" {
				return path, nil
			}
		}
	}
	return "", errors.New("required tool \"go\" is unavailable")
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("cannot locate repository root")
		}
		dir = parent
	}
}

func selectRuntime() (string, error) {
	requested := strings.ToLower(strings.TrimSpace(os.Getenv("BIFROEST_E2E_RUNTIME")))
	if requested == "" {
		requested = "auto"
	}
	if requested != "auto" && requested != "docker" && requested != "podman" {
		return "", fmt.Errorf("BIFROEST_E2E_RUNTIME must be auto, docker, or podman; got %q", requested)
	}
	check := func(name string) bool {
		if _, err := exec.LookPath(name); err != nil {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, name, "info").Run() == nil
	}
	if requested != "auto" {
		if !check(requested) {
			return "", fmt.Errorf("requested runtime %q is not installed or not functional", requested)
		}
		return requested, nil
	}
	if check("docker") {
		return "docker", nil
	}
	if check("podman") {
		return "podman", nil
	}
	return "", errNoRuntime
}

func (f *fixture) prepareCommon() error {
	for _, key := range []string{f.clientKey, f.wrongKey, f.agentKey, f.hostKey} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		result := runCommand(ctx, f.repoRoot, nil, f.tools["ssh-keygen"], "-q", "-t", "ed25519", "-N", "", "-f", key)
		cancel()
		if result.err != nil {
			return fmt.Errorf("generate %s: %w\n%s", filepath.Base(key), result.err, result.stderr)
		}
		if err := os.Chmod(key, 0600); err != nil {
			return fmt.Errorf("secure private key %s: %w", filepath.Base(key), err)
		}
		if err := os.Chown(key, os.Geteuid(), os.Getegid()); err != nil {
			return fmt.Errorf("set private key owner for %s: %w", filepath.Base(key), err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		result = runCommand(ctx, f.repoRoot, nil, f.tools["ssh-keygen"], "-y", "-f", key)
		cancel()
		if result.err != nil {
			return fmt.Errorf("validate generated private key %s: %w\n%s", filepath.Base(key), result.err, result.stderr)
		}
	}

	binDir := filepath.Join(f.tempDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}
	f.helper = filepath.Join(binDir, "e2e-helper")
	f.bifroest = filepath.Join(binDir, "bifroest")
	buildEnv := []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64"}
	for _, build := range []struct {
		output      string
		packagePath string
		tags        string
	}{
		{f.bifroest, "./cmd/bifroest", "local_build"},
		{f.helper, "./test/e2e/helper", "e2e"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		args := []string{"build", "-tags", build.tags, "-trimpath", "-ldflags=-s -w", "-o", build.output, build.packagePath}
		result := runCommand(ctx, f.repoRoot, buildEnv, f.goTool, args...)
		cancel()
		if result.err != nil {
			return fmt.Errorf("build %s: %w\n%s", build.packagePath, result.err, result.stderr)
		}
	}
	return nil
}

func (f *fixture) prepareRuntime(apiService bool) error {
	runtimeCLI, err := selectRuntime()
	if err != nil {
		return err
	}
	f.runtimeCLI = runtimeCLI
	if !apiService {
		return nil
	}
	if runtimeCLI == "podman" {
		socket := filepath.Join(f.tempDir, "podman.sock")
		f.runtimeHost = "unix://" + socket
		f.runtimeService, err = launchProcess(f.repoRoot, nil, runtimeCLI, "system", "service", "--time=0", f.runtimeHost)
		if err != nil {
			return fmt.Errorf("start Podman API service: %w", err)
		}
		if err := pollProcess(15*time.Second, f.runtimeService, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			result := runCommand(ctx, f.repoRoot, nil, runtimeCLI, "--url", f.runtimeHost, "info")
			if result.err != nil {
				return fmt.Errorf("%w: %s", result.err, strings.TrimSpace(result.stderr))
			}
			return nil
		}); err != nil {
			return fmt.Errorf("wait for Podman API service: %w", err)
		}
		return nil
	}

	f.runtimeHost = strings.TrimSpace(os.Getenv("DOCKER_HOST"))
	if f.runtimeHost == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result := runCommand(ctx, f.repoRoot, nil, runtimeCLI, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
		cancel()
		if result.err == nil {
			f.runtimeHost = strings.TrimSpace(result.stdout)
		}
	}
	return nil
}

func (f *fixture) prepareLocal() error {
	contextDir := filepath.Join(f.tempDir, "local-context")
	if err := os.MkdirAll(contextDir, 0755); err != nil {
		return err
	}
	files := map[string]struct {
		content []byte
		mode    os.FileMode
	}{
		"Containerfile":        {[]byte(localContainerfile), 0644},
		"bifroest":             {mustRead(f.bifroest), 0755},
		"e2e-helper":           {mustRead(f.helper), 0755},
		"configuration.yaml":   {[]byte(localConfiguration), 0644},
		"ssh_host_ed25519_key": {mustRead(f.hostKey), 0600},
		"authorized_keys":      {mustRead(f.clientKey + ".pub"), 0644},
	}
	for name, file := range files {
		if err := os.WriteFile(filepath.Join(contextDir, name), file.content, file.mode); err != nil {
			return fmt.Errorf("write local container context file %s: %w", name, err)
		}
	}
	if err := f.buildImage(contextDir); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	result := runCommand(ctx, f.repoRoot, nil, f.runtimeCLI, "run", "--detach", "--name", f.name, "--publish", "127.0.0.1::2222", "--security-opt=no-new-privileges", f.imageName)
	cancel()
	if result.err != nil {
		return fmt.Errorf("start local-backend container: %w\n%s", result.err, result.stderr)
	}
	f.containerID = strings.TrimSpace(result.stdout)

	if err := poll(20*time.Second, func() error {
		result := f.runtime(3*time.Second, "port", f.containerID, "2222/tcp")
		if result.err != nil {
			return result.err
		}
		for _, line := range strings.Split(strings.TrimSpace(result.stdout), "\n") {
			host, port, err := net.SplitHostPort(strings.TrimSpace(line))
			if err == nil && (host == f.host || host == "0.0.0.0" || host == "::") {
				f.port = port
				return nil
			}
		}
		return fmt.Errorf("runtime did not report an IPv4 published port: %q", result.stdout)
	}); err != nil {
		return fmt.Errorf("resolve published SSH port: %w", err)
	}
	if err := f.writeKnownHosts(); err != nil {
		return err
	}
	if err := poll(25*time.Second, func() error {
		result := f.ssh(5*time.Second, f.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "ready")
		if result.err != nil {
			return fmt.Errorf("%w: %s", result.err, strings.TrimSpace(result.stderr))
		}
		if result.stdout != "ready\n" {
			return fmt.Errorf("unexpected readiness output %q", result.stdout)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("wait for local-backend SSH readiness: %w", err)
	}
	return nil
}

func (f *fixture) buildImage(contextDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	result := runCommand(ctx, f.repoRoot, nil, f.runtimeCLI, "build", "--platform=linux/amd64", "--tag", f.imageName, contextDir)
	cancel()
	if result.err != nil {
		return fmt.Errorf("build container image: %w\nstdout:\n%s\nstderr:\n%s", result.err, result.stdout, result.stderr)
	}
	result = f.runtime(20*time.Second, "image", "inspect", "--format", "{{.Id}}", f.imageName)
	if result.err != nil {
		return fmt.Errorf("inspect built image: %w\n%s", result.err, result.stderr)
	}
	f.imageID = strings.TrimSpace(result.stdout)
	if f.imageID == "" {
		return errors.New("runtime returned an empty image ID")
	}
	return nil
}

func (f *fixture) writeKnownHosts() error {
	publicKey := strings.Fields(string(mustRead(f.hostKey + ".pub")))
	if len(publicKey) < 2 {
		return errors.New("generated host public key is malformed")
	}
	knownHost := fmt.Sprintf("[%s]:%s %s %s\n", f.host, f.port, publicKey[0], publicKey[1])
	return os.WriteFile(f.knownHosts, []byte(knownHost), 0600)
}

func mustRead(path string) []byte {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return content
}

func (f *fixture) ssh(timeout time.Duration, key, user string, extra []string, remote ...string) commandResult {
	return f.sshWithEnv(timeout, nil, key, user, extra, remote...)
}

func (f *fixture) sshWithEnv(timeout time.Duration, env []string, key, user string, extra []string, remote ...string) commandResult {
	args := f.sshArgs(key, user)
	args = append(args, extra...)
	args = append(args, user+"@"+f.host)
	args = append(args, remote...)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return runCommand(ctx, f.repoRoot, env, f.tools["ssh"], args...)
}

func (f *fixture) sshArgs(key, user string) []string {
	return []string{
		"-F", "/dev/null",
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityFile=" + key,
		"-o", "UserKnownHostsFile=" + f.knownHosts,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=5",
		"-o", "ServerAliveInterval=2",
		"-o", "ServerAliveCountMax=2",
		"-o", "LogLevel=ERROR",
		"-p", f.port,
	}
}

func (f *fixture) runtime(timeout time.Duration, args ...string) commandResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return runCommand(ctx, f.repoRoot, nil, f.runtimeCLI, args...)
}

func (f *fixture) containerIDs() ([]string, error) {
	if f.flowName == "" {
		if f.containerID == "" {
			return nil, nil
		}
		return []string{f.containerID}, nil
	}
	result := f.runtime(5*time.Second, "ps", "--all", "--quiet", "--filter", "label="+flowLabel+"="+f.flowName)
	if result.err != nil {
		return nil, fmt.Errorf("list run containers: %w: %s", result.err, strings.TrimSpace(result.stderr))
	}
	var ids []string
	for _, id := range strings.Fields(result.stdout) {
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func runCommand(ctx context.Context, dir string, extraEnv []string, name string, args ...string) commandResult {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		err = fmt.Errorf("%w: %v", ctx.Err(), err)
	}
	return commandResult{stdout.String(), stderr.String(), err}
}

func poll(timeout time.Duration, check func() error) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		if err := check(); err == nil {
			return nil
		} else {
			last = err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return last
		}
		delay := 100 * time.Millisecond
		if remaining < delay {
			delay = remaining
		}
		time.Sleep(delay)
	}
}

type runningProcess struct {
	cmd    *exec.Cmd
	done   chan struct{}
	stdout bytes.Buffer
	stderr bytes.Buffer
	mu     sync.Mutex
	err    error
}

func launchProcess(dir string, env []string, name string, args ...string) (*runningProcess, error) {
	p := &runningProcess{cmd: exec.Command(name, args...), done: make(chan struct{})}
	p.cmd.Dir = dir
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.Stdout = &p.stdout
	p.cmd.Stderr = &p.stderr
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		err := p.cmd.Wait()
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
	}()
	return p, nil
}

func startProcess(t *testing.T, env []string, name string, args ...string) *runningProcess {
	t.Helper()
	p, err := launchProcess("", env, name, args...)
	if err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	return p
}

func startSSH(t *testing.T, f *fixture, env, extra, remote []string) *runningProcess {
	t.Helper()
	args := f.sshArgs(f.clientKey, "e2e")
	args = append(args, extra...)
	args = append(args, "e2e@"+f.host)
	args = append(args, remote...)
	return startProcess(t, env, f.tools["ssh"], args...)
}

func (p *runningProcess) collect() (bool, error) {
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return true, p.err
	default:
		return false, nil
	}
}

func (p *runningProcess) wait(timeout time.Duration) error {
	if exited, err := p.collect(); exited {
		return err
	}
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.err
	case <-time.After(timeout):
		return context.DeadlineExceeded
	}
}

func (p *runningProcess) stop() {
	if exited, _ := p.collect(); exited {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	if err := p.wait(3 * time.Second); !errors.Is(err, context.DeadlineExceeded) {
		return
	}
	_ = p.cmd.Process.Kill()
	_ = p.wait(3 * time.Second)
}

func pollProcess(timeout time.Duration, process *runningProcess, check func() error) error {
	return poll(timeout, func() error {
		if exited, err := process.collect(); exited {
			return fmt.Errorf("process exited before readiness: %v\nstdout:\n%s\nstderr:\n%s", err, process.stdout.String(), process.stderr.String())
		}
		return check()
	})
}

func (f *fixture) cleanup() {
	if f.t.Failed() {
		f.saveLogs()
	}
	if f.bifroestProc != nil {
		f.bifroestProc.stop()
	}
	if f.runtimeCLI != "" {
		ids, err := f.containerIDs()
		if err != nil {
			f.t.Logf("cannot enumerate E2E containers during cleanup: %v", err)
		}
		for _, id := range ids {
			_ = f.runtime(20*time.Second, "rm", "--force", id).err
		}
		if f.networkID != "" {
			_ = f.runtime(20*time.Second, "network", "rm", f.networkID).err
		}
		if f.imageID != "" {
			_ = f.runtime(30*time.Second, "image", "rm", "--force", f.imageID).err
		}
	}
	if f.runtimeService != nil {
		f.runtimeService.stop()
	}
}

func (f *fixture) saveLogs() {
	logDir := filepath.Join(f.repoRoot, "var", "e2e")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		f.t.Logf("cannot create E2E log directory: %v", err)
		return
	}
	var content strings.Builder
	if f.bifroestProc != nil {
		content.WriteString("--- bifroest stdout ---\n")
		content.WriteString(f.bifroestProc.stdout.String())
		content.WriteString("\n--- bifroest stderr ---\n")
		content.WriteString(f.bifroestProc.stderr.String())
	}
	ids, _ := f.containerIDs()
	for _, id := range ids {
		result := f.runtime(15*time.Second, "logs", id)
		content.WriteString("\n--- container " + id + " stdout ---\n")
		content.WriteString(result.stdout)
		content.WriteString("\n--- container " + id + " stderr ---\n")
		content.WriteString(result.stderr)
	}
	if f.runtimeService != nil {
		content.WriteString("\n--- runtime service stdout ---\n")
		content.WriteString(f.runtimeService.stdout.String())
		content.WriteString("\n--- runtime service stderr ---\n")
		content.WriteString(f.runtimeService.stderr.String())
	}
	path := filepath.Join(logDir, f.name+".log")
	if err := os.WriteFile(path, []byte(content.String()), 0644); err != nil {
		f.t.Logf("cannot write E2E logs: %v", err)
		return
	}
	f.t.Logf("E2E logs written to %s", path)
}

func normalizePublicKey(content string) string {
	fields := strings.Fields(content)
	if len(fields) < 2 {
		return strings.TrimSpace(content)
	}
	return fields[0] + " " + fields[1]
}

func unusedTCPPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

const localContainerfile = `FROM ` + alpineImage + `
COPY bifroest /usr/local/bin/bifroest
COPY e2e-helper /usr/local/bin/e2e-helper
COPY configuration.yaml /etc/bifroest/configuration.yaml
COPY ssh_host_ed25519_key /etc/bifroest/ssh_host_ed25519_key
COPY authorized_keys /home/e2e/.ssh/authorized_keys
RUN addgroup -S -g 10001 e2e \
 && adduser -S -D -H -u 10001 -G e2e -h /home/e2e -s /bin/sh e2e \
 && mkdir -p /home/e2e /var/lib/bifroest/sessions \
 && chown -R 10001:10001 /home/e2e \
 && chmod 0700 /home/e2e/.ssh \
 && chmod 0600 /home/e2e/.ssh/authorized_keys /etc/bifroest/ssh_host_ed25519_key \
 && chmod 0755 /usr/local/bin/bifroest /usr/local/bin/e2e-helper \
 && chmod 0700 /var/lib/bifroest/sessions
EXPOSE 2222
USER 0:10001
ENTRYPOINT ["/bin/sh", "-c", "umask 002 && exec /usr/local/bin/bifroest run --configuration=/etc/bifroest/configuration.yaml"]
`

const localConfiguration = `startMessage: '{{""}}'
ssh:
  addresses:
    - "0.0.0.0:2222"
  keys:
    hostKeys:
      - "/etc/bifroest/ssh_host_ed25519_key"
    rememberMeNotification: '{{""}}'
  banner: '{{""}}'
  idleTimeout: 30s
  maxTimeout: 2m
  gracefulShutdownTimeout: 3s
  handshakeTimeout: 5s
  sessionRequestTimeout: 5s
session:
  type: fs
  storage: "/var/lib/bifroest/sessions"
  idleTimeout: 2m
  maxTimeout: 5m
  maxConnections: 16
flows:
  - name: local
    authorization:
      type: local
      authorizedKeys:
        - "/home/e2e/.ssh/authorized_keys"
      password:
        allowed: false
        interactiveAllowed: false
        emptyAllowed: false
      pamService: ""
    environment:
      type: local
      name: "e2e"
      banner: '{{""}}'
      portForwardingAllowed: true
`

func yamlString(value string) string {
	return strconv.Quote(value)
}
