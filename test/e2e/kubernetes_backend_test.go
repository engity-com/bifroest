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
	"strconv"
	"strings"
	"testing"
	"time"
)

type kubernetesFixture struct {
	*fixture
	kindTool       string
	kubectlTool    string
	clusterName    string
	kubeconfig     string
	namespace      string
	clusterCreated bool
	environmentPod string
}

func TestOpenSSHKubernetesEnvironment(t *testing.T) {
	k, err := newKubernetesFixture(t)
	if errors.Is(err, errNoRuntime) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime=%s cluster=%s namespace=%s port=%s", k.runtimeCLI, k.clusterName, k.namespace, k.port)

	t.Run("wrong key creates no environment", func(t *testing.T) {
		result := k.ssh(10*time.Second, k.wrongKey, "e2e", nil, "/usr/local/bin/e2e-helper", "ready")
		if result.err == nil {
			t.Fatalf("login unexpectedly succeeded: %s", result.stdout)
		}
		time.Sleep(500 * time.Millisecond)
		pods, err := k.podNames()
		if err != nil {
			t.Fatal(err)
		}
		if len(pods) != 0 {
			t.Fatalf("rejected key created environment Pods: %v", pods)
		}
	})

	t.Run("exec stdout stderr and exit status", func(t *testing.T) {
		result := k.ssh(3*time.Minute, k.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "streams")
		if code := exitCode(result.err); code != 23 {
			t.Fatalf("exit code: got %d, want 23 (error: %v)\nstdout:\n%s\nstderr:\n%s", code, result.err, result.stdout, result.stderr)
		}
		if !strings.HasSuffix(result.stdout, "stdout-e2e\n") {
			t.Errorf("stdout: got %q", result.stdout)
		}
		if result.stderr != "stderr-e2e\n" {
			t.Errorf("stderr: got %q", result.stderr)
		}
		if err := k.waitForEnvironmentPod(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("session and Pod reuse", func(t *testing.T) {
		first := k.ssh(30*time.Second, k.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "environment")
		if first.err != nil {
			t.Fatalf("first connection failed: %v\n%s", first.err, first.stderr)
		}
		firstIDs := parseEnvironmentIDs(t, first.stdout)
		podBefore := k.environmentPod

		second := k.ssh(30*time.Second, k.clientKey, "e2e", nil, "/usr/local/bin/e2e-helper", "environment")
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
		pods, err := k.podNames()
		if err != nil {
			t.Fatal(err)
		}
		if len(pods) != 1 || pods[0] != podBefore {
			t.Fatalf("Pod was not reused: before=%q after=%v", podBefore, pods)
		}
		labels := k.kubectl(10*time.Second, "get", "pod", podBefore, "-n", k.namespace,
			"-o", "jsonpath={.metadata.labels.org\\.engity\\.bifroest/flow}{' '}{.metadata.labels.org\\.engity\\.bifroest/session-id}")
		if labels.err != nil {
			t.Fatalf("read Pod labels: %v\n%s", labels.err, labels.stderr)
		}
		if fields := strings.Fields(labels.stdout); len(fields) != 2 || fields[0] != k.flowName || fields[1] != firstIDs["session"] {
			t.Fatalf("unexpected Pod labels %q", labels.stdout)
		}
	})

	t.Run("PTY allocation", func(t *testing.T) {
		result := k.sshWithEnv(30*time.Second, []string{"TERM=xterm-256color"}, k.clientKey, "e2e", []string{"-tt"}, "/usr/local/bin/e2e-helper", "pty")
		if result.err != nil {
			t.Fatalf("PTY command failed: %v\nstdout:\n%s\nstderr:\n%s", result.err, result.stdout, result.stderr)
		}
		if output := strings.ReplaceAll(strings.TrimSpace(result.stdout), "\r", ""); output != "pty=true term=xterm-256color" {
			t.Fatalf("unexpected PTY output %q", output)
		}
	})

	runContainerExecutionEnvironmentTest(t, k.fixture, 75*time.Second, "from-image")

	runBackendProtocolTests(t, k.fixture, 75*time.Second, k.ensurePodEchoServer)

	t.Run("native SFTP lifecycle", func(t *testing.T) {
		source := filepath.Join(t.TempDir(), "source.bin")
		download := filepath.Join(t.TempDir(), "download.bin")
		payload := bytes.Repeat([]byte("kubernetes-sftp-e2e\x00"), 4096)
		if err := os.WriteFile(source, payload, 0600); err != nil {
			t.Fatal(err)
		}
		batch := filepath.Join(t.TempDir(), "batch")
		commands := fmt.Sprintf("put %s upload.tmp\nrename upload.tmp renamed.bin\nget renamed.bin %s\nrm renamed.bin\n", source, download)
		if err := os.WriteFile(batch, []byte(commands), 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{
			"-F", "/dev/null", "-S", k.tools["ssh"], "-b", batch, "-P", k.port, "-i", k.clientKey,
			"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=" + k.knownHosts,
			"-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR", "e2e@" + k.host,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		result := runCommand(ctx, k.repoRoot, nil, k.tools["sftp"], args...)
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
		k.ensurePodEchoServer(t)
		socket := filepath.Join(t.TempDir(), "local-forward.sock")
		forward := startSSH(t, k.fixture, nil, []string{"-N", "-o", "ExitOnForwardFailure=yes", "-L", fmt.Sprintf("%s:127.0.0.1:%d", socket, echoPort)}, nil)
		defer forward.stop()
		if err := pollProcess(20*time.Second, forward, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := runCommand(ctx, k.repoRoot, nil, k.helper, "echo-client", "unix", socket, "262144")
			if result.err != nil {
				return fmt.Errorf("%w: %s", result.err, result.stderr)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ssh -D SOCKS5 transfer", func(t *testing.T) {
		k.ensurePodEchoServer(t)
		port, err := unusedTCPPort()
		if err != nil {
			t.Fatal(err)
		}
		proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		forward := startSSH(t, k.fixture, nil, []string{"-N", "-o", "ExitOnForwardFailure=yes", "-D", proxy}, nil)
		defer forward.stop()
		if err := pollProcess(20*time.Second, forward, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := runCommand(ctx, k.repoRoot, nil, k.helper, "echo-client", "socks", proxy, fmt.Sprintf("127.0.0.1:%d", echoPort), "262144")
			if result.err != nil {
				return fmt.Errorf("%w: %s", result.err, result.stderr)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ssh -R transfer", func(t *testing.T) {
		hostEcho, address := startEchoServer(t, k.helper)
		defer hostEcho.stop()
		forward := startSSH(t, k.fixture, nil, []string{"-N", "-o", "ExitOnForwardFailure=yes", "-R", fmt.Sprintf("127.0.0.1:%d:%s", reversePort, address)}, nil)
		defer forward.stop()
		if err := pollProcess(20*time.Second, forward, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := runCommand(ctx, k.repoRoot, nil, k.helper, "echo-client", "tcp", fmt.Sprintf("127.0.0.1:%d", reversePort), "262144")
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
		agentProcess := startProcess(t, nil, k.tools["ssh-agent"], "-D", "-a", socket)
		defer agentProcess.stop()
		if err := poll(5*time.Second, func() error { _, err := os.Stat(socket); return err }); err != nil {
			t.Fatalf("ssh-agent did not create socket: %v", err)
		}
		env := []string{"SSH_AUTH_SOCK=" + socket}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		result := runCommand(ctx, k.repoRoot, env, k.tools["ssh-add"], k.agentKey)
		cancel()
		if result.err != nil {
			t.Fatalf("ssh-add failed: %v\n%s", result.err, result.stderr)
		}
		result = k.sshWithEnv(30*time.Second, env, k.clientKey, "e2e", []string{"-A"}, "/usr/local/bin/e2e-helper", "agent-keys")
		if result.err != nil {
			t.Fatalf("agent forwarding failed: %v\nstderr:\n%s", result.err, result.stderr)
		}
		if got, want := normalizePublicKey(result.stdout), normalizePublicKey(string(mustRead(k.agentKey+".pub"))); got != want {
			t.Fatalf("forwarded keys: got %q, want %q", got, want)
		}
	})

	t.Run("abrupt disconnect cleans process", func(t *testing.T) {
		pidFile := "/tmp/bifroest-e2e-abrupt.pid"
		connection := startSSH(t, k.fixture, nil, nil, []string{"/usr/local/bin/e2e-helper", "wait-for-stop", pidFile})
		if err := k.waitForRemoteProcess(connection, pidFile); err != nil {
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
		if err := poll(15*time.Second, func() error {
			result := k.podExec(5*time.Second, "/usr/local/bin/e2e-helper", "process-alive", pidFile)
			if result.err == nil {
				return errors.New("remote process is still alive")
			}
			if exitCode(result.err) == 1 {
				return nil
			}
			return fmt.Errorf("cannot inspect remote process: %w: %s", result.err, result.stderr)
		}); err != nil {
			info := k.podExec(5*time.Second, "/usr/local/bin/e2e-helper", "process-info", pidFile)
			t.Fatalf("%v\nprocess info:\n%s\n%s", err, info.stdout, info.stderr)
		}
	})

	// This must remain final: the session and its only environment are expected to disappear.
	t.Run("session expiry cleans Pod", func(t *testing.T) {
		if err := poll(60*time.Second, func() error {
			pods, err := k.podNames()
			if err != nil {
				return err
			}
			if len(pods) != 0 {
				return fmt.Errorf("environment Pods still exist: %v", pods)
			}
			entries, err := os.ReadDir(k.sessionStorage)
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

func newKubernetesFixture(t *testing.T) (*kubernetesFixture, error) {
	t.Helper()
	f, err := newFixture(t)
	if err != nil {
		return nil, err
	}
	k := &kubernetesFixture{
		fixture:     f,
		clusterName: fmt.Sprintf("bf-e2e-%d", time.Now().UnixNano()),
		kubeconfig:  filepath.Join(f.tempDir, "admin.kubeconfig"),
		namespace:   "bifroest-e2e",
	}
	k.flowName = k.name
	t.Cleanup(k.cleanup)
	if k.kindTool, err = exec.LookPath("kind"); err != nil {
		return k, errors.New("required tool \"kind\" is unavailable")
	}
	if k.kubectlTool, err = exec.LookPath("kubectl"); err != nil {
		return k, errors.New("required tool \"kubectl\" is unavailable")
	}
	if err := f.prepareRuntime(true); err != nil {
		return k, err
	}
	if err := k.prepareCluster(); err != nil {
		return k, err
	}
	if err := k.prepareImages(); err != nil {
		return k, err
	}
	controllerKubeconfig, err := k.prepareRBAC()
	if err != nil {
		return k, err
	}
	if err := k.startBifroest(controllerKubeconfig); err != nil {
		return k, err
	}
	return k, nil
}

func (k *kubernetesFixture) prepareCluster() error {
	logDir := filepath.Join(k.repoRoot, "var", "e2e")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(logDir, "kind-cluster"), []byte(k.clusterName), 0644); err != nil {
		return err
	}
	k.clusterCreated = true
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	result := runCommand(ctx, k.repoRoot, []string{"KIND_EXPERIMENTAL_PROVIDER=" + k.runtimeCLI}, k.kindTool,
		"create", "cluster", "--name", k.clusterName, "--wait", "5m", "--kubeconfig", k.kubeconfig)
	if result.err != nil {
		return fmt.Errorf("create kind cluster: %w\nstdout:\n%s\nstderr:\n%s", result.err, result.stdout, result.stderr)
	}
	result = k.kubectl(2*time.Minute, "wait", "--for=condition=Ready", "node", "--all", "--timeout=2m")
	if result.err != nil {
		return fmt.Errorf("wait for kind nodes: %w\n%s", result.err, result.stderr)
	}
	return nil
}

func (k *kubernetesFixture) prepareImages() error {
	targetContext := filepath.Join(k.tempDir, "kubernetes-target-context")
	if err := os.MkdirAll(targetContext, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(targetContext, "Containerfile"), []byte(dockerEnvironmentContainerfile), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(targetContext, "e2e-helper"), mustRead(k.helper), 0755); err != nil {
		return err
	}
	if err := k.buildImage(targetContext); err != nil {
		return err
	}

	imageArchive := filepath.Join(k.tempDir, "kubernetes-image.tar")
	result := k.runtime(5*time.Minute, "save", "--output", imageArchive, k.imageName)
	if result.err != nil {
		return fmt.Errorf("export E2E image %s: %w\nstdout:\n%s\nstderr:\n%s", k.imageName, result.err, result.stdout, result.stderr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	result = runCommand(ctx, k.repoRoot, []string{"KIND_EXPERIMENTAL_PROVIDER=" + k.runtimeCLI}, k.kindTool,
		"load", "image-archive", "--name", k.clusterName, imageArchive)
	cancel()
	if result.err != nil {
		return fmt.Errorf("load E2E image %s into kind: %w\nstdout:\n%s\nstderr:\n%s", k.imageName, result.err, result.stdout, result.stderr)
	}
	return nil
}

func (k *kubernetesFixture) prepareRBAC() (string, error) {
	manifest := filepath.Join(k.tempDir, "rbac.yaml")
	if err := os.WriteFile(manifest, []byte(fmt.Sprintf(kubernetesRBAC, k.namespace, k.namespace, k.namespace, k.namespace)), 0600); err != nil {
		return "", err
	}
	result := k.kubectl(30*time.Second, "apply", "-f", manifest)
	if result.err != nil {
		return "", fmt.Errorf("apply Kubernetes RBAC: %w\n%s", result.err, result.stderr)
	}
	token := k.kubectl(30*time.Second, "create", "token", "bifroest-controller", "-n", k.namespace, "--duration=1h")
	if token.err != nil {
		return "", fmt.Errorf("create controller token: %w\n%s", token.err, token.stderr)
	}
	server := k.kubectl(10*time.Second, "config", "view", "--raw", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
	if server.err != nil {
		return "", fmt.Errorf("read Kubernetes API server: %w\n%s", server.err, server.stderr)
	}
	ca := k.kubectl(10*time.Second, "config", "view", "--raw", "--minify", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	if ca.err != nil {
		return "", fmt.Errorf("read Kubernetes CA: %w\n%s", ca.err, ca.stderr)
	}
	return fmt.Sprintf(kubernetesControllerKubeconfig,
		strings.TrimSpace(server.stdout), strings.TrimSpace(ca.stdout), k.namespace, strings.TrimSpace(token.stdout)), nil
}

func (k *kubernetesFixture) startBifroest(controllerKubeconfig string) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	k.port = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if err := os.MkdirAll(k.sessionStorage, 0700); err != nil {
		_ = listener.Close()
		return err
	}
	configurationPath := filepath.Join(k.tempDir, "kubernetes-environment.yaml")
	configuration := fmt.Sprintf(kubernetesEnvironmentConfiguration,
		yamlString(net.JoinHostPort(k.host, k.port)), yamlString(k.hostKey), yamlString(k.sessionStorage),
		yamlString(k.flowName), yamlString(k.clientKey+".pub"), yamlString(controllerKubeconfig),
		yamlString(k.namespace), yamlString(k.imageName),
	)
	if err := os.WriteFile(configurationPath, []byte(configuration), 0600); err != nil {
		_ = listener.Close()
		return err
	}
	if err := k.writeKnownHosts(); err != nil {
		_ = listener.Close()
		return err
	}
	processEnv := []string{
		"PATH=" + filepath.Dir(k.goTool) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"CGO_ENABLED=0",
		"BIFROEST_LOCAL_KIND_CLUSTER=" + k.clusterName,
		"KIND_EXPERIMENTAL_PROVIDER=" + k.runtimeCLI,
	}
	if k.runtimeHost != "" {
		processEnv = append(processEnv, "DOCKER_HOST="+k.runtimeHost)
	}
	if err := listener.Close(); err != nil {
		return err
	}
	k.bifroestProc, err = k.launchLoggedProcess("bifroest", processEnv, k.bifroest,
		"run", "--configuration="+configurationPath, "--log.level=DEBUG")
	if err != nil {
		return fmt.Errorf("start host Bifroest: %w", err)
	}
	if err := pollProcess(30*time.Second, k.bifroestProc, func() error {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(k.host, k.port), 500*time.Millisecond)
		if err != nil {
			return err
		}
		return conn.Close()
	}); err != nil {
		return fmt.Errorf("wait for host Bifroest: %w", err)
	}
	return nil
}

func (k *kubernetesFixture) kubectl(timeout time.Duration, args ...string) commandResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	all := append([]string{"--kubeconfig", k.kubeconfig}, args...)
	return runCommand(ctx, k.repoRoot, nil, k.kubectlTool, all...)
}

func (k *kubernetesFixture) podNames() ([]string, error) {
	result := k.kubectl(10*time.Second, "get", "pods", "-n", k.namespace, "-l", flowLabel+"="+k.flowName,
		"-o", "jsonpath={.items[*].metadata.name}")
	if result.err != nil {
		return nil, fmt.Errorf("list environment Pods: %w: %s", result.err, result.stderr)
	}
	return strings.Fields(result.stdout), nil
}

func (k *kubernetesFixture) waitForEnvironmentPod() error {
	return poll(2*time.Minute, func() error {
		pods, err := k.podNames()
		if err != nil {
			return err
		}
		if len(pods) != 1 {
			return fmt.Errorf("got %d environment Pods, want one: %v", len(pods), pods)
		}
		result := k.kubectl(10*time.Second, "get", "pod", pods[0], "-n", k.namespace, "-o", "jsonpath={.status.phase}")
		if result.err != nil {
			return result.err
		}
		if strings.TrimSpace(result.stdout) != "Running" {
			return fmt.Errorf("environment Pod is not running: %q", result.stdout)
		}
		k.environmentPod = pods[0]
		return nil
	})
}

func (k *kubernetesFixture) podExec(timeout time.Duration, command ...string) commandResult {
	args := []string{"exec", "-n", k.namespace, k.environmentPod, "-c", "bifroest", "--"}
	args = append(args, command...)
	return k.kubectl(timeout, args...)
}

func (k *kubernetesFixture) ensurePodEchoServer(t *testing.T) {
	t.Helper()
	result := k.podExec(10*time.Second, "/bin/sh", "-c",
		fmt.Sprintf("/usr/local/bin/e2e-helper echo-server tcp 127.0.0.1:%d >/tmp/e2e-echo.log 2>&1 </dev/null &", echoPort))
	if result.err != nil {
		t.Fatalf("start Pod echo server: %v\n%s", result.err, result.stderr)
	}
	if err := poll(10*time.Second, func() error {
		probe := k.podExec(5*time.Second, "/usr/local/bin/e2e-helper", "echo-client", "tcp", fmt.Sprintf("127.0.0.1:%d", echoPort), "16")
		return probe.err
	}); err != nil {
		t.Fatalf("wait for Pod echo server: %v", err)
	}
}

func (k *kubernetesFixture) waitForRemoteProcess(process *runningProcess, pidFile string) error {
	return pollProcess(15*time.Second, process, func() error {
		return k.podExec(5*time.Second, "/usr/local/bin/e2e-helper", "process-alive", pidFile).err
	})
}

func (k *kubernetesFixture) cleanup() {
	if k.clusterCreated && k.t.Failed() {
		logDir := filepath.Join(k.repoRoot, "var", "e2e", k.name+"-kind")
		_ = os.MkdirAll(filepath.Dir(logDir), 0755)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		result := runCommand(ctx, k.repoRoot, []string{"KIND_EXPERIMENTAL_PROVIDER=" + k.runtimeCLI}, k.kindTool,
			"export", "logs", logDir, "--name", k.clusterName)
		cancel()
		if result.err != nil {
			k.t.Logf("cannot export kind logs: %v\n%s", result.err, result.stderr)
		}
	}
	if k.bifroestProc != nil {
		k.bifroestProc.stop()
	}
	if k.clusterCreated {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		result := runCommand(ctx, k.repoRoot, []string{"KIND_EXPERIMENTAL_PROVIDER=" + k.runtimeCLI}, k.kindTool,
			"delete", "cluster", "--name", k.clusterName)
		cancel()
		if result.err != nil {
			k.t.Logf("cannot delete kind cluster: %v\n%s", result.err, result.stderr)
		}
	}
	_ = k.runtime(30*time.Second, "image", "rm", "--force", "localhost/bifroest:generic-"+k.bifroestVersion).err
	if !k.t.Failed() {
		_ = os.Remove(filepath.Join(k.repoRoot, "var", "e2e", "kind-cluster"))
	}
}

const kubernetesRBAC = `apiVersion: v1
kind: Namespace
metadata:
  name: %s
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: bifroest-controller
  namespace: %s
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: bifroest-workload
  namespace: %s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: bifroest-controller
  namespace: %s
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["pods/exec", "pods/portforward"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: bifroest-controller
  namespace: %[1]s
subjects:
  - kind: ServiceAccount
    name: bifroest-controller
    namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: bifroest-controller
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %[1]s-namespace-reader
rules:
  - apiGroups: [""]
    resources: ["namespaces"]
    resourceNames: ["%[1]s"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: %[1]s-namespace-reader
subjects:
  - kind: ServiceAccount
    name: bifroest-controller
    namespace: %[1]s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: %[1]s-namespace-reader
`

const kubernetesControllerKubeconfig = `apiVersion: v1
kind: Config
clusters:
  - name: kind
    cluster:
      server: %s
      certificate-authority-data: %s
contexts:
  - name: e2e
    context:
      cluster: kind
      namespace: %s
      user: bifroest-controller
current-context: e2e
users:
  - name: bifroest-controller
    user:
      token: %s
`

const kubernetesEnvironmentConfiguration = `startMessage: '{{""}}'
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
      type: kubernetes
      config: %s
      context: "e2e"
      namespace: %s
      serviceAccountName: "bifroest-workload"
      image: %s
      imagePullPolicy: never
      readyTimeout: 2m
      removeTimeout: 30s
      directory: "/home/e2e"
      user: "e2e"
      group: "e2e"
      banner: '{{""}}'
      portForwardingAllowed: true
      cleanOrphan: false
`
