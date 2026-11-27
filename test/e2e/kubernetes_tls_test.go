//go:build e2e

package e2e_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
)

func TestKubernetesTLSBootstrap(t *testing.T) {
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	for _, tool := range []string{"go", "docker", "kind", "kubectl", "helm"} {
		_, err := exec.LookPath(tool)
		require.NoError(t, err, "required Kubernetes integration tool: %s", tool)
	}
	name := "bifroest-tls-" + uuid.NewString()[:8]
	report := filepath.Join(root, "var", "test-report", name)
	require.NoError(t, os.MkdirAll(report, 0o700))
	save := func(name string, raw []byte) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(report, name), raw, 0o600))
	}
	save("run.txt", []byte("Go Kubernetes TLS bootstrap test started.\n"))
	work := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	env := append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "KUBECONFIG="+filepath.Join(work, "kubeconfig"))
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, args[0], args[1:]...)
		command.Dir, command.Env = root, env
		return command.CombinedOutput()
	}
	mustRun := func(args ...string) []byte {
		t.Helper()
		output, err := run(ctx, args...)
		require.NoError(t, err, "%s\n%s", strings.Join(args, " "), output)
		return output
	}
	mustRun("go", "build", "-tags=local_build,local_kind", "-o", filepath.Join(work, "bifroest"), "./cmd/bifroest")
	mustRun("go", "test", "-c", "-tags=tls_bootstrap_fixture", "-o", filepath.Join(work, "fixture"), "./pkg/transporttls")
	for _, name := range []string{"Dockerfile", "passwd", "group"} {
		raw, err := os.ReadFile(filepath.Join(root, "test", "e2e", "testdata", "tls-bootstrap", name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(work, name), raw, 0o600))
	}
	image := "bifroest-tls-bootstrap:" + name
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		output, err := run(cleanup, "docker", "image", "rm", image)
		if err != nil {
			t.Errorf("cannot remove fixture image: %v\n%s", err, output)
		}
	})
	mustRun("docker", "build", "-t", image, work)
	const pod = "bootstrap-bifroest-0"
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		for _, resource := range []string{"pods", "endpointslices", "pvc", "events"} {
			output, _ := run(cleanup, "kubectl", "get", resource, "-o", "yaml")
			save(resource+".yaml", output)
		}
		output, _ := run(cleanup, "kubectl", "logs", pod)
		save("pod-latest.log", output)
		output, err := run(cleanup, "kind", "delete", "cluster", "--name", name)
		if err != nil {
			t.Errorf("cannot remove fixture cluster: %v\n%s", err, output)
		}
	})
	mustRun("kind", "create", "cluster", "--name", name, "--kubeconfig", filepath.Join(work, "kubeconfig"), "--wait", "2m")
	mustRun("kind", "load", "docker-image", "--name", name, image)
	values := map[string]any{
		"image": map[string]any{"repository": "bifroest-tls-bootstrap", "tag": name, "pullPolicy": "Never"},
		"configuration": map[string]any{
			"tls": map[string]any{"public": map[string]any{"acme": map[string]any{"acceptTerms": true}}},
			"http": map[string]any{
				"enabled": "acmeTlsAlpnOnly", "addresses": []string{":8443"}, "domains": []string{"app.example.org"}, "tls": "public",
				"webUi": map[string]any{"enabled": false}, "sshTunnel": map[string]any{"enabled": false}, "loginFlow": map[string]any{"enabled": false},
			},
		},
		"service":       map[string]any{"http": map[string]any{"enabled": true, "type": "ClusterIP", "publishNotReadyAddresses": true}},
		"networkPolicy": map[string]any{"httpPeers": []any{map[string]any{"ipBlock": map[string]any{"cidr": "0.0.0.0/0"}}}},
		"probes": map[string]any{
			"startup":   map[string]any{"periodSeconds": 1, "timeoutSeconds": 1, "failureThreshold": 120},
			"readiness": map[string]any{"periodSeconds": 1, "timeoutSeconds": 1, "failureThreshold": 3},
		},
	}
	raw, err := json.Marshal(values)
	require.NoError(t, err)
	valuesPath := filepath.Join(work, "values.json")
	require.NoError(t, os.WriteFile(valuesPath, raw, 0o600))
	mustRun("helm", "install", "bootstrap", "charts/bifroest", "-f", valuesPath)
	logs := func() string {
		output, _ := run(ctx, "kubectl", "logs", pod)
		return string(output)
	}
	require.Eventually(t, func() bool { return strings.Contains(logs(), "TLS_BOOTSTRAP_PENDING") }, 90*time.Second, 500*time.Millisecond)
	var state corev1.Pod
	require.NoError(t, json.Unmarshal(mustRun("kubectl", "get", "pod", pod, "-o", "json"), &state))
	readyCondition := false
	for _, condition := range state.Status.Conditions {
		if condition.Type == corev1.PodReady {
			readyCondition = true
			require.NotEqual(t, corev1.ConditionTrue, condition.Status)
		}
	}
	require.True(t, readyCondition, "the unready Pod must expose its readiness condition")
	var endpoints discoveryv1.EndpointSliceList
	require.NoError(t, json.Unmarshal(mustRun("kubectl", "get", "endpointslices", "-l", "kubernetes.io/service-name=bootstrap-bifroest-http", "-o", "json"), &endpoints))
	addresses := 0
	for _, slice := range endpoints.Items {
		for _, endpoint := range slice.Endpoints {
			addresses++
			require.NotNil(t, endpoint.Conditions.Ready)
			require.True(t, *endpoint.Conditions.Ready, "the Service must route the unready Pod for ACME")
		}
	}
	require.Positive(t, addresses)
	var claims corev1.PersistentVolumeClaimList
	require.NoError(t, json.Unmarshal(mustRun("kubectl", "get", "pvc", "-o", "json"), &claims))
	require.Len(t, claims.Items, 1)
	require.Equal(t, corev1.ClaimBound, claims.Items[0].Status.Phase)
	forwardLog, err := os.Create(filepath.Join(report, "port-forward.log"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, forwardLog.Close()) })
	forwardCtx, stopForward := context.WithCancel(ctx)
	forward := exec.CommandContext(forwardCtx, "kubectl", "port-forward", "--address=127.0.0.1", "pod/"+pod, ":9091")
	forward.Dir, forward.Env, forward.Stderr = root, env, forwardLog
	forward.WaitDelay = 5 * time.Second
	output, err := forward.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, forward.Start())
	forwardDone, ports := make(chan struct{}), make(chan string, 1)
	var forwardErr error
	go func() {
		defer close(forwardDone)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = fmt.Fprintln(forwardLog, line)
			if address, ok := strings.CutPrefix(line, "Forwarding from "); ok {
				address, _, _ = strings.Cut(address, " -> ")
				_, port, err := net.SplitHostPort(address)
				if err == nil {
					select {
					case ports <- port:
					default:
					}
				}
			}
		}
		forwardErr = forward.Wait()
	}()
	t.Cleanup(func() { stopForward(); <-forwardDone })
	var port string
	select {
	case port = <-ports:
		_, err := strconv.ParseUint(port, 10, 16)
		require.NoError(t, err)
	case <-forwardDone:
		t.Fatalf("port-forward stopped during startup: %v", forwardErr)
	case <-time.After(30 * time.Second):
		t.Fatal("port-forward did not report its allocated local port")
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{}}
	t.Cleanup(client.CloseIdleConnections)
	control := func(path string) bool {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/"+path, nil)
		if err != nil {
			return false
		}
		response, err := client.Do(request)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == http.StatusOK
	}
	require.Eventually(t, func() bool { return control("begin") }, 30*time.Second, 500*time.Millisecond)
	mustRun("kubectl", "wait", "--for=condition=Ready", "pod/"+pod, "--timeout=90s")
	require.Eventually(t, func() bool { return strings.Contains(logs(), "TLS_BOOTSTRAP_RENEWED") }, 90*time.Second, 500*time.Millisecond)
	require.True(t, control("finish"))
	var final string
	require.Eventually(t, func() bool {
		final = logs()
		return strings.Contains(final, "--- PASS: TestKubernetesTLSBootstrap")
	}, 30*time.Second, 500*time.Millisecond)
	save("pod.log", []byte(final))
	require.Contains(t, final, "TLS_BOOTSTRAP_READY")
	require.NotContains(t, final, "SKIP")
	require.NotContains(t, final, "FAIL")
	save("run.txt", []byte("PASS: Go-managed Pebble CA, ALPN-only bootstrap, fresh PVC, rootless Pod and renewal.\n"))
	t.Logf("TLS bootstrap, rootless PVC and renewal passed; report: %s", report)
}
