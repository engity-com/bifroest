//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func monitoringTool(t *testing.T, variable, name string) string {
	t.Helper()
	requested := os.Getenv(variable)
	if requested == "" {
		requested = name
	}
	path, err := exec.LookPath(requested)
	if err != nil {
		if os.Getenv(variable) != "" {
			t.Fatalf("%s: %v", variable, err)
		}
		t.Skipf("monitoring integration requires %s (%s)", name, variable)
	}
	return path
}

func monitoringAddresses(t *testing.T, count int) []string {
	t.Helper()
	addresses := make([]string, 0, count)
	for range count {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()
		addresses = append(addresses, listener.Addr().String())
	}
	return addresses
}

func monitoringJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}

func monitoringTLSFiles(t *testing.T, dir string) (string, string, *x509.Certificate) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	key, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)
	certPath, keyPath := filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, bfcrypto.WriteBootstrapFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), false))
	return certPath, keyPath, leaf
}

func monitoringHTTP(client *http.Client, address, token, accept string) (int, http.Header, []byte, error) {
	request, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	return response.StatusCode, response.Header, data, err
}

type monitoringPromSample struct {
	Metric map[string]string `json:"metric"`
	Value  []json.RawMessage `json:"value"`
}

func monitoringQuery(client *http.Client, address, expression string) ([]monitoringPromSample, error) {
	status, _, data, err := monitoringHTTP(client, address+"/api/v1/query?query="+url.QueryEscape(expression), "", "")
	if err != nil {
		return nil, err
	}
	var result struct {
		Status string `json:"status"`
		Data   struct {
			Result []monitoringPromSample `json:"result"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	if status != http.StatusOK || result.Status != "success" {
		return nil, fmt.Errorf("query %q: HTTP %d: %s", expression, status, result.Error)
	}
	return result.Data.Result, nil
}

func monitoringQueryValue(client *http.Client, address, expression string, want float64) error {
	samples, err := monitoringQuery(client, address, expression)
	if err != nil {
		return err
	}
	if len(samples) != 1 || len(samples[0].Value) != 2 {
		return fmt.Errorf("query %q: expected one sample, got %v", expression, samples)
	}
	var text string
	if err := json.Unmarshal(samples[0].Value[1], &text); err != nil {
		return err
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || value != want {
		return fmt.Errorf("query %q: got %s, want %g", expression, text, want)
	}
	return nil
}

func monitoringPromtool(t *testing.T, tool, dir, input string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, tool, args...)
	command.Dir = dir
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "promtool %v:\n%s", args, output)
}

func TestMonitoringPrometheusIntegration(t *testing.T) {
	prometheus := monitoringTool(t, "BIFROEST_E2E_PROMETHEUS", "prometheus")
	promtool := monitoringTool(t, "BIFROEST_E2E_PROMTOOL", "promtool")
	root, err := findRepoRoot()
	require.NoError(t, err)
	goTool, err := findGoTool(root)
	require.NoError(t, err)
	binary := filepath.Join(t.TempDir(), "bifroest")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	build := runCommand(ctx, root, []string{"CGO_ENABLED=0", "GOOS=" + runtime.GOOS, "GOARCH=" + runtime.GOARCH}, goTool, "build", "-p=1", "-o", binary, "./cmd/bifroest")
	cancel()
	require.NoError(t, build.err, "build Bifrost: %s", build.stderr)
	monitoringPromtool(t, promtool, root, "", "--version")
	for _, scenario := range []string{"http", "tls-bearer"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			addresses := monitoringAddresses(t, 4)
			monitorAddress, sshAddress, workloadAddress, promAddress := addresses[0], addresses[1], addresses[2], addresses[3]
			certPath, keyPath, leaf := monitoringTLSFiles(t, dir)
			_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			hostSigner, err := gossh.NewSignerFromKey(hostPrivate)
			require.NoError(t, err)
			hostKey, err := x509.MarshalPKCS8PrivateKey(hostPrivate)
			require.NoError(t, err)
			hostPath := filepath.Join(dir, "ssh-host-key.pem")
			require.NoError(t, bfcrypto.WriteBootstrapFile(hostPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: hostKey}), false))
			const secret, user, password = "monitoring-e2e-secret", "monitoring-qa-user", "monitoring-qa-password"
			monitor := map[string]any{"enabled": true, "addresses": []string{monitorAddress}}
			scheme, token := "http", ""
			pair := []any{map[string]any{"certificateFile": certPath, "privateKeyFile": keyPath}}
			if scenario == "tls-bearer" {
				tokenPath := filepath.Join(dir, "monitoring.token")
				require.NoError(t, os.WriteFile(tokenPath, []byte(secret+"\n"), 0600))
				monitor["bearerTokenFile"] = tokenPath
				monitor["tls"] = map[string]any{"enabled": true, "certificates": pair}
				scheme, token = "https", secret
			}
			configuration := map[string]any{
				"ssh":        map[string]any{"addresses": []string{sshAddress}, "keys": map[string]any{"hostKeys": []string{hostPath}}, "banner": ""},
				"http":       map[string]any{"enabled": true, "addresses": []string{workloadAddress}, "domains": []string{"localhost"}, "webUi": map[string]any{"enabled": false}, "loginFlow": map[string]any{"enabled": false}, "sshTunnel": map[string]any{"enabled": true}, "tls": map[string]any{"certificates": pair, "acme": map[string]any{"enabled": false}}},
				"monitoring": monitor, "session": map[string]any{"type": "fs", "storage": filepath.Join(dir, "sessions")}, "alternatives": map[string]any{"location": filepath.Join(dir, "alternative")}, "housekeeping": map[string]any{"initialDelay": "1h"},
				"flows": []any{map[string]any{"name": "monitoring-qa", "authorization": map[string]any{"type": "simple", "entries": []any{map[string]any{"name": user, "password": "plain:" + password}}}, "environment": map[string]any{"type": "dummy"}}},
			}
			confPath := filepath.Join(dir, "bifroest.yaml")
			monitoringJSONFile(t, confPath, configuration)
			logPrefix := filepath.Join(root, "var", "e2e", fmt.Sprintf("monitoring-%d-%s", time.Now().UnixNano(), scenario))
			bifroest, err := launchProcessWithLogs(root, nil, logPrefix+"-bifroest", binary, "run", "--configuration="+confPath)
			require.NoError(t, err)
			defer bifroest.stop()
			pool := x509.NewCertPool()
			pool.AddCert(leaf)
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			endpoint := scheme + "://" + monitorAddress
			require.NoError(t, pollProcess(20*time.Second, bifroest, func() error {
				status, _, _, err := monitoringHTTP(client, endpoint+"/ready", "", "")
				if err == nil && status != 200 {
					err = fmt.Errorf("readiness HTTP %d", status)
				}
				return err
			}))
			for _, path := range []string{"/status", "/ready"} {
				status, _, _, err := monitoringHTTP(client, endpoint+path, "", "")
				require.NoError(t, err)
				require.Equal(t, 200, status)
			}
			status, _, body, err := monitoringHTTP(client, endpoint+"/missing", token, "")
			require.NoError(t, err)
			require.Equal(t, 404, status)
			require.Empty(t, body)
			if token != "" {
				for _, bad := range []string{"", "incorrect-token"} {
					status, _, _, err := monitoringHTTP(client, endpoint+"/metrics", bad, "")
					require.NoError(t, err)
					require.Equal(t, 401, status)
				}
			}
			status, header, body, err := monitoringHTTP(client, endpoint+"/metrics", token, "application/openmetrics-text; version=1.0.0; charset=utf-8")
			require.NoError(t, err)
			require.Equal(t, 200, status)
			require.Contains(t, header.Get("Content-Type"), "application/openmetrics-text")
			require.True(t, bytes.HasSuffix(body, []byte("# EOF\n")))
			for _, private := range []string{secret, user, password} {
				require.NotContains(t, string(body), private)
			}
			_, _, text, err := monitoringHTTP(client, endpoint+"/metrics", token, "text/plain; version=0.0.4")
			require.NoError(t, err)
			monitoringPromtool(t, promtool, dir, string(text), "check", "metrics")
			job := map[string]any{"job_name": "bifroest", "scheme": scheme, "scrape_protocols": []string{"OpenMetricsText1.0.0"}, "static_configs": []any{map[string]any{"targets": []string{monitorAddress}}}}
			jobs := []any{job}
			if token != "" {
				job["authorization"] = map[string]any{"credentials_file": filepath.Join(dir, "monitoring.token")}
				job["tls_config"] = map[string]any{"ca_file": certPath, "server_name": "localhost"}
				for _, name := range []string{"wrong-token", "untrusted-ca", "wrong-tls-name"} {
					bad := map[string]any{}
					for k, v := range job {
						bad[k] = v
					}
					bad["job_name"] = name
					switch name {
					case "wrong-token":
						bad["authorization"] = map[string]any{"credentials": "incorrect-token"}
					case "untrusted-ca":
						bad["tls_config"] = map[string]any{"server_name": "localhost"}
					case "wrong-tls-name":
						bad["tls_config"] = map[string]any{"ca_file": certPath, "server_name": "incorrect.invalid"}
					}
					jobs = append(jobs, bad)
				}
			}
			promConfig := filepath.Join(dir, "prometheus.yaml")
			monitoringJSONFile(t, promConfig, map[string]any{"global": map[string]any{"scrape_interval": "1s", "scrape_timeout": "750ms"}, "scrape_configs": jobs})
			monitoringPromtool(t, promtool, dir, "", "check", "config", promConfig)
			prom, err := launchProcessWithLogs(root, nil, logPrefix+"-prometheus", prometheus, "--config.file="+promConfig, "--web.listen-address="+promAddress, "--storage.tsdb.path="+filepath.Join(dir, "tsdb"), "--storage.tsdb.retention.time=1h", "--log.level=warn")
			require.NoError(t, err)
			defer prom.stop()
			promURL := "http://" + promAddress
			require.NoError(t, pollProcess(20*time.Second, prom, func() error { return monitoringQueryValue(client, promURL, `up{job="bifroest"}`, 1) }))
			if token != "" {
				for _, name := range []string{"wrong-token", "untrusted-ca", "wrong-tls-name"} {
					require.NoError(t, poll(10*time.Second, func() error { return monitoringQueryValue(client, promURL, `up{job="`+name+`"}`, 0) }))
				}
			}
			// Multiple scrapes and probes must not count as workload HTTP traffic.
			require.NoError(t, poll(10*time.Second, func() error {
				return monitoringQueryValue(client, promURL, `count_over_time(bifroest_ready{job="bifroest"}[1m]) >= bool 3`, 1)
			}))
			require.NoError(t, monitoringQueryValue(client, promURL, `bifroest_http_connections_opened_total{job="bifroest"}`, 0))
			sshClient, err := gossh.Dial("tcp", sshAddress, &gossh.ClientConfig{User: user, Auth: []gossh.AuthMethod{gossh.Password(password)}, HostKeyCallback: gossh.FixedHostKey(hostSigner.PublicKey()), Timeout: 2 * time.Second})
			require.NoError(t, err)
			defer sshClient.Close()
			require.NoError(t, poll(10*time.Second, func() error {
				return monitoringQueryValue(client, promURL, `sum(bifroest_sessions_active{job="bifroest"})`, 1)
			}))
			require.NoError(t, poll(10*time.Second, func() error {
				return monitoringQueryValue(client, promURL, `sum(bifroest_authentication_attempts_total{job="bifroest",result="success"})`, 1)
			}))
			require.NoError(t, poll(10*time.Second, func() error {
				return monitoringQueryValue(client, promURL, `abs(sum(bifroest_sessions_age_sum_seconds{job="bifroest"}) / sum(bifroest_sessions_age_observations{job="bifroest"}) - sum(bifroest_sessions_average_age_seconds{job="bifroest"})) < bool 1e-9`, 1)
			}))
			require.NoError(t, sshClient.Close())
			require.NoError(t, poll(10*time.Second, func() error {
				return monitoringQueryValue(client, promURL, `sum(bifroest_sessions_active{job="bifroest"})`, 0)
			}))
			require.NoError(t, poll(10*time.Second, func() error {
				return monitoringQueryValue(client, promURL, `absent(bifroest_sessions_average_age_seconds{job="bifroest"})`, 1)
			}))
			for range 2 {
				bad, err := gossh.Dial("tcp", sshAddress, &gossh.ClientConfig{User: user, Auth: []gossh.AuthMethod{gossh.Password("incorrect-password")}, HostKeyCallback: gossh.FixedHostKey(hostSigner.PublicKey()), Timeout: 2 * time.Second})
				if bad != nil {
					_ = bad.Close()
				}
				require.Error(t, err)
			}
			require.NoError(t, poll(10*time.Second, func() error {
				return monitoringQueryValue(client, promURL, `sum(bifroest_authentication_attempts_total{job="bifroest",result="denied"})`, 2)
			}))
			_, workloadPort, err := net.SplitHostPort(workloadAddress)
			require.NoError(t, err)
			status, _, _, err = monitoringHTTP(client, "https://localhost:"+workloadPort+"/not-a-route", "", "")
			require.NoError(t, err)
			require.Equal(t, 404, status)
			transport.CloseIdleConnections()
			require.NoError(t, poll(10*time.Second, func() error {
				return monitoringQueryValue(client, promURL, `sum(bifroest_http_requests_total{job="bifroest",route="unknown",status="404"})`, 1)
			}))
			require.NoError(t, poll(10*time.Second, func() error {
				return monitoringQueryValue(client, promURL, `bifroest_http_connections_active{job="bifroest"}`, 0)
			}))
			t.Logf("real OpenMetrics scrape and TLS/token negative controls passed; logs: %s", logPrefix)
		})
	}
}

func monitoringGuideRules(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "docs", "guides", "monitoring.md"))
	require.NoError(t, err)
	match := regexp.MustCompile("(?s)```yaml title=\"Prometheus alert rules\"\\n(.*?)\\n```").FindSubmatch(data)
	require.Len(t, match, 2, "test the documented rules, never a hand-maintained copy")
	return string(match[1])
}
