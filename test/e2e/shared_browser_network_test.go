//go:build e2e

package e2e_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Docker's host interface changes cause Chromium to abort even unrelated
// loopback requests with ERR_NETWORK_CHANGED. Keep the browser in its own
// network namespace and relay only the fixture's TCP port. TLS, HTTP, WASM and
// WebSockets still use the real browser and server; no request is intercepted
// or replayed. Other hosts do not use Chromium's Linux network notifier.
func sharedBrowserCommand(origin, executable string, args ...string) (string, []string, error) {
	if runtime.GOOS != "linux" {
		return executable, args, nil
	}
	isolated, err := sharedBrowserNetworkArguments(origin, executable, args...)
	if err != nil {
		return "", nil, err
	}
	pasta, err := exec.LookPath("pasta")
	if err != nil {
		return "", nil, fmt.Errorf("Linux browser E2E needs pasta network isolation; install the passt package: %w", err)
	}
	return pasta, isolated, nil
}

func sharedBrowserNetworkArguments(origin, executable string, args ...string) ([]string, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("invalid browser fixture origin: %w", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || u.Scheme != "https" || u.Hostname() != "app.example.org" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || executable == "" {
		return nil, fmt.Errorf("expected a public HTTPS fixture origin with an explicit port")
	}
	result := []string{
		"--quiet", "--config-net", "--ipv4-only", "--splice-only",
		"--tcp-ports", "none", "--udp-ports", "none",
		"--tcp-ns", strconv.Itoa(port), "--udp-ns", "none",
		"--", executable,
	}
	return append(result, args...), nil
}

func TestSharedBrowserNetworkArguments(t *testing.T) {
	for _, origin := range []string{
		"http://app.example.org:443", "https://other.example.org:443",
		"https://app.example.org", "https://app.example.org:0", "https://app.example.org:65536",
		"https://user@app.example.org:443", "https://app.example.org:443/",
		"https://app.example.org:443?", "https://app.example.org:443?token=secret", "https://app.example.org:443/#Work",
	} {
		if _, err := sharedBrowserNetworkArguments(origin, "node", "browser.ts"); err == nil {
			t.Errorf("accepted unexpected origin %q", origin)
		}
	}
	args, err := sharedBrowserNetworkArguments("https://app.example.org:18443", "node", "browser.ts", "unchanged-argument")
	if err != nil {
		t.Fatal(err)
	}
	want := "--quiet --config-net --ipv4-only --splice-only --tcp-ports none --udp-ports none --tcp-ns 18443 --udp-ns none -- node browser.ts unchanged-argument"
	if strings.Join(args, " ") != want {
		t.Fatalf("isolation must relay only the fixture port and retain the command: %q", args)
	}
}

func TestSharedBrowserNetworkIsolation(t *testing.T) {
	const probeEnv = "BIFROEST_TEST_BROWSER_NETWORK_PROBE"
	const certificateEnv = "BIFROEST_TEST_BROWSER_NETWORK_CERTIFICATE"
	if endpoint := os.Getenv(probeEnv); endpoint != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(os.Getenv(certificateEnv))) {
			t.Fatal("missing fixture TLS trust")
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 5 * time.Second}
		defer client.CloseIdleConnections()
		response, err := client.Get(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("fixture HTTPS response: status=%d error=%v", response.StatusCode, err)
		}
		namespace, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"namespace": namespace, "body": string(body)}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux network namespace integration")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "real-https-through-isolated-loopback")
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	command, args, err := sharedBrowserCommand("https://app.example.org:"+u.Port(), os.Args[0], "-test.run=^TestSharedBrowserNetworkIsolation$", "-test.timeout=20s")
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	result := runCommand(ctx, "", []string{probeEnv + "=" + server.URL, certificateEnv + "=" + string(certificate)}, command, args...)
	if result.err != nil {
		t.Fatalf("isolated browser transport: %v\n%s\n%s", result.err, result.stdout, result.stderr)
	}
	var probe struct{ Namespace, Body string }
	if err := json.NewDecoder(strings.NewReader(result.stdout)).Decode(&probe); err != nil {
		t.Fatal(err)
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if probe.Namespace == namespace || probe.Namespace == "" || probe.Body != "real-https-through-isolated-loopback" {
		t.Fatalf("HTTPS must reach the real host listener from a separate network namespace: %+v, host=%s", probe, namespace)
	}
	command, args, err = sharedBrowserCommand("https://app.example.org:"+u.Port(), "/bin/sh", "-c", "exit 23")
	if err != nil {
		t.Fatal(err)
	}
	failed := runCommand(ctx, "", nil, command, args...)
	var exit *exec.ExitError
	if !errors.As(failed.err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("network isolation must preserve browser command failures: %v\n%s", failed.err, failed.stderr)
	}
}
