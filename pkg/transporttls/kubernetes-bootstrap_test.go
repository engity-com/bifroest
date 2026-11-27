//go:build tls_bootstrap_fixture

package transporttls_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/transporttls"
)

func TestKubernetesTLSBootstrap(t *testing.T) {
	require.Equal(t, 10001, os.Geteuid(), "fixture must run rootless with the chart security context")
	begin, finish := make(chan struct{}), make(chan struct{})
	var beginOnce, finishOnce sync.Once
	directory, trust, root, counts := transporttls.KubernetesCAFixture(t, "bootstrap-bifroest-http:443", begin)
	t.Cleanup(func() { beginOnce.Do(func() { close(begin) }) })
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromFile("/etc/engity/bifroest/configuration.yaml"))
	conf.HouseKeeping.Every.SetNative(100 * time.Millisecond)
	profile := conf.Tls["public"]
	_, err := os.Stat(profile.Acme.Storage)
	require.True(t, os.IsNotExist(err), "test requires a fresh PVC, not a cached certificate")
	profile.Acme.DirectoryUrl = directory
	conf.Tls["public"] = profile
	raw, err := yaml.Marshal(conf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile("/tmp/configuration.yaml", raw, 0600))
	require.NoError(t, os.WriteFile("/tmp/test-ca.pem", trust, 0600))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/bifroest", "run", "--configuration=/tmp/configuration.yaml")
	command.Env = append(os.Environ(), "SSL_CERT_FILE=/tmp/test-ca.pem")
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	require.NoError(t, command.Start())
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Bifröst child did not drain")
		}
	})
	control := &http.Server{Addr: "127.0.0.1:9091", ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/begin":
			beginOnce.Do(func() { close(begin) })
		case "/finish":
			finishOnce.Do(func() { close(finish) })
		default:
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = control.ListenAndServe() }()
	t.Cleanup(func() { _ = control.Close() })
	localClient := &http.Client{Timeout: time.Second}
	status := func(path string) int {
		response, err := localClient.Get("http://127.0.0.1:9090" + path)
		if err != nil {
			return 0
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	require.Eventually(t, func() bool { return status("/status") == 200 && status("/ready") == 503 }, 30*time.Second, 50*time.Millisecond)
	require.Eventually(t, func() bool { _, registrations := counts(); return registrations == 1 }, 30*time.Second, 50*time.Millisecond)
	// A Service routing an unready Pod must still not expose its application.
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "app.example.org", RootCAs: x509.NewCertPool()}
	clientTLS.RootCAs.AddCert(root)
	dial := func() (net.Conn, error) {
		ctx, stop := context.WithTimeout(t.Context(), 3*time.Second)
		defer stop()
		return (&tls.Dialer{Config: clientTLS}).DialContext(ctx, "tcp", "bootstrap-bifroest-http:443")
	}
	connection, err := dial()
	if connection != nil {
		_ = connection.Close()
	}
	require.Error(t, err, "application handshake must be blocked before certificate preparation")
	fmt.Println("TLS_BOOTSTRAP_PENDING")
	require.Eventually(t, func() bool { return status("/ready") == 200 }, 60*time.Second, 50*time.Millisecond)
	expiry := func() float64 {
		response, err := localClient.Get("http://127.0.0.1:9090/metrics")
		if err != nil {
			return 0
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			return 0
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "bifroest_tls_certificate_expiration_timestamp_seconds{") &&
				strings.Contains(line, `source="tls:public"`) && strings.Contains(line, `name="app.example.org"`) {
				fields := strings.Fields(line)
				if len(fields) == 2 {
					value, _ := strconv.ParseFloat(fields[1], 64)
					return value
				}
			}
		}
		return 0
	}
	var first []byte
	firstExpiry := float64(0)
	if conf.Http.IsAcmeTlsAlpnOnly() {
		connection, err = dial()
		if connection != nil {
			_ = connection.Close()
		}
		require.Error(t, err, "ALPN-only must not serve application TLS after readiness")
		firstExpiry = expiry()
		require.Positive(t, firstExpiry)
	} else {
		connection, err = dial()
		require.NoError(t, err)
		first = connection.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw
		require.NoError(t, connection.Close())
	}
	fmt.Println("TLS_BOOTSTRAP_READY")
	require.Eventually(t, func() bool {
		issuances, registrations := counts()
		if registrations != 1 || issuances < 2 {
			return false
		}
		if conf.Http.IsAcmeTlsAlpnOnly() {
			return expiry() > firstExpiry
		}
		connection, err := dial()
		if err != nil {
			return false
		}
		defer connection.Close()
		return !bytes.Equal(first, connection.(*tls.Conn).ConnectionState().PeerCertificates[0].Raw)
	}, 30*time.Second, 100*time.Millisecond)
	if conf.Http.IsAcmeTlsAlpnOnly() {
		connection, err = dial()
		if connection != nil {
			_ = connection.Close()
		}
		require.Error(t, err, "renewal must not enable application TLS")
	}
	fmt.Println("TLS_BOOTSTRAP_RENEWED")
	select {
	case <-finish:
	case err := <-done:
		done <- err
		t.Fatalf("Bifröst stopped before fixture completion: %v", err)
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}
