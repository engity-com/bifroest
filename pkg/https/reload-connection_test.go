package https

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestTLSReloadPreservesExistingConnectionAndUpdatesNewHandshakes(t *testing.T) {
	first := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	second := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Acme.Enabled = false
	conf.Tls.Certificates = []configuration.HttpCertificate{first.configured}
	endpoint, err := NewEndpoint(conf, EndpointOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "alive") })})
	require.NoError(t, err)
	require.NoError(t, endpoint.Prepare(t.Context()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- endpoint.Serve(listener) }()
	t.Cleanup(func() { require.NoError(t, endpoint.Close()); require.ErrorIs(t, <-done, http.ErrServerClosed) })
	pool := x509.NewCertPool()
	pool.AddCert(first.root)
	pool.AddCert(second.root)
	transport := func() *http.Transport {
		return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		}}
	}
	one, two := transport(), transport()
	defer one.CloseIdleConnections()
	defer two.CloseIdleConnections()
	get := func(tr *http.Transport) *tls.ConnectionState {
		t.Helper()
		response, err := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Get("https://app.example.org/")
		require.NoError(t, err)
		_, err = io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, 200, response.StatusCode)
		return response.TLS
	}
	old := get(one)
	require.Equal(t, first.certificate.Certificate[0], old.PeerCertificates[0].Raw)
	copyReloadPair(t, second.configured, first.configured)
	require.NoError(t, endpoint.tls.ReloadFiles(t.Context()))
	reused := get(one)
	require.Equal(t, old.PeerCertificates[0].Raw, reused.PeerCertificates[0].Raw, "rotation must not close an existing TLS connection")
	fresh := get(two)
	require.Equal(t, second.certificate.Certificate[0], fresh.PeerCertificates[0].Raw)
}
