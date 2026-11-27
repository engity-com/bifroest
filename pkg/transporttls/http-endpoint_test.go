package transporttls_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/transporttls"
)

func TestHTTPSEndpointUsesRealListenerForLocalAcmeProofs(t *testing.T) {
	conf, source, root, probe, proofs := transporttls.AcmeEndpointFixture(t)
	endpoint, err := https.NewEndpoint(conf, https.EndpointOptions{Source: source})
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- endpoint.Serve(listener) }()
	t.Cleanup(func() { require.NoError(t, endpoint.Close()); require.ErrorIs(t, <-done, http.ErrServerClosed) })
	probe(listener.Addr().String())
	require.NoError(t, endpoint.Prepare(t.Context()))
	require.True(t, endpoint.Ready())
	require.Equal(t, 1, proofs())
	pool := x509.NewCertPool()
	pool.AddCert(root)
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		}}
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://app.example.org/")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusNotImplemented, response.StatusCode)
}
