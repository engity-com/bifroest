package https

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func startEndpointTestListener(t *testing.T, endpoint *Endpoint) (net.Listener, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- endpoint.Serve(listener) }()
	t.Cleanup(func() {
		require.NoError(t, endpoint.Close())
		select {
		case err := <-done:
			require.ErrorIs(t, err, http.ErrServerClosed)
		case <-time.After(5 * time.Second):
			t.Error("HTTPS Serve did not stop")
		}
	})
	return listener, done
}

func endpointTestClient(t *testing.T, listener net.Listener, root *x509.Certificate) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(root)
	transport := &http.Transport{
		ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func TestHTTPSEndpointServesRealHttp2AndChecksAuthorities(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org", "other.example.org"}, true, nil)
	conf := newTlsTestConfiguration(t, "app.example.org", "other.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
	endpoint, err := NewEndpoint(conf, EndpointOptions{})
	require.NoError(t, err)
	listener, _ := startEndpointTestListener(t, endpoint)
	client := endpointTestClient(t, listener, fixture.root)
	_, err = client.Get("https://app.example.org/work")
	require.Error(t, err, "normal TLS must fail before preparation")
	require.NoError(t, endpoint.Prepare(context.Background()))
	response, err := client.Get("https://app.example.org/work")
	require.NoError(t, err)
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.Equal(t, 2, response.ProtoMajor)
	require.Equal(t, http.StatusNotImplemented, response.StatusCode)
	require.Equal(t, "DENY", response.Header.Get("X-Frame-Options"))
	request, err := http.NewRequestWithContext(context.Background(), "GET", "https://app.example.org/work", nil)
	require.NoError(t, err)
	request.Host = "other.example.org"
	response, err = client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusMisdirectedRequest, response.StatusCode)
	require.Nil(t, endpoint.source.value, "explicit coverage must not open ACME storage")
}

func TestHTTPSEndpointUsesRealListenerForLocalAcmeProofs(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Acme.DirectoryUrl = ca.server.URL + "/directory"
	conf.Tls.Acme.Storage = filepath.Join(t.TempDir(), "acme")
	source, err := newACME(conf, ca.server.Client(), clock.now)
	require.NoError(t, err)
	defer source.Close()
	endpoint, err := NewEndpoint(conf, EndpointOptions{Source: source})
	require.NoError(t, err)
	endpoint.tls.now = clock.now
	listener, _ := startEndpointTestListener(t, endpoint)
	ca.setProbe(listener.Addr().String())
	require.NoError(t, endpoint.Prepare(context.Background()))
	require.True(t, endpoint.Ready())
	require.Equal(t, 1, ca.counts().proofs)
	client := endpointTestClient(t, listener, ca.root)
	response, err := client.Get("https://app.example.org/")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusNotImplemented, response.StatusCode)
}

func TestHTTPSEndpointKeyRejectionPreventsReadiness(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, true, nil)
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
	_, err := NewEndpoint(conf, EndpointOptions{ValidateKey: func(crypto.PublicKey) error { return errors.New("forbidden key reuse") }})
	require.ErrorContains(t, err, "forbidden key reuse")
}

func TestHTTPSEndpointForcedShutdownCancelsSlowRequest(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, true, nil)
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
	conf.GracefulShutdownTimeout = common.DurationOf(30 * time.Millisecond)
	started, stopped := make(chan struct{}), make(chan struct{})
	endpoint, err := NewEndpoint(conf, EndpointOptions{Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(stopped) })})
	require.NoError(t, err)
	listener, _ := startEndpointTestListener(t, endpoint)
	require.NoError(t, endpoint.Prepare(context.Background()))
	client := endpointTestClient(t, listener, fixture.root)
	done := make(chan error, 1)
	go func() {
		response, err := client.Get("https://app.example.org/")
		if response != nil {
			_ = response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	require.NoError(t, endpoint.Close())
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("request was not canceled")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client did not finish")
	}
}
