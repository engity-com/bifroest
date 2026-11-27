package https

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func proxyTestRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://backend.internal/api/v1/discovery", nil)
	r.URL.Scheme, r.URL.Host = "", "" // Real server requests use origin-form.
	r.RemoteAddr = "10.1.2.3:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.org")
	r.Header.Set("X-Forwarded-Prefix", "/team/bifroest")
	r.Header.Set("X-Forwarded-For", "198.51.100.42, 10.1.2.2")
	r.Header.Set("Origin", "https://app.example.org")
	return r
}

func proxyTestConf(t *testing.T) *configuration.Http {
	t.Helper()
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls = nil
	conf.Upstream = configuration.HttpUpstream{Mode: "reverseProxy", TrustedPeers: configuration.HttpTrustedPeers{"private"}}
	return conf
}

func TestProxyBoundaryUsesOnlyExplicitlyTrustedMetadata(t *testing.T) {
	conf := proxyTestConf(t)
	var called bool
	handler, err := httpBoundary(conf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		info, ok := UpstreamOf(r)
		require.True(t, ok)
		require.Equal(t, "https://app.example.org", info.Origin)
		require.Equal(t, "/team/bifroest", info.PathPrefix)
		require.Equal(t, netip.MustParseAddr("198.51.100.42"), info.Client)
		require.Equal(t, netip.MustParseAddr("10.1.2.3"), info.Proxy)
		require.Equal(t, "198.51.100.42:0", r.RemoteAddr)
		require.Nil(t, r.TLS, "never forge backend TLS state")
		require.Equal(t, "/api/v1/discovery", r.URL.Path)
		w.WriteHeader(204)
	}), false)
	require.NoError(t, err)
	r := proxyTestRequest()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, 204, w.Code)
	require.True(t, called)
	require.Equal(t, "10.1.2.3:1234", r.RemoteAddr, "original transport request is not mutated")
	_, ok := UpstreamOf(r)
	require.False(t, ok)
}

func TestProxyBoundaryRejectsSpoofedAndAmbiguousMetadata(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"untrusted peer", func(r *http.Request) { r.RemoteAddr = "198.51.100.1:22" }},
		{"missing scheme", func(r *http.Request) { r.Header.Del("X-Forwarded-Proto") }},
		{"insecure public scheme", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") }},
		{"duplicate scheme", func(r *http.Request) { r.Header.Add("X-Forwarded-Proto", "https") }},
		{"scheme list", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https,http") }},
		{"unknown host", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "evil.example.org") }},
		{"host list", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "app.example.org,evil.example.org") }},
		{"empty host", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "") }},
		{"duplicate host", func(r *http.Request) { r.Header.Add("X-Forwarded-Host", "app.example.org") }},
		{"empty port", func(r *http.Request) { r.Header.Set("X-Forwarded-Port", "") }},
		{"zero port", func(r *http.Request) { r.Header.Set("X-Forwarded-Port", "0") }},
		{"duplicate prefix", func(r *http.Request) { r.Header.Add("X-Forwarded-Prefix", "/other") }},
		{"encoded prefix", func(r *http.Request) { r.Header.Set("X-Forwarded-Prefix", "/a%2fb") }},
		{"prefix traversal", func(r *http.Request) { r.Header.Set("X-Forwarded-Prefix", "/a/../b") }},
		{"missing chain", func(r *http.Request) { r.Header.Del("X-Forwarded-For") }},
		{"duplicate chain", func(r *http.Request) { r.Header.Add("X-Forwarded-For", "192.0.2.1") }},
		{"bad chain", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "unknown") }},
		{"conflicting port", func(r *http.Request) {
			r.Header.Set("X-Forwarded-Host", "app.example.org:443")
			r.Header.Set("X-Forwarded-Port", "8443")
		}},
		{"cross-origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example.org") }},
		{"missing origin", func(r *http.Request) { r.Header.Del("Origin") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, err := httpBoundary(proxyTestConf(t), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("rejected request reached handler") }), false)
			require.NoError(t, err)
			r := proxyTestRequest()
			test.change(r)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			require.GreaterOrEqual(t, w.Code, 400)
		})
	}
}

func TestProxyChainStopsAtFirstUntrustedHop(t *testing.T) {
	r := proxyTestRequest()
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.9, 10.2.3.4")
	request, err := proxyRequest(proxyTestConf(t).Upstream, r)
	require.NoError(t, err)
	info, _ := UpstreamOf(request)
	require.Equal(t, "198.51.100.9", info.Client.String(), "ignore client-controlled entries before the first untrusted hop")
}

func TestProxyRootDoesNotInheritSSHDefaultPrefix(t *testing.T) {
	conf := proxyTestConf(t)
	conf.Upstream.DefaultPrefix = "/ssh-login"
	r := proxyTestRequest()
	r.Header.Del("X-Forwarded-Prefix")
	r.Header.Del("X-Forwarded-Host")
	r.Host = "app.example.org"
	r.Header.Set("X-Forwarded-Port", "8443")
	r.Header.Set("Origin", "https://app.example.org:8443")
	request, err := proxyRequest(conf.Upstream, r)
	require.NoError(t, err)
	require.Empty(t, PathPrefix(request))
	require.Equal(t, "app.example.org:8443", request.Host)
}

func TestDirectModeNeverTrustsProxyHeaders(t *testing.T) {
	handler, err := Boundary(configuration.HttpDomains{"app.example.org"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := UpstreamOf(r)
		require.False(t, ok)
		require.Empty(t, PathPrefix(r))
		require.Equal(t, "10.1.2.3:1234", r.RemoteAddr)
		w.WriteHeader(204)
	}))
	require.NoError(t, err)
	r := proxyTestRequest()
	r.Host = "app.example.org"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, 400, w.Code)
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "app.example.org"}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, 204, w.Code)
}

func TestPlainProxyEndpointDoesNotPrepareCertificateSources(t *testing.T) {
	endpoint, err := NewEndpoint(proxyTestConf(t), EndpointOptions{})
	require.NoError(t, err)
	require.False(t, endpoint.Ready())
	require.Nil(t, endpoint.server.TLSConfig)
	require.NoError(t, endpoint.Prepare(context.Background()))
	require.True(t, endpoint.Ready())
	done := make(chan error, 1)
	go func() { done <- endpoint.RunFileReload(context.Background(), nil) }()
	require.NoError(t, endpoint.Close())
	require.False(t, endpoint.Ready())
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("plain proxy lifecycle did not stop on close")
	}
	require.ErrorIs(t, endpoint.Prepare(context.Background()), ErrClosed)
}
