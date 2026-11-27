package service

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/https"
)

func TestHttpUpstreamRealTLSIngressAndPlainBackendKeepAccessPrefixBound(t *testing.T) {
	svc, _, _ := webTestFixture(t)
	conf := &configuration.Http{}
	require.NoError(t, conf.SetDefaults())
	conf.Enabled, conf.Domains = configuration.HttpEnabled, configuration.HttpDomains{"app.example.org"}
	conf.Upstream = configuration.HttpUpstream{Mode: "reverseProxy", TrustedPeers: configuration.HttpTrustedPeers{"127.0.0.1"}}
	svc.Configuration.Http = conf
	seen := make(chan https.UpstreamRequest, 8)
	endpoint, err := https.NewEndpoint(conf, https.EndpointOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Error("backend unexpectedly uses TLS")
		}
		info, ok := https.UpstreamOf(r)
		if !ok {
			t.Error("missing validated upstream context")
		}
		seen <- info
		svc.web.ServeHTTP(w, r)
	})})
	require.NoError(t, err)
	require.NoError(t, endpoint.Prepare(t.Context()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- endpoint.Serve(listener) }()
	t.Cleanup(func() { require.NoError(t, endpoint.Close()); require.ErrorIs(t, <-done, http.ErrServerClosed) })
	backend, err := url.Parse("http://" + listener.Addr().String())
	require.NoError(t, err)
	proxy := &httputil.ReverseProxy{Rewrite: func(request *httputil.ProxyRequest) {
		if request.In.TLS == nil {
			t.Error("ingress accepted plaintext")
		}
		request.SetURL(backend)
		prefix := "/bifroest"
		if strings.HasPrefix(request.In.URL.Path, "/other/") {
			prefix = "/other"
		}
		request.Out.URL.Path = strings.TrimPrefix(request.In.URL.Path, prefix)
		request.Out.Host = request.In.Host
		request.Out.Header.Set("X-Forwarded-Proto", "https")
		request.Out.Header.Set("X-Forwarded-Prefix", prefix)
		request.Out.Header.Set("X-Forwarded-For", "198.51.100.42")
	}}
	ingress := httptest.NewTLSServer(proxy)
	defer ingress.Close()
	client := ingress.Client()
	client.Timeout = 3 * time.Second
	post := func(prefix, action, body, token string) (int, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ingress.URL+prefix+webAPI+action, strings.NewReader(body))
		require.NoError(t, err)
		r.Host = "app.example.org"
		r.Header.Set("Origin", "https://app.example.org")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-For", "203.0.113.66") // Must be overwritten by ingress.
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(r)
		require.NoError(t, err)
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		return response.StatusCode, data
	}
	status, body := post("/bifroest", "login/password", `{"slug":"Work","user":"alice","password":"correct"}`, "")
	require.Equal(t, 200, status, string(body))
	info := <-seen
	require.Equal(t, "198.51.100.42", info.Client.String())
	require.Equal(t, "127.0.0.1", info.Proxy.String())
	var access struct {
		AccessToken string `json:"accessToken"`
	}
	require.NoError(t, json.Unmarshal(body, &access))
	require.NotEmpty(t, access.AccessToken)
	status, body = post("/bifroest", "access", `{"slug":"Work"}`, access.AccessToken)
	require.Equal(t, 200, status, string(body))
	status, _ = post("/other", "access", `{"slug":"Work"}`, access.AccessToken)
	require.Equal(t, 401, status, "same origin does not accidentally reuse a token at another mount")
	for _, mount := range []string{"/bifroest", "/other"} {
		dialer := websocket.Dialer{
			TLSClientConfig: client.Transport.(*http.Transport).TLSClientConfig.Clone(),
			Subprotocols:    []string{webTerminalProtocol}, HandshakeTimeout: 3 * time.Second,
		}
		socket, response, err := dialer.Dial(strings.Replace(ingress.URL, "https://", "wss://", 1)+mount+webAPI+"terminal", http.Header{"Host": {"app.example.org"}, "Origin": {"https://app.example.org"}})
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		require.NoError(t, err)
		require.NoError(t, socket.WriteJSON(webSocketOpen(access.AccessToken)))
		if mount == "/bifroest" {
			requireWebSocketReady(t, socket)
			_, _, status := webSocketResult(t, socket)
			require.Equal(t, `"exit"`, string(status["type"]))
		} else {
			require.Equal(t, `"authentication-denied"`, string(webSocketStatus(t, socket)["code"]))
		}
		require.NoError(t, socket.Close())
	}
	r, err := http.NewRequestWithContext(context.Background(), "POST", backend.String()+webAPI+"discovery", strings.NewReader(`{"slug":"Work"}`))
	require.NoError(t, err)
	response, err := http.DefaultClient.Do(r)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, 400, response.StatusCode, "plain backend without ingress metadata is rejected")
}
