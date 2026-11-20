package https

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestSshTunnelBoundaryExceptionIsNarrow(t *testing.T) {
	for _, test := range []struct {
		name, path, origin, fetch, host string
		enabled                         bool
		status                          int
	}{
		{"native tunnel", SshTunnelPath, "", "", "app.example.org", true, 204},
		{"same origin", SshTunnelPath, "https://app.example.org", "same-origin", "app.example.org", true, 204},
		{"cross origin", SshTunnelPath, "https://evil.example.org", "", "app.example.org", true, 403},
		{"cross site", SshTunnelPath, "", "cross-site", "app.example.org", true, 403},
		{"wrong authority", SshTunnelPath, "", "", "evil.example.org", true, 421},
		{"disabled tunnel", SshTunnelPath, "", "", "app.example.org", false, 403},
		{"other API", "/api/v1/login/password", "", "", "app.example.org", true, 403},
		{"trailing slash", SshTunnelPath + "/", "", "", "app.example.org", true, 403},
		{"encoded alias", "/api/v1/%73sh", "", "", "app.example.org", true, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, err := boundary(configuration.HttpDomains{"app.example.org"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := io.Copy(io.Discard, r.Body)
				require.NoError(t, err)
				w.WriteHeader(204)
			}), test.enabled)
			require.NoError(t, err)
			r := httptest.NewRequest("POST", test.path, strings.NewReader(strings.Repeat("x", 2<<20)))
			r.Host = test.host
			r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "app.example.org"}
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			r.Header.Set("Sec-Fetch-Site", test.fetch)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			require.Equal(t, test.status, w.Code)
		})
	}
}

func TestBrowserKeyWorkerCspDoesNotEnableDocumentEval(t *testing.T) {
	policy, err := DocumentPolicy(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	require.NoError(t, err)
	require.Contains(t, policy, "worker-src 'self'")
	require.NotContains(t, policy, "unsafe-eval")
	require.NotContains(t, policy, "unsafe-inline")
	require.Contains(t, BrowserKeyWorkerPolicy, "'wasm-unsafe-eval'")
	require.NotContains(t, BrowserKeyWorkerPolicy, "'unsafe-eval'")
	require.Contains(t, BrowserKeyWorkerPolicy, "worker-src 'none'")
}

func TestHTTPSBoundaryEnforcesHostSniOriginAndHeaders(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"ordinary navigation", func(*http.Request) {}, 204},
		{"canonical host", func(r *http.Request) { r.Host = "APP.Example.org.:443" }, 204},
		{"same-origin POST", func(r *http.Request) { r.Method = "POST"; r.Header.Set("Origin", "https://app.example.org:443") }, 204},
		{"missing TLS", func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Proto", "https") }, 400},
		{"unconfigured host", func(r *http.Request) { r.Host = "evil.example.org" }, 421},
		{"other configured host with wrong SNI", func(r *http.Request) { r.Host = "other.example.org" }, 421},
		{"missing DNS SNI", func(r *http.Request) { r.TLS.ServerName = "" }, 421},
		{"cross-origin GET", func(r *http.Request) { r.Header.Set("Origin", "https://other.example.org") }, 403},
		{"wrong port", func(r *http.Request) { r.Header.Set("Origin", "https://app.example.org:444") }, 403},
		{"null origin", func(r *http.Request) { r.Header.Set("Origin", "null") }, 403},
		{"multiple origins", func(r *http.Request) {
			r.Header.Add("Origin", "https://app.example.org")
			r.Header.Add("Origin", "https://app.example.org")
		}, 403},
		{"origin path", func(r *http.Request) { r.Header.Set("Origin", "https://app.example.org/") }, 403},
		{"origin query", func(r *http.Request) { r.Header.Set("Origin", "https://app.example.org?") }, 403},
		{"empty origin fragment", func(r *http.Request) { r.Header.Set("Origin", "https://app.example.org#") }, 403},
		{"origin credentials", func(r *http.Request) { r.Header.Set("Origin", "https://user@app.example.org") }, 403},
		{"POST without origin", func(r *http.Request) { r.Method = "POST" }, 403},
		{"websocket without origin", func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }, 403},
		{"websocket with origin", func(r *http.Request) {
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Origin", "https://app.example.org")
		}, 204},
		{"cross-site API fetch", func(r *http.Request) {
			r.URL.Path = "/api/test"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}, 403},
		{"cross-site API root", func(r *http.Request) {
			r.URL.Path = "/api"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}, 403},
		{"cross-site asset fetch", func(r *http.Request) {
			r.URL.Path = "/assets/browser-key.wasm"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}, 403},
		{"OIDC login top-level navigation", func(r *http.Request) {
			r.URL.Path = "/login/"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		}, 204},
		{"OIDC login without slash top-level navigation", func(r *http.Request) {
			r.URL.Path = "/login"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
			r.Header.Set("Origin", "https://mail.example.net")
		}, 204},
		{"OIDC login HEAD navigation", func(r *http.Request) {
			r.Method, r.URL.Path = "HEAD", "/login/"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		}, 204},
		{"OIDC login fetch not exempt", func(r *http.Request) {
			r.URL.Path = "/login/"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "cors")
			r.Header.Set("Sec-Fetch-Dest", "empty")
		}, 403},
		{"OIDC login frame not exempt", func(r *http.Request) {
			r.URL.Path = "/login/"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "iframe")
		}, 403},
		{"OIDC login POST navigation not exempt", func(r *http.Request) {
			r.Method, r.URL.Path = "POST", "/login/"
			r.Header.Set("Origin", "https://app.example.org")
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		}, 403},
		{"OIDC login websocket not exempt", func(r *http.Request) {
			r.URL.Path = "/login/"
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Origin", "https://app.example.org")
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		}, 403},
		{"OIDC API navigation not exempt", func(r *http.Request) {
			r.URL.Path = "/api/v1/oidc/start"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		}, 403},
		{"asset navigation not exempt", func(r *http.Request) {
			r.URL.Path = "/assets/browser-key.wasm"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		}, 403},
		{"OIDC callback top-level redirect", func(r *http.Request) {
			r.URL.Path = configuration.OidcCallbackPath
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Origin", "https://idp.example.org")
		}, 204},
		{"OIDC callback POST not exempt", func(r *http.Request) {
			r.Method, r.URL.Path = "POST", configuration.OidcCallbackPath
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Origin", "https://idp.example.org")
		}, 403},
		{"OIDC callback websocket not exempt", func(r *http.Request) {
			r.URL.Path = configuration.OidcCallbackPath
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Origin", "https://idp.example.org")
		}, 403},
		{"OIDC other route not exempt", func(r *http.Request) {
			r.URL.Path = "/login/request/anything"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}, 403},
		{"OIDC callback suffix not exempt", func(r *http.Request) {
			r.URL.Path = configuration.OidcCallbackPath + "/"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}, 403},
		{"encoded alias", func(r *http.Request) { r.URL.RawPath = "/%77ork"; r.URL.Path = "/work" }, 400},
		{"dot path", func(r *http.Request) { r.URL.Path = "/a/../work" }, 400},
		{"backslash path", func(r *http.Request) { r.URL.Path = "/a\\work" }, 400},
		{"CONNECT", func(r *http.Request) { r.Method = "CONNECT" }, 400},
		{"absolute form", func(r *http.Request) { r.URL.Scheme = "https"; r.URL.Host = r.Host }, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			boundary, err := Boundary(configuration.HttpDomains{"app.example.org", "other.example.org"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
			require.NoError(t, err)
			request := httptest.NewRequest("GET", "/work", nil)
			request.Host = "app.example.org"
			request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "app.example.org"}
			test.change(request)
			response := httptest.NewRecorder()
			boundary.ServeHTTP(response, request)
			require.Equal(t, test.status, response.Code)
			require.Equal(t, "DENY", response.Header().Get("X-Frame-Options"))
			require.Contains(t, response.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			require.Empty(t, response.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestHTTPSBoundaryAllowsOnlyAnUnambiguousIpWithoutSni(t *testing.T) {
	for _, domains := range []configuration.HttpDomains{{"127.0.0.1"}, {"[::1]"}, {"127.0.0.1", "app.example.org"}} {
		boundary, err := Boundary(domains, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
		require.NoError(t, err)
		request := httptest.NewRequest("GET", "/", nil)
		request.Host = domains[0]
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		response := httptest.NewRecorder()
		boundary.ServeHTTP(response, request)
		if len(domains) == 1 {
			require.Equal(t, 204, response.Code)
		} else {
			require.Equal(t, 421, response.Code)
		}
	}
}
