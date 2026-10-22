package https

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

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
		{"cross-site internal fetch", func(r *http.Request) {
			r.URL.Path = "/_bifroest/api/test"
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
