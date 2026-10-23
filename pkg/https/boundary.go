package https

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/engity-com/bifroest/pkg/configuration"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

// DocumentPolicy adds only a fresh server-generated nonce. Inline event handlers,
// eval, framing and remote script/style URLs remain disallowed; callers must not
// take this value from a request or persisted/browser authentication state.
func DocumentPolicy(nonce string) (string, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(nonce)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != nonce {
		return "", fmt.Errorf("invalid document nonce")
	}
	return "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self' 'nonce-" + nonce + "'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'", nil
}

// Boundary enforces the directly terminated HTTPS authority and browser origin.
// Forwarded/X-Forwarded-* headers never substitute for TLS, SNI, Host or Origin.
func Boundary(domains configuration.HttpDomains, next http.Handler) (http.Handler, error) {
	canonical, err := domains.Canonical()
	if err != nil || len(canonical) == 0 {
		return nil, fmt.Errorf("HTTPS boundary needs configured domains")
	}
	allowed := make(map[string]bool, len(canonical))
	for _, domain := range canonical {
		allowed[domain] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS12 || r.URL == nil || r.URL.IsAbs() || r.URL.Opaque != "" || r.URL.User != nil || r.Method == http.MethodConnect {
			http.Error(w, "direct HTTPS request required", http.StatusBadRequest)
			return
		}
		host, err := bnet.CanonicalHttpHost(r.Host)
		if err != nil || !allowed[host] {
			http.Error(w, "request authority is not configured", http.StatusMisdirectedRequest)
			return
		}
		name := r.TLS.ServerName
		if name == "" && len(canonical) == 1 {
			if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
				name = host
			}
		}
		sni, err := bnet.CanonicalHttpHost(name)
		if err != nil || sni != host {
			http.Error(w, "request authority differs from TLS", http.StatusMisdirectedRequest)
			return
		}
		// Reject path aliases before a router can clean or discard RawPath.
		if strings.Contains(r.URL.EscapedPath(), "%") || (r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path) || strings.Contains(r.URL.Path, "\\") {
			http.Error(w, "invalid request path", http.StatusBadRequest)
			return
		}
		for _, part := range strings.Split(r.URL.Path, "/") {
			if part == "." || part == ".." {
				http.Error(w, "invalid request path", http.StatusBadRequest)
				return
			}
		}
		origins := r.Header.Values("Origin")
		upgrade := r.Header.Get("Upgrade") != ""
		safe := r.Method == http.MethodGet || r.Method == http.MethodHead
		if len(origins) > 1 || ((!safe || upgrade) && len(origins) == 0) {
			http.Error(w, "same-origin proof required", http.StatusForbidden)
			return
		}
		if len(origins) == 1 {
			origin, err := url.Parse(origins[0])
			if err != nil || origin.Scheme != "https" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.ForceQuery || strings.Contains(origins[0], "#") || origin.Opaque != "" || !sameHTTPSAuthority(origin.Host, r.Host) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" && (!safe || upgrade || strings.HasPrefix(r.URL.Path, "/_bifroest/")) {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		// Individual future protocol handlers must impose their tighter limits.
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	}), nil
}

func sameHTTPSAuthority(a, b string) bool {
	hostA, errA := bnet.CanonicalHttpHost(a)
	hostB, errB := bnet.CanonicalHttpHost(b)
	if errA != nil || errB != nil || hostA != hostB {
		return false
	}
	port := func(authority string) string {
		parsed, err := url.Parse("https://" + authority)
		if err != nil {
			return ""
		}
		if value := parsed.Port(); value != "" {
			return value
		}
		return "443"
	}
	return port(a) == port(b)
}
