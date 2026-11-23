package https

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/engity-com/bifroest/pkg/configuration"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

type upstreamContextKey struct{}

// UpstreamRequest is validated ingress metadata, separate from backend TLS.
type UpstreamRequest struct {
	Origin     string
	PathPrefix string
	Client     netip.Addr
	Proxy      netip.Addr
}

func UpstreamOf(r *http.Request) (UpstreamRequest, bool) {
	value, ok := r.Context().Value(upstreamContextKey{}).(UpstreamRequest)
	return value, ok
}

func PathPrefix(r *http.Request) string { value, _ := UpstreamOf(r); return value.PathPrefix }

func singleProxyHeader(r *http.Request, name string, required bool) (string, error) {
	values := r.Header.Values(name)
	if len(values) == 0 && !required {
		return "", nil
	}
	if len(values) != 1 || strings.ContainsAny(values[0], ",\r\n") || values[0] != strings.TrimSpace(values[0]) || len(values[0]) > 2048 {
		return "", fmt.Errorf("invalid proxy metadata")
	}
	if required && values[0] == "" {
		return "", fmt.Errorf("missing proxy metadata")
	}
	return values[0], nil
}

func proxyRequest(conf configuration.HttpUpstream, r *http.Request) (*http.Request, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy peer")
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !conf.TrustedPeers.Contains(peer) {
		return nil, fmt.Errorf("untrusted proxy peer")
	}
	proto, err := singleProxyHeader(r, "X-Forwarded-Proto", true)
	if err != nil || proto != "https" {
		return nil, fmt.Errorf("public HTTPS required")
	}
	prefix, err := singleProxyHeader(r, "X-Forwarded-Prefix", false)
	if err != nil || configuration.ValidateHttpPathPrefix(prefix) != nil {
		return nil, fmt.Errorf("invalid proxy prefix")
	}
	authority, err := singleProxyHeader(r, "X-Forwarded-Host", false)
	if err != nil || len(r.Header.Values("X-Forwarded-Host")) != 0 && authority == "" {
		return nil, fmt.Errorf("invalid public authority")
	}
	if authority == "" {
		authority = r.Host
	}
	if _, err := bnet.CanonicalHttpHost(authority); err != nil {
		return nil, fmt.Errorf("invalid public authority")
	}
	port, err := singleProxyHeader(r, "X-Forwarded-Port", false)
	if err != nil || len(r.Header.Values("X-Forwarded-Port")) != 0 && port == "" {
		return nil, fmt.Errorf("invalid public port")
	}
	if port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 || strconv.FormatUint(number, 10) != port {
			return nil, fmt.Errorf("invalid public port")
		}
		parsed, _ := url.Parse("https://" + authority)
		if parsed.Port() != "" && parsed.Port() != port {
			return nil, fmt.Errorf("conflicting public port")
		}
		if parsed.Port() == "" {
			authority = parsed.Host + ":" + port
		}
	}
	origin, err := bnet.CanonicalHttpsOrigin(authority)
	if err != nil {
		return nil, fmt.Errorf("invalid public authority")
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 || len(values[0]) > 4096 {
		return nil, fmt.Errorf("invalid client chain")
	}
	parts := strings.Split(values[0], ",")
	if len(parts) > 32 {
		return nil, fmt.Errorf("client chain too long")
	}
	chain := make([]netip.Addr, len(parts))
	for index, part := range parts {
		address, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return nil, fmt.Errorf("invalid client address")
		}
		chain[index] = address.Unmap()
	}
	client := peer.Unmap()
	for index := len(chain) - 1; index >= 0; index-- {
		if !conf.TrustedPeers.Contains(client) {
			break
		}
		client = chain[index]
	}
	info := UpstreamRequest{Origin: origin, PathPrefix: prefix, Client: client, Proxy: peer.Unmap()}
	result := r.Clone(context.WithValue(r.Context(), upstreamContextKey{}, info))
	result.Host = strings.TrimPrefix(origin, "https://")
	result.RemoteAddr = net.JoinHostPort(client.String(), "0")
	return result, nil
}
