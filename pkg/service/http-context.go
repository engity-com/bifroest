package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	log "github.com/echocat/slf4g"

	bconn "github.com/engity-com/bifroest/pkg/connection"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

// webScope is request authority, including the effective HTTPS port, and an
// exact canonical slug. It is not a client-supplied environment selector.
type webScope struct {
	Origin string `json:"origin"`
	Slug   string `json:"slug"`
}

func requestWebScope(r *http.Request, slug string) (webScope, error) {
	if err := bnet.ValidateHttpSlug(slug); err != nil {
		return webScope{}, err
	}
	host, err := bnet.CanonicalHttpHost(r.Host)
	if err != nil {
		return webScope{}, err
	}
	parsed, err := url.Parse("https://" + r.Host)
	if err != nil {
		return webScope{}, err
	}
	authority := host
	if port := parsed.Port(); port != "" {
		number, _ := strconv.ParseUint(port, 10, 16) // CanonicalHttpHost validated it.
		if number != 443 {
			authority += ":" + strconv.FormatUint(number, 10)
		}
	}
	return webScope{Origin: "https://" + authority, Slug: slug}, nil
}

func (this webScope) selection() bconn.Selection {
	parsed, _ := url.Parse(this.Origin)
	host, _ := bnet.CanonicalHttpHost(parsed.Host)
	return bconn.Selection{Transport: bconn.TransportHttp, Host: host, Slug: this.Slug}
}

type webRemote struct {
	user string
	host bnet.Host
}

func (this webRemote) User() string    { return this.user }
func (this webRemote) Host() bnet.Host { return this.host }
func (this webRemote) String() string  { return this.user + "@" + this.host.String() }
func (this webRemote) GetField(name string) (any, bool, error) {
	switch name {
	case "user":
		return this.user, true, nil
	case "host":
		return this.host, true, nil
	default:
		return nil, false, fmt.Errorf("unknown remote field %q", name)
	}
}

func webPeer(r *http.Request) (netip.Addr, error) {
	address, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid direct peer")
	}
	value, err := netip.ParseAddr(address)
	if err != nil || value.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid direct peer")
	}
	return value.Unmap(), nil
}

// No essh.Context, network socket or persistent authentication state is hidden
// in this logical login request. Forwarded headers cannot supply peer metadata.
type webLoginConnection struct {
	id     bconn.Id
	ctx    context.Context
	cancel context.CancelFunc
	scope  webScope
	remote webRemote
	closed atomic.Bool
}

func (this *webLoginConnection) Id() bconn.Id               { return this.id }
func (this *webLoginConnection) Lifetime() context.Context  { return this.ctx }
func (this *webLoginConnection) Remote() bnet.Remote        { return this.remote }
func (*webLoginConnection) Logger() log.Logger              { return log.GetLogger("http.authentication") }
func (this *webLoginConnection) Selection() bconn.Selection { return this.scope.selection() }
func (this *webLoginConnection) IsClosed() bool             { return this.closed.Load() || this.ctx.Err() != nil }
func (this *webLoginConnection) Close() error               { this.closed.Store(true); this.cancel(); return nil }

func newWebLoginConnection(ctx context.Context, r *http.Request, scope webScope, user string) (*webLoginConnection, error) {
	peer, err := webPeer(r)
	if err != nil {
		return nil, err
	}
	id, err := bconn.NewId()
	if err != nil {
		return nil, err
	}
	host, err := bnet.NewHost(peer.String())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	conn := &webLoginConnection{id: id, ctx: ctx, cancel: cancel, scope: scope, remote: webRemote{user: user, host: host}}
	conn.ctx = context.WithValue(ctx, auditConnectionContextKey{}, conn)
	return conn, nil
}

func webBearer(r *http.Request) string {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(values[0], "Bearer ")
}
