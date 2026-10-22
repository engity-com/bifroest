package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

const webAccessLifetime = 10 * time.Minute

// An ephemeral, tab-memory bearer proof, not RememberMe or session ownership.
// Only a hash is indexed server-side. It never accepts a session ID as a proof.
// Expiry prevents NEW access; logout additionally closes its own web children.
type webAccess struct {
	scope    webScope
	auth     authorization.Authorization
	identity authentication.Identity
	target   session.Target
	user     string
	expires  time.Time
	mutex    sync.Mutex
	closed   bool
	children map[*terminalConnection]struct{}
}

func webAccessKey(token string) ([32]byte, bool) {
	if len(token) != len("bwa1.")+43 || token[:5] != "bwa1." {
		return [32]byte{}, false
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(token[5:])
	if err != nil || len(value) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(token)), true
}

func (this *webService) issue(scope webScope, base *environmentContext) (string, *webAccess, error) {
	identity, err := base.Authentication()
	if err != nil {
		return "", nil, err
	}
	if err := identity.Validate(); err != nil {
		return "", nil, err
	}
	target, err := this.target(base)
	if err != nil {
		return "", nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", nil, err
	}
	token := "bwa1." + base64.RawURLEncoding.EncodeToString(nonce[:])
	key, _ := webAccessKey(token)
	access := &webAccess{scope: scope, auth: base.Authorization(), identity: identity, target: target, user: base.Connection().Remote().User(), expires: time.Now().Add(webAccessLifetime), children: make(map[*terminalConnection]struct{})}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.pruneLocked(time.Now())
	if this.ctx.Err() != nil || base.Context().Err() != nil || len(this.access) >= webMaximumAccess {
		return "", nil, fmt.Errorf("web access unavailable")
	}
	if _, exists := this.access[key]; exists {
		return "", nil, fmt.Errorf("web access collision")
	}
	this.access[key] = access
	return token, access, nil
}

func (this *webService) target(base *environmentContext) (session.Target, error) {
	sess := base.Authorization().FindSession()
	resolver, ok := environment.SessionTargetResolverFor(this.service.environments, sess.Flow())
	if !ok {
		return "", fmt.Errorf("web access requires a pure session target resolver")
	}
	info, err := sess.Info(base.Context())
	if err != nil {
		return "", err
	}
	created, err := info.Created(base.Context())
	if err != nil {
		return "", err
	}
	target, err := resolver.ResolveSessionTarget(newAssociationTargetContext(base.Context(), base, session.Reference{Flow: sess.Flow(), Id: sess.Id(), Created: created}))
	if err != nil {
		return "", err
	}
	return target, target.Validate()
}

func (this *webService) lookup(scope webScope, token string, includeExpired bool) (*webAccess, error) {
	key, ok := webAccessKey(token)
	if !ok {
		return nil, fmt.Errorf("web access denied")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	access := this.access[key]
	if this.ctx.Err() != nil || access == nil || access.scope != scope {
		return nil, fmt.Errorf("web access denied")
	}
	access.mutex.Lock()
	defer access.mutex.Unlock()
	if access.closed || !includeExpired && !time.Now().Before(access.expires) {
		return nil, fmt.Errorf("web access denied")
	}
	return access, nil
}

func (this *webService) validate(base *environmentContext, access *webAccess) error {
	if this.service.sessionConnections.isRevoked(access.auth.FindSession()) {
		return fmt.Errorf("web access revoked")
	}
	if err := this.service.validateTerminalAuthorization(base); err != nil {
		return err
	}
	identity, err := base.Authentication()
	if err != nil {
		return err
	}
	if identity != access.identity {
		return fmt.Errorf("web identity changed")
	}
	target, err := this.target(base)
	if err != nil {
		return err
	}
	if target != access.target {
		return fmt.Errorf("web target changed")
	}
	return nil
}

func (this *webService) logout(scope webScope, token string) error {
	access, err := this.lookup(scope, token, true)
	if err != nil {
		return err
	}
	key, _ := webAccessKey(token)
	this.mutex.Lock()
	delete(this.access, key)
	this.mutex.Unlock()
	return access.close()
}

func (this *webAccess) close() error {
	this.mutex.Lock()
	this.closed = true
	children := make([]managedConnection, 0, len(this.children))
	for child := range this.children {
		children = append(children, child)
	}
	this.mutex.Unlock()
	return closeSessionConnections(children)
}

// Trusted adapter bridge; only the protocol handler can turn a verified proof
// into a connection. Neither session IDs nor client metadata are authorizations.
// Each use acquires a fresh quota lease and never reattaches an old execution.
func (this *webService) connect(scope webScope, token string, transport terminalTransport) (*terminalConnection, error) {
	if isNilDependency(transport) || isNilDependency(transport.Lifetime()) {
		return nil, fmt.Errorf("missing web transport")
	}
	release, ok := this.operations.register()
	if !ok {
		return nil, context.Canceled
	}
	defer release()
	access, err := this.lookup(scope, token, false)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(transport.Lifetime())
	stop := context.AfterFunc(this.ctx, cancel)
	defer stop()
	wrapped := &webAccessTransport{terminalTransport: transport, ctx: ctx, cancel: cancel, scope: scope, user: access.user, access: access}
	base := &environmentContext{service: this.service, connection: wrapped, authorization: access.auth, executionContext: ctx}
	if err := this.validate(base, access); err != nil {
		cancel()
		return nil, err
	}
	conn, err := this.service.registerTerminalConnection(wrapped, access.auth)
	if err != nil {
		cancel()
		return nil, err
	}
	wrapped.mutex.Lock()
	wrapped.connection = conn
	alreadyClosed := wrapped.closed
	wrapped.mutex.Unlock()
	access.mutex.Lock()
	if access.closed || alreadyClosed || !time.Now().Before(access.expires) {
		access.mutex.Unlock()
		_ = conn.Close()
		return nil, fmt.Errorf("web access ended")
	}
	access.children[conn] = struct{}{}
	access.mutex.Unlock()
	// A parent cancellation may have closed the wrapper before the insertion.
	if conn.IsClosed() {
		wrapped.remove()
		return nil, context.Canceled
	}
	return conn, nil
}

type webAccessTransport struct {
	terminalTransport
	ctx        context.Context
	cancel     context.CancelFunc
	scope      webScope
	user       string
	access     *webAccess
	mutex      sync.Mutex
	connection *terminalConnection
	closed     bool
}

func (this *webAccessTransport) Lifetime() context.Context  { return this.ctx }
func (this *webAccessTransport) Selection() bconn.Selection { return this.scope.selection() }
func (this *webAccessTransport) Remote() bnet.Remote {
	return webRemote{user: this.user, host: this.terminalTransport.Remote().Host()}
}
func (this *webAccessTransport) remove() {
	this.mutex.Lock()
	conn := this.connection
	this.mutex.Unlock()
	if conn != nil {
		this.access.mutex.Lock()
		delete(this.access.children, conn)
		this.access.mutex.Unlock()
	}
}
func (this *webAccessTransport) Close() error {
	this.mutex.Lock()
	wasClosed := this.closed
	this.closed = true
	this.mutex.Unlock()
	if wasClosed {
		return nil
	}
	this.cancel()
	this.remove()
	return this.terminalTransport.Close()
}
