package service

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type oidcAssociationProvider struct {
	server                         *httptest.Server
	key                            *rsa.PrivateKey
	logins, refreshes              atomic.Int32
	rejectRefresh                  atomic.Bool
	refreshStarted, releaseRefresh chan struct{}
	releaseOnce                    sync.Once
}

func newOidcAssociationProvider(t *testing.T) *oidcAssociationProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p := &oidcAssociationProvider{key: key, refreshStarted: make(chan struct{}, 1), releaseRefresh: make(chan struct{})}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(func() { p.release(); p.server.Close() })
	return p
}
func (p *oidcAssociationProvider) release() { p.releaseOnce.Do(func() { close(p.releaseRefresh) }) }
func (p *oidcAssociationProvider) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "device_authorization_endpoint": p.server.URL + "/device", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/jwks":
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "local-key", "n": enc(p.key.N.Bytes()), "e": enc(big.NewInt(int64(p.key.E)).Bytes())}}})
	case "/device":
		_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "test-device", "user_code": "test-code", "verification_uri": p.server.URL + "/verify", "expires_in": 60, "interval": 1})
	case "/token":
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			n := p.refreshes.Add(1)
			select {
			case p.refreshStarted <- struct{}{}:
			default:
			}
			select {
			case <-p.releaseRefresh:
			case <-r.Context().Done():
				return
			}
			if p.rejectRefresh.Load() {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("rotated-access-%d", n), "refresh_token": fmt.Sprintf("rotated-refresh-%d", n), "token_type": "Bearer", "expires_in": 3600})
			return
		}
		n := p.logins.Add(1)
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "local-key"})
		claims, _ := json.Marshal(map[string]any{"iss": p.server.URL, "sub": "verified-subject", "aud": "client", "iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(time.Hour).Unix(), "login": n})
		enc := base64.RawURLEncoding.EncodeToString
		input := enc(header) + "." + enc(claims)
		digest := sha256.Sum256([]byte(input))
		signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, stdcrypto.SHA256, digest[:])
		if err != nil {
			http.Error(w, "cannot sign", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("login-access-%d", n), "refresh_token": fmt.Sprintf("login-refresh-%d", n), "token_type": "Bearer", "expires_in": 3600, "id_token": input + "." + enc(signature)})
	default:
		http.NotFound(w, r)
	}
}

type oidcAssociationRequest struct {
	authorization.Request
	svc          *service
	ctx          context.Context
	remote       bnet.Remote
	reuseEntered chan struct{}
}

func (r *oidcAssociationRequest) Context() context.Context     { return r.ctx }
func (r *oidcAssociationRequest) Sessions() session.Repository { return r.svc.sessions }
func (r *oidcAssociationRequest) Connection() bconn.Connection {
	return oidcAssociationConnection{associationAdapterConnection{remote: r.remote}}
}
func (r *oidcAssociationRequest) Validate(auth authorization.Authorization) (bool, error) {
	return r.svc.environments.WillBeAccepted(associationAdapterContext{ctx: r.ctx, auth: auth, remote: r.remote})
}
func (r *oidcAssociationRequest) SendInfo(string) error  { return nil }
func (r *oidcAssociationRequest) SendError(string) error { return nil }
func (r *oidcAssociationRequest) Prompt(string, bool) (string, error) {
	return "", fmt.Errorf("unexpected OIDC password prompt")
}
func (r *oidcAssociationRequest) ResolveAuthenticatedSessionWithReuse(auth authorization.Authorization, token []byte, reuse session.Predicate) (session.Session, bool, error) {
	if r.reuseEntered != nil {
		select {
		case r.reuseEntered <- struct{}{}:
		default:
		}
	}
	return r.svc.resolveAuthenticatedSessionWithReuse(associationAdapterContext{ctx: r.ctx, auth: auth, remote: r.remote}, token, reuse)
}

type oidcAssociationConnection struct{ associationAdapterConnection }

func (oidcAssociationConnection) Logger() log.Logger { return log.GetLogger("oidc-association-test") }

func oidcAssociationFixture(t *testing.T, configure ...func(*configuration.AuthorizationOidcDeviceAuth)) (*service, *authorization.OidcDeviceAuthAuthorizer, *oidcAssociationProvider, context.Context) {
	t.Helper()
	p := newOidcAssociationProvider(t)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, p.server.Client())
	conf := &configuration.AuthorizationOidcDeviceAuth{}
	require.NoError(t, conf.SetDefaults())
	conf.Issuer = template.MustNewUrl(p.server.URL)
	conf.ClientId = template.MustNewString("client")
	conf.ClientSecret = template.MustNewString("secret")
	for _, fn := range configure {
		fn(conf)
	}
	authorizer, err := authorization.NewOidcDeviceAuth(ctx, "work", conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, authorizer.Close()) })
	fs := &configuration.SessionFs{}
	require.NoError(t, fs.SetDefaults())
	fs.Storage = t.TempDir()
	repository, err := session.NewFacadeRepository(ctx, &configuration.Session{V: fs})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	dummyConf := &configuration.EnvironmentDummy{}
	require.NoError(t, dummyConf.SetDefaults())
	environments, err := environment.NewDummyRepository(ctx, "work", dummyConf, nil, nil)
	require.NoError(t, err)
	return &service{sessions: repository, environments: environments}, authorizer, p, ctx
}

func oidcAssociationStoredToken(t *testing.T, sess session.Session) map[string]any {
	t.Helper()
	raw, err := sess.AuthorizationToken(t.Context())
	require.NoError(t, err)
	var token map[string]any
	require.NoError(t, json.Unmarshal(raw, &token))
	return token
}

func TestOidcPrimaryAssociationSharesRotatingGrantWithoutOverwritingIt(t *testing.T) {
	svc, authorizer, provider, ctx := oidcAssociationFixture(t)
	first, err := authorizer.AuthorizeInteractive(&oidcAssociationRequest{svc: svc, ctx: ctx, remote: associationAdapterRemote("ssh-client")})
	require.NoError(t, err)
	sess := first.FindSession()
	require.NotNil(t, sess)
	stored := oidcAssociationStoredToken(t, sess)
	stored["expiry"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(stored)
	require.NoError(t, err)
	require.NoError(t, sess.SetAuthorizationToken(ctx, raw))
	refreshed := make(chan error, 1)
	go func() {
		_, lost, err := authorizer.RefreshSession(ctx, sess)
		if lost && err == nil {
			err = fmt.Errorf("unexpected lost access")
		}
		refreshed <- err
	}()
	select {
	case <-provider.refreshStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not start")
	}
	request := &oidcAssociationRequest{svc: svc, ctx: ctx, remote: associationAdapterRemote(""), reuseEntered: make(chan struct{}, 1)}
	type result struct {
		auth authorization.Authorization
		err  error
	}
	done := make(chan result, 1)
	go func() { auth, err := authorizer.AuthorizeInteractive(request); done <- result{auth, err} }()
	select {
	case <-request.reuseEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("fresh device login did not reach reuse")
	}
	select {
	case got := <-done:
		t.Fatalf("login did not wait for rotating grant: %v", got.err)
	default:
	}
	require.Equal(t, "login-refresh-1", oidcAssociationStoredToken(t, sess)["refresh_token"])
	provider.release()
	require.NoError(t, <-refreshed)
	var second authorization.Authorization
	select {
	case got := <-done:
		require.NoError(t, got.err)
		second = got.auth
	case <-time.After(5 * time.Second):
		t.Fatal("fresh login did not finish")
	}
	require.Equal(t, sess.Id(), second.FindSession().Id())
	require.Equal(t, "rotated-refresh-1", oidcAssociationStoredToken(t, sess)["refresh_token"])
	require.EqualValues(t, 1, provider.refreshes.Load())
	require.EqualValues(t, 2, provider.logins.Load())
	identity, err := authorization.AuthenticationOf(second)
	require.NoError(t, err)
	require.Equal(t, "verified-subject", identity.Subject)
	fields, ok := second.(interface {
		GetField(string, authorization.ContextEnabled) (any, bool, error)
	})
	require.True(t, ok)
	idToken, found, err := fields.GetField("idToken", request)
	require.NoError(t, err)
	require.True(t, found)
	login, found, err := idToken.(*authorization.OidcIdToken).GetField("login")
	require.NoError(t, err)
	require.True(t, found)
	require.EqualValues(t, 2, login, "new connection uses its newly verified claims, not the retained grant's old claims")
	third, err := authorizer.AuthorizeInteractive(&oidcAssociationRequest{svc: svc, ctx: ctx, remote: associationAdapterRemote("different-client")})
	require.NoError(t, err)
	require.Equal(t, sess.Id(), third.FindSession().Id())
	require.Equal(t, "rotated-refresh-1", oidcAssociationStoredToken(t, sess)["refresh_token"])
}

func TestOidcPrimaryAssociationCannotReviveGrantWithLostAccess(t *testing.T) {
	svc, authorizer, provider, ctx := oidcAssociationFixture(t)
	first, err := authorizer.AuthorizeInteractive(&oidcAssociationRequest{svc: svc, ctx: ctx, remote: associationAdapterRemote("client")})
	require.NoError(t, err)
	sess := first.FindSession()
	connections := []*connection{newTrackedSessionConnection(t, svc), newTrackedSessionConnection(t, svc)}
	for _, conn := range connections {
		svc.sessionConnections.track(conn, sess)
	}
	stored := oidcAssociationStoredToken(t, sess)
	stored["expiry"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(stored)
	require.NoError(t, err)
	require.NoError(t, sess.SetAuthorizationToken(ctx, raw))
	provider.rejectRefresh.Store(true)
	provider.release()
	lost := make(chan error, 1)
	authorizer.OnLostAccess = func(candidate session.Session) {
		_ = svc.sessionConnections.revoke(candidate.Flow(), candidate.Id())
		_, err := candidate.Dispose(ctx)
		lost <- err
	}
	second, err := authorizer.AuthorizeInteractive(&oidcAssociationRequest{svc: svc, ctx: ctx, remote: associationAdapterRemote("")})
	require.NoError(t, err)
	require.NotEqual(t, sess.Id(), second.FindSession().Id())
	require.NoError(t, <-lost)
	for _, conn := range connections {
		require.True(t, conn.closed.Load(), "grant loss during primary reuse must revoke every existing connection")
	}
	late := newTrackedSessionConnection(t, svc)
	svc.sessionConnections.track(late, sess)
	require.True(t, late.closed.Load(), "late registration must not revive the old session")
	fresh := newTrackedSessionConnection(t, svc)
	svc.sessionConnections.track(fresh, second.FindSession())
	require.False(t, fresh.closed.Load(), "the fresh session must not inherit the old revocation")
	require.NoError(t, fresh.Close())
	current, err := svc.sessions.FindBy(ctx, sess.Flow(), sess.Id(), nil)
	require.NoError(t, err)
	info, err := current.Info(ctx)
	require.NoError(t, err)
	require.Equal(t, session.StateDisposed, info.State())
	require.Equal(t, "login-refresh-1", oidcAssociationStoredToken(t, current)["refresh_token"])
	require.Equal(t, "login-refresh-2", oidcAssociationStoredToken(t, second.FindSession())["refresh_token"])
}

func TestOidcPrimaryAssociationRequiresVerifiedIdentityNotRequestingName(t *testing.T) {
	t.Run("verified but hidden ID token", func(t *testing.T) {
		svc, a, _, ctx := oidcAssociationFixture(t, func(conf *configuration.AuthorizationOidcDeviceAuth) { conf.RetrieveIdToken = false })
		auth, err := a.AuthorizeInteractive(&oidcAssociationRequest{svc: svc, ctx: ctx, remote: associationAdapterRemote("unverified-client-name")})
		require.NoError(t, err)
		identity, err := authorization.AuthenticationOf(auth)
		require.NoError(t, err)
		require.Equal(t, "verified-subject", identity.Subject)
		binding, err := session.AssociationOf(ctx, auth.FindSession())
		require.NoError(t, err)
		require.NotNil(t, binding)
		require.Equal(t, identity.Subject, binding.Subject)
	})
	t.Run("no identity artifacts", func(t *testing.T) {
		svc, a, _, ctx := oidcAssociationFixture(t, func(conf *configuration.AuthorizationOidcDeviceAuth) {
			conf.RetrieveIdToken = false
			conf.RetrieveUserInfo = false
			conf.ForceDisposeSessionOn = "never"
			conf.RefreshToken.Mode = "never"
		})
		auth, err := a.AuthorizeInteractive(&oidcAssociationRequest{svc: svc, ctx: ctx, remote: associationAdapterRemote("same-name")})
		require.NoError(t, err)
		_, err = authorization.AuthenticationOf(auth)
		require.ErrorIs(t, err, authorization.ErrAuthenticationUnavailable)
		binding, err := session.AssociationOf(ctx, auth.FindSession())
		require.NoError(t, err)
		require.Nil(t, binding, "no guessed binding from a name or unverified JWT")
	})
}
