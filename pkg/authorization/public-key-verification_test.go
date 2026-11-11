package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

type verificationTestRequest struct {
	Request
	ctx        context.Context
	repository session.Repository
	key        ssh.PublicKey
	verified   bool
	validate   func(Authorization) (bool, error)
	resolved   Authorization
}

func (this *verificationTestRequest) Context() context.Context       { return this.ctx }
func (this *verificationTestRequest) Sessions() session.Repository   { return this.repository }
func (this *verificationTestRequest) RemotePublicKey() ssh.PublicKey { return this.key }
func (this *verificationTestRequest) PublicKeyVerified() bool        { return this.verified }
func (this *verificationTestRequest) SetAuthorizationContext(auth Authorization) {
	this.resolved = auth
}
func (*verificationTestRequest) Connection() connection.Connection {
	return verificationTestConnection{}
}
func (this *verificationTestRequest) Validate(auth Authorization) (bool, error) {
	if this.validate != nil {
		return this.validate(auth)
	}
	return true, nil
}

type verificationTestConnection struct{ connection.Connection }

// Hiding the optional verified assertion must be equivalent to an unsigned probe.
type unverifiedTestRequest struct{ PublicKeyRequest }

func (verificationTestConnection) Remote() bnet.Remote { return authenticationTestRemote("user") }
func (verificationTestConnection) Logger() log.Logger {
	return log.GetLogger("authorization.verification-test")
}

func newVerificationTestRepository(t *testing.T) *session.FacadeRepository {
	t.Helper()
	conf := &configuration.SessionFs{}
	require.NoError(t, conf.SetDefaults())
	conf.Storage = t.TempDir()
	repository, err := session.NewFacadeRepository(t.Context(), &configuration.Session{V: conf})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	return repository
}

func TestPublicKeyProbesCannotCreateSimpleOrAnonymousSessions(t *testing.T) {
	for _, kind := range []string{"simple raw key", "simple certificate", "none"} {
		t.Run(kind, func(t *testing.T) {
			repository := newVerificationTestRepository(t)
			key := newUserCertificateTestSigner(t).PublicKey()
			var authorizer CloseableAuthorizer
			if kind == "none" {
				var err error
				authorizer, err = NewNone(t.Context(), "flow", &configuration.AuthorizationNone{})
				require.NoError(t, err)
			} else {
				conf := &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "user", AuthorizedKeys: crypto.AuthorizedKeys(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))}}}
				if kind == "simple certificate" {
					ca := newUserCertificateTestSigner(t)
					cert := newUserCertificateTestCertificateWithMutation(t, ca, key, time.Now(), func(cert *ssh.Certificate) { cert.ValidPrincipals = []string{"user"} })
					conf.TrustedUserCAs = crypto.PublicKeys(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey()))))
					key = cert
				}
				var err error
				authorizer, err = NewSimple(t.Context(), "flow", conf)
				require.NoError(t, err)
			}
			defer authorizer.Close()
			req := &verificationTestRequest{ctx: t.Context(), repository: repository, key: key}
			probe, err := authorizer.AuthorizePublicKey(unverifiedTestRequest{req})
			require.NoError(t, err)
			require.True(t, probe.IsAuthorized())
			require.Nil(t, probe.FindSession())
			for i := 0; i < 3; i++ {
				auth, err := authorizer.AuthorizePublicKey(req)
				require.NoError(t, err)
				require.True(t, auth.IsAuthorized())
				require.Nil(t, auth.FindSession())
			}
			count := 0
			require.NoError(t, repository.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
			require.Zero(t, count)
			req.verified = true
			auth, err := authorizer.AuthorizePublicKey(req)
			require.NoError(t, err)
			require.True(t, auth.IsAuthorized())
			require.NotNil(t, auth.FindSession())
		})
	}
}

func TestOidcUnsignedPublicKeyProbesNeverRestoreRefreshOrRevoke(t *testing.T) {
	var requests atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer provider.Close()
	for _, kind := range []string{"valid", "expired", "pending verification"} {
		t.Run(kind, func(t *testing.T) {
			repository := newVerificationTestRepository(t)
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, provider.Client())
			token := oidcToken{Token: &oauth2.Token{AccessToken: "access", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour)}, Subject: "subject", Issuer: provider.URL, LastVerifiedAt: time.Now(), ReceivedAt: time.Now()}
			if kind == "expired" {
				token.Expiry = time.Now().Add(-time.Hour)
			}
			if kind == "pending verification" {
				token.Pending = &oidcPendingVerification{Token: &oauth2.Token{AccessToken: "pending-access", RefreshToken: "pending-refresh"}, IdToken: "unverified-token", ReceivedAt: time.Now()}
			}
			raw, err := json.Marshal(token)
			require.NoError(t, err)
			sess, err := repository.Create(ctx, "flow", authenticationTestRemote("user"), raw)
			require.NoError(t, err)
			key := newUserCertificateTestSigner(t).PublicKey()
			require.NoError(t, sess.AddPublicKey(ctx, key))
			var lost, verified int
			authorizer := &OidcDeviceAuthAuthorizer{
				flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: true, RetrieveUserInfo: true, ForceDisposeSessionOn: "lostAccess"},
				oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: provider.URL}},
				OnLostAccess: func(session.Session) { lost++ }, OnVerified: func(session.Session, time.Time) { verified++ },
			}
			req := &verificationTestRequest{ctx: ctx, repository: repository, key: key, validate: func(Authorization) (bool, error) {
				t.Fatal("probe must not validate absent OIDC artifacts")
				return false, nil
			}}
			req.resolved = &simple{entry: &configuration.AuthorizationSimpleEntry{Name: "previous-flow"}}
			for i := 0; i < 3; i++ {
				auth, err := authorizer.AuthorizePublicKey(req)
				require.NoError(t, err)
				require.True(t, auth.IsAuthorized())
				require.Equal(t, sess.Id(), auth.FindSession().Id())
				_, err = AuthenticationOf(auth)
				require.ErrorIs(t, err, ErrAuthenticationUnavailable)
				require.Nil(t, auth.(*oidc).token.Token)
				require.Nil(t, req.resolved, "probe must not use a previous flow's prospective identity")
			}
			require.Zero(t, requests.Load())
			require.Zero(t, lost)
			require.Zero(t, verified)
			stored, err := sess.AuthorizationToken(ctx)
			require.NoError(t, err)
			require.Equal(t, raw, stored)
			if kind == "expired" {
				req.verified = true
				auth, err := authorizer.AuthorizePublicKey(req)
				require.NoError(t, err)
				require.False(t, auth.IsAuthorized())
				require.Equal(t, 1, lost)
				require.Positive(t, requests.Load())
				requests.Store(0)
			}
		})
	}
}

func TestOidcVerifiedPublicKeyRestoresCurrentRemoteAndIdentity(t *testing.T) {
	repository := newVerificationTestRepository(t)
	token := oidcToken{Token: &oauth2.Token{AccessToken: "access", Expiry: time.Now().Add(time.Hour)}, Subject: "subject", Issuer: "https://issuer.example", LastVerifiedAt: time.Now()}
	raw, err := json.Marshal(token)
	require.NoError(t, err)
	sess, err := repository.Create(t.Context(), "flow", authenticationTestRemote("user"), raw)
	require.NoError(t, err)
	key := newUserCertificateTestSigner(t).PublicKey()
	require.NoError(t, sess.AddPublicKey(t.Context(), key))
	authorizer := &OidcDeviceAuthAuthorizer{flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "never", RefreshToken: configuration.AuthorizationOidcRefreshToken{Mode: "never"}}}
	validated := false
	req := &verificationTestRequest{ctx: t.Context(), repository: repository, key: key, verified: true, validate: func(auth Authorization) (bool, error) {
		validated = true
		require.Equal(t, "user", auth.Remote().User())
		identity, err := AuthenticationOf(auth)
		require.NoError(t, err)
		require.Equal(t, "subject", identity.Subject)
		return true, nil
	}}
	auth, err := authorizer.AuthorizePublicKey(req)
	require.NoError(t, err)
	require.True(t, auth.IsAuthorized())
	require.True(t, validated)
	require.Equal(t, sess.Id(), auth.FindSession().Id())
}
