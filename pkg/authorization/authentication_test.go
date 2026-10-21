package authorization

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
)

type authenticationTestRemote string

func (this authenticationTestRemote) User() string   { return string(this) }
func (authenticationTestRemote) Host() net.Host      { return net.Host{} }
func (this authenticationTestRemote) String() string { return string(this) }

type unknownAuthenticationAuthorization struct{ Authorization }

func (unknownAuthenticationAuthorization) IsAuthorized() bool { return true }

func TestNormalizedAuthenticationDoesNotSubstituteRequestingName(t *testing.T) {
	requested := authenticationTestRemote("requested-target")
	for _, test := range []struct {
		name      string
		auth      Authorization
		principal string
	}{
		{"simple", &simple{entry: &configuration.AuthorizationSimpleEntry{Name: "Alice"}, remote: requested}, "Alice"},
		{"htpasswd", &htpasswd{remote: requested, principal: "verified-name"}, "verified-name"},
		{"none", &none{remote: requested}, authentication.AnonymousPrincipal},
		{"forbidden", Forbidden(requested), authentication.AnonymousPrincipal},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity, err := AuthenticationOf(test.auth)
			require.NoError(t, err)
			require.Equal(t, test.principal, identity.Principal)
			require.Equal(t, "requested-target", test.auth.Remote().User())
		})
	}
	for _, auth := range []Authorization{
		unknownAuthenticationAuthorization{}, &simple{}, &htpasswd{remote: requested}, &oidc{remote: requested},
	} {
		_, err := AuthenticationOf(auth)
		require.ErrorIs(t, err, ErrAuthenticationUnavailable)
	}
}

func TestDelegatedAuthenticationKeepsOriginAndAuthority(t *testing.T) {
	evidence := &AuthorizationEvidence{
		Origin: AuthorizationEvidenceOrigin{User: "original-user", AuthorizationKind: "simple"},
		Hops:   []AuthorizationEvidenceHop{{CaFingerprint: "SHA256:first-ca"}},
	}
	identity, err := AuthenticationOf(&BifroestAuthorization{evidence: evidence, remote: authenticationTestRemote("target-user")})
	require.NoError(t, err)
	require.Equal(t, "original-user", identity.Principal)
	otherEvidence := evidence.Clone()
	otherEvidence.Hops[0].CaFingerprint = "SHA256:another-ca"
	other, err := AuthenticationOf(&BifroestAuthorization{evidence: otherEvidence})
	require.NoError(t, err)
	require.False(t, identity.SameSubject(other))
}

func TestOidcAuthenticationUsesVerifiedSubject(t *testing.T) {
	const issuer = "https://issuer.example"
	idToken, claims := oidcRestoreTestIdToken(t, issuer, "client", time.Now().Add(time.Hour))
	authorizer := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: true},
		verifier: coidc.NewVerifier(issuer, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{ClientID: "client"}),
	}
	auth, err := authorizer.finalizeAuth(context.Background(), authorizer.logger(), &oidcToken{
		Token: &oauth2.Token{AccessToken: "access"}, IdToken: idToken,
	}, true)
	require.NoError(t, err)
	auth.remote = authenticationTestRemote("requested-target")
	identity, err := AuthenticationOf(auth)
	require.NoError(t, err)
	require.Equal(t, authentication.Identity{Principal: "subject", Issuer: issuer, Subject: "subject"}, identity)
}

func TestOidcAuthenticationDoesNotReadUnverifiedJWTClaims(t *testing.T) {
	const issuer = "https://issuer.example"
	idToken, _ := oidcRestoreTestIdToken(t, issuer, "client", time.Now().Add(time.Hour))
	authorizer := &OidcDeviceAuthAuthorizer{flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{}}
	auth, err := authorizer.finalizeAuth(context.Background(), authorizer.logger(), &oidcToken{
		Token: &oauth2.Token{AccessToken: "access"}, IdToken: idToken,
		Subject: "unverified-persisted-subject", Issuer: issuer,
	}, false)
	require.NoError(t, err)
	_, err = AuthenticationOf(auth)
	require.ErrorIs(t, err, ErrAuthenticationUnavailable)
}

func TestOidcAuthenticationRetainsPreviouslyVerifiedIdentity(t *testing.T) {
	const issuer = "https://issuer.example"
	authorizer := &OidcDeviceAuthAuthorizer{flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{}}
	auth, err := authorizer.finalizeAuth(context.Background(), authorizer.logger(), &oidcToken{
		Token:   &oauth2.Token{AccessToken: "access"},
		Subject: "verified-subject", Issuer: issuer, LastVerifiedAt: time.Now(),
	}, false)
	require.NoError(t, err)
	identity, err := AuthenticationOf(auth)
	require.NoError(t, err)
	require.Equal(t, "verified-subject", identity.Principal)
	require.Equal(t, issuer, identity.Issuer)
}

func TestOidcUserInfoCannotReplaceDifferentVerifiedSubject(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": server.URL, "userinfo_endpoint": server.URL + "/userinfo",
			})
		case "/userinfo":
			_, _ = w.Write([]byte(`{"sub":"different-user","email":"different@example.org"}`))
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	provider, err := coidc.NewProvider(ctx, server.URL)
	require.NoError(t, err)
	idToken, claims := oidcRestoreTestIdToken(t, server.URL, "client", time.Now().Add(time.Hour))
	authorizer := &OidcDeviceAuthAuthorizer{
		flow: "flow", issuer: server.URL, provider: provider,
		conf:     &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: true, RetrieveUserInfo: true},
		verifier: coidc.NewVerifier(server.URL, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{ClientID: "client"}),
	}
	_, err = authorizer.finalizeAuth(ctx, authorizer.logger(), &oidcToken{
		Token: &oauth2.Token{AccessToken: "access"}, IdToken: idToken,
	}, true)
	require.ErrorContains(t, err, "UserInfo subject differs")

	// A UserInfo-only configuration may resolve the subject from its trusted
	// issuer, without pretending that an unverified ID token was checked.
	authorizer.conf.RetrieveIdToken = false
	auth, err := authorizer.finalizeAuth(ctx, authorizer.logger(), &oidcToken{
		Token: &oauth2.Token{AccessToken: "access"},
	}, true)
	require.NoError(t, err)
	identity, err := AuthenticationOf(auth)
	require.NoError(t, err)
	require.Equal(t, "different-user", identity.Principal)
	require.Equal(t, server.URL, identity.Issuer)
}
