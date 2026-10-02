package authorization

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

func oidcRefreshTestSession(t *testing.T, token oidcToken) *authorizationRestoreTestSession {
	t.Helper()
	raw, err := json.Marshal(token)
	require.NoError(t, err)
	return &authorizationRestoreTestSession{flow: "flow", token: raw}
}

func TestOidcNextRefreshAt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a := &OidcDeviceAuthAuthorizer{flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{
		ForceDisposeSessionOn: "never",
		RefreshToken: configuration.AuthorizationOidcRefreshToken{
			Mode: "proactive", AtLifetimePercent: 70, FallbackEvery: common.DurationOf(15 * time.Minute),
		},
	}}
	ctx := context.Background()
	sess := oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "access", Expiry: now.Add(time.Hour)}, ReceivedAt: now})
	due, err := a.NextRefreshAt(ctx, sess)
	require.NoError(t, err)
	require.Equal(t, now.Add(42*time.Minute), due)

	sess = oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "access"}, ReceivedAt: now})
	due, err = a.NextRefreshAt(ctx, sess)
	require.NoError(t, err)
	require.Equal(t, now.Add(15*time.Minute), due)

	sess = oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "access"}})
	due, err = a.NextRefreshAt(ctx, sess)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), due, time.Second)
}

func TestOidcNextRefreshAtUsesIdTokenExpiryWithoutJWKS(t *testing.T) {
	const issuer = "https://issuer.example"
	var jwksRequests atomic.Int32
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksRequests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer jwks.Close()
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, jwks.Client())
	now := time.Now().UTC().Truncate(time.Second)
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{
			RetrieveIdToken: true, ForceDisposeSessionOn: "never", RefreshToken: configuration.AuthorizationOidcRefreshToken{Mode: "proactive"},
		},
		verifier: coidc.NewVerifier(issuer, coidc.NewRemoteKeySet(ctx, jwks.URL), &coidc.Config{ClientID: "client"}),
	}
	for i := range 100 {
		idToken, _ := oidcRestoreTestIdToken(t, issuer, "client", now.Add(-time.Minute))
		sess := oidcRefreshTestSession(t, oidcToken{
			Token:   &oauth2.Token{AccessToken: "access", Expiry: now.Add(time.Hour)},
			IdToken: idToken, ReceivedAt: now,
		})
		due, err := a.NextRefreshAt(ctx, sess)
		require.NoError(t, err)
		require.WithinDuration(t, time.Now(), due, time.Second, "session %d", i)
	}
	require.Zero(t, jwksRequests.Load())

	idToken, _ := oidcRestoreTestIdToken(t, issuer, "client", now.Add(2*time.Minute))
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "access", Expiry: now.Add(time.Hour)},
		IdToken: idToken, ReceivedAt: now,
	})
	due, err := a.NextRefreshAt(ctx, sess)
	require.NoError(t, err)
	require.True(t, due.Equal(now.Add(2*time.Minute)))
	require.Zero(t, jwksRequests.Load())

	sess = oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "access", Expiry: now.Add(time.Hour)},
		IdToken: "malformed.jwt", ReceivedAt: now,
	})
	due, err = a.NextRefreshAt(ctx, sess)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), due, time.Second)
	require.Zero(t, jwksRequests.Load())
}

func TestOidcRefreshRotatesTokenAndRestoresExpiredSession(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "/token", r.URL.Path)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "old-refresh", r.Form.Get("refresh_token"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "never", RefreshToken: configuration.AuthorizationOidcRefreshToken{Mode: "proactive"}},
		oauth2Config: oauth2.Config{ClientID: "client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{TokenURL: server.URL + "/token"}},
	}
	sess := oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "old-access", RefreshToken: "old-refresh", Expiry: time.Now().Add(-time.Minute)}})
	auth, err := a.RestoreFromSession(ctx, sess, &RestoreOpts{})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Equal(t, sess, auth.FindSession())
	var stored oidcToken
	require.NoError(t, json.Unmarshal(sess.token, &stored))
	require.Equal(t, "new-access", stored.AccessToken)
	require.Equal(t, "new-refresh", stored.RefreshToken)
	require.WithinDuration(t, time.Now(), stored.ReceivedAt, time.Second)
	due, err := a.NextRefreshAt(ctx, sess)
	require.NoError(t, err)
	require.True(t, due.After(time.Now()))
	_, lost, err := a.RefreshSession(ctx, sess)
	require.NoError(t, err)
	require.False(t, lost)
	require.Equal(t, 1, calls)
}

func TestOidcRefreshWithoutNewIdTokenDoesNotReuseExpiredProof(t *testing.T) {
	const issuer = "https://issuer.example"
	idToken, claims := oidcRestoreTestIdToken(t, issuer, "client", time.Now().Add(-time.Minute))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{
			RetrieveIdToken: true, ForceDisposeSessionOn: "lostAccess",
		},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
		verifier:     coidc.NewVerifier(issuer, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{ClientID: "client"}),
	}
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "keep-refresh", Expiry: time.Now().Add(-time.Minute)},
		IdToken: idToken, Subject: "subject", Issuer: issuer, LastVerifiedAt: time.Now().Add(-time.Minute), ReceivedAt: time.Now().Add(-time.Hour),
	})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	auth, err := a.RestoreFromSession(ctx, sess, &RestoreOpts{})
	require.NoError(t, err)
	require.Nil(t, auth.(*oidc).idToken.IDToken)
	var stored oidcToken
	require.NoError(t, json.Unmarshal(sess.token, &stored))
	require.Empty(t, stored.IdToken)
	require.Equal(t, "keep-refresh", stored.RefreshToken)
	require.Equal(t, "subject", stored.Subject)
	require.WithinDuration(t, time.Now(), stored.LastVerifiedAt, time.Second)
}

func TestOidcLostAccessRefreshWithoutIdTokenRenewsVerificationBeyondThirtyMinutes(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess"},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
	}
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour)},
		Subject: "pinned", Issuer: "issuer", ReceivedAt: time.Now().Add(-3 * time.Hour), LastVerifiedAt: time.Now().Add(-25 * time.Minute),
	})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	for i := range 2 {
		next, lost, err := a.RefreshSession(ctx, sess)
		require.NoError(t, err)
		require.False(t, lost)
		var stored oidcToken
		require.NoError(t, json.Unmarshal(sess.token, &stored))
		require.Equal(t, "pinned", stored.Subject)
		require.Equal(t, "issuer", stored.Issuer)
		require.WithinDuration(t, time.Now(), stored.LastVerifiedAt, time.Second)
		require.True(t, next.After(time.Now()))
		require.LessOrEqual(t, next.Sub(stored.LastVerifiedAt), 30*time.Minute)
		if i == 0 {
			stored.LastVerifiedAt = time.Now().Add(-25 * time.Minute)
			stored.ReceivedAt = time.Now().Add(-3 * time.Hour)
			sess = oidcRefreshTestSession(t, stored)
		}
	}
	require.EqualValues(t, 2, exchanges.Load())
}

func TestOidcLostAccessDoesNotRecoverAfterVerificationDeadline(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess"},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
	}
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour)},
		Subject: "user", Issuer: "issuer", ReceivedAt: time.Now().Add(-time.Hour), LastVerifiedAt: time.Now().Add(-31 * time.Minute),
	})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	_, lost, err := a.RefreshSession(ctx, sess)
	require.ErrorContains(t, err, "deadline exceeded")
	require.True(t, lost)
	require.Zero(t, exchanges.Load())
}

func TestOidcProactiveReconnectRefreshesExpiredIdTokenDespiteValidAccessToken(t *testing.T) {
	const issuer = "https://issuer.example"
	idToken, claims := oidcRestoreTestIdToken(t, issuer, "client", time.Now().Add(-time.Minute))
	failRefresh := false
	var exchanges atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if failRefresh {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		} else {
			_, _ = w.Write([]byte(`{"access_token":"refreshed","token_type":"Bearer","expires_in":3600}`))
		}
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{
			RetrieveIdToken: true, ForceDisposeSessionOn: "never", RefreshToken: configuration.AuthorizationOidcRefreshToken{Mode: "proactive"},
		},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL, AuthStyle: oauth2.AuthStyleInHeader}},
		verifier:     coidc.NewVerifier(issuer, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{ClientID: "client"}),
	}
	initial := oidcToken{
		Token:   &oauth2.Token{AccessToken: "still-valid", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour)},
		IdToken: idToken, Subject: "subject", Issuer: issuer, LastVerifiedAt: time.Now().Add(-time.Minute), ReceivedAt: time.Now(),
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	failingSession := oidcRefreshTestSession(t, initial)
	due, err := a.NextRefreshAt(ctx, failingSession)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), due, time.Second)
	failRefresh = true
	_, err = a.RestoreFromSession(ctx, failingSession, &RestoreOpts{})
	require.ErrorContains(t, err, "refresh token was rejected")
	require.NotErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Zero(t, failingSession.setTokenCalls)

	sess := oidcRefreshTestSession(t, initial)
	failRefresh = false
	auth, err := a.RestoreFromSession(ctx, sess, &RestoreOpts{})
	require.NoError(t, err)
	require.Equal(t, "refreshed", auth.(*oidc).token.AccessToken)
	require.Nil(t, auth.(*oidc).idToken.IDToken)
	var stored oidcToken
	require.NoError(t, json.Unmarshal(sess.token, &stored))
	require.Empty(t, stored.IdToken)
	require.WithinDuration(t, time.Now(), stored.LastVerifiedAt, time.Second)
	backgroundSession := oidcRefreshTestSession(t, initial)
	next, lost, err := a.RefreshSession(ctx, backgroundSession)
	require.NoError(t, err)
	require.False(t, lost)
	require.True(t, next.After(time.Now()))
	require.NoError(t, json.Unmarshal(backgroundSession.token, &stored))
	require.Equal(t, "refreshed", stored.AccessToken)
	require.EqualValues(t, 3, exchanges.Load())
}

func TestOidcConcurrentRefreshUsesRotatedSessionToken(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new","refresh_token":"rotated","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "never", RefreshToken: configuration.AuthorizationOidcRefreshToken{Mode: "proactive"}},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
	}
	sess := oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "old", RefreshToken: "old-refresh", Expiry: time.Now().Add(-time.Minute)}})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, _, err := a.RefreshSession(ctx, sess)
			results <- err
		}()
	}
	for range 2 {
		require.NoError(t, <-results)
	}
	require.EqualValues(t, 1, exchanges.Load())
	require.Equal(t, 1, sess.setTokenCalls)
}

func TestOidcRefreshInvalidGrantAndTransientFailure(t *testing.T) {
	status := http.StatusBadRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusBadRequest {
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		} else {
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
		}
	}))
	defer server.Close()
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess", RefreshToken: configuration.AuthorizationOidcRefreshToken{Mode: "proactive"}},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
	}
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh"},
		Subject: "subject", Issuer: "issuer", LastVerifiedAt: time.Now(),
	})
	_, lost, err := a.RefreshSession(ctx, sess)
	require.Error(t, err)
	require.True(t, lost)
	require.Zero(t, sess.setTokenCalls)
	status = http.StatusServiceUnavailable
	next, lost, err := a.RefreshSession(ctx, sess)
	require.Error(t, err)
	require.False(t, lost)
	require.True(t, next.After(time.Now()))
	require.Zero(t, sess.setTokenCalls)
}

func TestOidcLostAccessRejectsExpiredRefreshResponseAfterDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"already-expired","token_type":"Bearer","expires_in":-60}`))
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess"},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	for _, tc := range []struct {
		name string
		age  time.Duration
		lost bool
	}{
		{name: "retry before deadline", age: time.Minute},
		{name: "dispose after deadline", age: time.Hour, lost: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := oidcRefreshTestSession(t, oidcToken{
				Token:          &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Minute)},
				Subject:        "user",
				Issuer:         "issuer",
				ReceivedAt:     time.Now().Add(-tc.age),
				LastVerifiedAt: time.Now().Add(-tc.age),
			})
			_, lost, err := a.RefreshSession(ctx, sess)
			require.Error(t, err)
			require.Equal(t, tc.lost, lost)
			require.Zero(t, sess.setTokenCalls)
		})
	}
}

func TestOidcNeverKeepsSessionOnInvalidGrantAndIdentityMismatch(t *testing.T) {
	const secret = "secret-refresh-token"
	issuer := "https://issuer.example"
	idToken, claims := oidcRestoreTestIdToken(t, issuer, "client", time.Now().Add(time.Hour))
	invalidGrant := true
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if invalidGrant {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"secret-refresh-token"}`))
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken})
		}
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "never", RefreshToken: configuration.AuthorizationOidcRefreshToken{Mode: "proactive"}},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
		verifier:     coidc.NewVerifier(issuer, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{ClientID: "client"}),
	}
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: secret, Expiry: time.Now().Add(-time.Minute)},
		Subject: "original", Issuer: issuer, LastVerifiedAt: time.Now().Add(-time.Minute), ReceivedAt: time.Now().Add(-time.Hour),
	})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	for _, mismatch := range []bool{false, true} {
		invalidGrant = !mismatch
		next, lost, err := a.RefreshSession(ctx, sess)
		require.Error(t, err)
		require.False(t, lost)
		require.True(t, next.After(time.Now()))
		require.NotContains(t, err.Error(), secret)
		require.NotContains(t, err.Error(), idToken)
		require.Zero(t, sess.setTokenCalls)
		_, err = a.RestoreFromSession(ctx, sess, &RestoreOpts{})
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrUnusableAuthorizationToken)
		require.NotContains(t, err.Error(), secret)
		require.Zero(t, sess.setTokenCalls)
	}
}

func TestOidcRefreshRejectsChangedSubject(t *testing.T) {
	const issuer = "https://issuer.example"
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	claims, err := json.Marshal(map[string]any{"iss": issuer, "sub": "different", "aud": "client", "iat": expires.Add(-time.Hour).Unix(), "exp": expires.Unix()})
	require.NoError(t, err)
	idToken := header + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("signature"))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken})
	}))
	defer server.Close()
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess"},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
		verifier:     coidc.NewVerifier(issuer, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{ClientID: "client"}),
	}
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Minute)},
		Subject: "original", Issuer: issuer, LastVerifiedAt: time.Now().Add(-time.Minute), ReceivedAt: time.Now().Add(-time.Hour),
	})
	_, lost, err := a.RefreshSession(ctx, sess)
	require.ErrorContains(t, err, "identity differs")
	require.True(t, lost)
	require.Zero(t, sess.setTokenCalls)
}

func TestOidcLostAccessRejectsMissingRefreshToken(t *testing.T) {
	for name, conf := range map[string]*configuration.AuthorizationOidcDeviceAuth{
		"zero-value defaults": {},
		"explicit lostAccess": {ForceDisposeSessionOn: "lostAccess"},
	} {
		t.Run(name, func(t *testing.T) {
			a := &OidcDeviceAuthAuthorizer{flow: "flow", conf: conf}
			sess := oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "access"}, Subject: "user", Issuer: "issuer", LastVerifiedAt: time.Now()})
			_, lost, err := a.RefreshSession(context.Background(), sess)
			require.ErrorContains(t, err, "no refresh token")
			require.True(t, lost)
			_, err = a.RestoreFromSession(context.Background(), sess, &RestoreOpts{})
			require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
		})
	}
}

func TestOidcLostAccessRejectsMissingAuthorizationToken(t *testing.T) {
	a := &OidcDeviceAuthAuthorizer{flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess"}}
	for _, tc := range []struct {
		name  string
		token []byte
		cause string
	}{
		{name: "missing token", cause: "no authorization token"},
		{name: "invalid token", token: []byte("broken"), cause: "invalid persisted OIDC session token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := &authorizationRestoreTestSession{flow: "flow", token: tc.token}
			due, err := a.NextRefreshAt(context.Background(), sess)
			require.NoError(t, err)
			require.WithinDuration(t, time.Now(), due, time.Second)
			_, lost, err := a.RefreshSession(context.Background(), sess)
			require.ErrorContains(t, err, tc.cause)
			require.True(t, lost)
		})
	}
}

func TestOidcLostAccessDoesNotRestorePastVerificationDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess"},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
	}
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "still-valid", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour)},
		Subject: "user", Issuer: "issuer", ReceivedAt: time.Now().Add(-time.Hour), LastVerifiedAt: time.Now().Add(-time.Hour),
	})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	_, err := a.RestoreFromSession(ctx, sess, &RestoreOpts{})
	require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Zero(t, sess.setTokenCalls)
}

func TestOidcVerificationDeadline(t *testing.T) {
	verified := time.Now().UTC().Truncate(time.Second)
	sess := oidcRefreshTestSession(t, oidcToken{
		Token: &oauth2.Token{AccessToken: "access"}, Subject: "subject", Issuer: "issuer", LastVerifiedAt: verified,
	})
	a := &OidcDeviceAuthAuthorizer{flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{
		ForceDisposeSessionOn: "lostAccess", RefreshToken: configuration.AuthorizationOidcRefreshToken{MaxUnverifiedFor: common.DurationOf(8 * time.Minute)},
	}}
	due, err := a.VerificationDeadline(context.Background(), sess)
	require.NoError(t, err)
	require.Equal(t, verified.Add(8*time.Minute), due)
	a.conf.RefreshToken.MaxUnverifiedFor = common.DurationOf(0)
	due, err = a.VerificationDeadline(context.Background(), sess)
	require.NoError(t, err)
	require.Equal(t, verified.Add(30*time.Minute), due)
	a.conf.ForceDisposeSessionOn = "never"
	due, err = a.VerificationDeadline(context.Background(), sess)
	require.NoError(t, err)
	require.True(t, due.IsZero())

	a.conf.ForceDisposeSessionOn = "lostAccess"
	for _, tc := range []struct {
		name  string
		token []byte
		err   error
	}{
		{"missing", nil, ErrNoSuchAuthorization},
		{"malformed", []byte("broken"), ErrUnusableAuthorizationToken},
		{"storage", nil, errors.New("storage failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := &authorizationRestoreTestSession{flow: "flow", token: tc.token}
			if tc.name == "storage" {
				candidate.tokenErr = tc.err
			}
			_, err := a.VerificationDeadline(context.Background(), candidate)
			require.ErrorIs(t, err, tc.err)
		})
	}
	missingIdentity := oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "access"}})
	_, err = a.VerificationDeadline(context.Background(), missingIdentity)
	require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
}

func TestOidcSessionLockRespectsCancellation(t *testing.T) {
	a := &OidcDeviceAuthAuthorizer{flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess"}}
	sess := oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "access"}})
	unlock, err := a.lockSession(context.Background(), sess)
	require.NoError(t, err)
	defer unlock()
	for _, tc := range []struct {
		name string
		call func(context.Context) error
	}{
		{"next refresh", func(ctx context.Context) error { _, err := a.NextRefreshAt(ctx, sess); return err }},
		{"refresh", func(ctx context.Context) error { _, _, err := a.RefreshSession(ctx, sess); return err }},
		{"deadline", func(ctx context.Context) error { _, err := a.VerificationDeadline(ctx, sess); return err }},
		{"restore", func(ctx context.Context) error { _, err := a.RestoreFromSession(ctx, sess, &RestoreOpts{}); return err }},
		{"public key candidate", func(ctx context.Context) error { _, err := a.lockSession(ctx, sess); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- tc.call(ctx) }()
			select {
			case err := <-result:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case <-time.After(time.Second):
				t.Fatal("session lock did not stop waiting after context cancellation")
			}
		})
	}
}

func TestOidcRefreshRetainsOnlyUnexpiredBoundIdToken(t *testing.T) {
	const issuer = "https://issuer.example"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	for _, tc := range []struct {
		name    string
		expiry  time.Time
		subject string
		retain  bool
	}{
		{"valid", time.Now().Add(2 * time.Minute), "subject", true},
		{"expired", time.Now().Add(-time.Minute), "subject", false},
		{"different subject", time.Now().Add(2 * time.Minute), "other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idToken, claims := oidcRestoreTestIdToken(t, issuer, "client", tc.expiry)
			a := &OidcDeviceAuthAuthorizer{
				flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: true, ForceDisposeSessionOn: "lostAccess"},
				oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
				verifier:     coidc.NewVerifier(issuer, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{ClientID: "client"}),
			}
			sess := oidcRefreshTestSession(t, oidcToken{
				Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Minute)},
				IdToken: idToken, Subject: tc.subject, Issuer: issuer, LastVerifiedAt: time.Now(),
			})
			next, lost, err := a.RefreshSession(ctx, sess)
			require.NoError(t, err)
			require.False(t, lost)
			var stored oidcToken
			require.NoError(t, json.Unmarshal(sess.token, &stored))
			if tc.retain {
				require.Equal(t, idToken, stored.IdToken)
				require.True(t, tc.expiry.UTC().Truncate(time.Second).Equal(next))
				auth, err := a.RestoreFromSession(ctx, sess, &RestoreOpts{})
				require.NoError(t, err)
				require.Equal(t, "subject", auth.(*oidc).idToken.Subject)
			} else {
				require.Empty(t, stored.IdToken)
				require.Nil(t, stored.Token.Extra("id_token"))
			}
		})
	}
}

func TestOidcRefreshWithNewIdTokenSchedulesItsExpiry(t *testing.T) {
	const issuer = "https://issuer.example"
	expiry := time.Now().Add(2 * time.Minute).UTC().Truncate(time.Second)
	idToken, claims := oidcRestoreTestIdToken(t, issuer, "client", expiry)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken,
		})
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: true, ForceDisposeSessionOn: "lostAccess"},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
		verifier:     coidc.NewVerifier(issuer, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{ClientID: "client"}),
	}
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Minute)},
		Subject: "subject", Issuer: issuer, LastVerifiedAt: time.Now().Add(-20 * time.Minute),
	})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	next, lost, err := a.RefreshSession(ctx, sess)
	require.NoError(t, err)
	require.False(t, lost)
	require.True(t, next.Equal(expiry))
	fromStorage, err := a.NextRefreshAt(ctx, sess)
	require.NoError(t, err)
	require.True(t, fromStorage.Equal(next))
	deadline, err := a.VerificationDeadline(ctx, sess)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().Add(30*time.Minute), deadline, time.Second)
}

func TestOidcLostAccessRefreshCapsNetworkAtVerificationDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"late","token_type":"Bearer"}`))
		}
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{
			ForceDisposeSessionOn: "lostAccess", RefreshToken: configuration.AuthorizationOidcRefreshToken{MaxUnverifiedFor: common.DurationOf(time.Minute)},
		},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
	}
	sess := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Minute)},
		Subject: "subject", Issuer: "issuer", LastVerifiedAt: time.Now().Add(-time.Minute + 150*time.Millisecond),
	})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	start := time.Now()
	_, lost, err := a.RefreshSession(ctx, sess)
	require.True(t, lost)
	require.ErrorContains(t, err, "deadline")
	require.Less(t, time.Since(start), 800*time.Millisecond)
	require.Zero(t, sess.setTokenCalls)
}

func TestOidcRefreshOnVerifiedOnlyAfterPersistence(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{
			ForceDisposeSessionOn: "lostAccess", RefreshToken: configuration.AuthorizationOidcRefreshToken{MaxUnverifiedFor: common.DurationOf(8 * time.Minute)},
		},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
	}
	var verified []time.Time
	a.OnVerified = func(got session.Session, deadline time.Time) {
		sess := got.(*authorizationRestoreTestSession)
		var stored oidcToken
		require.NoError(t, json.Unmarshal(sess.token, &stored))
		require.Equal(t, "new", stored.AccessToken)
		require.True(t, stored.LastVerifiedAt.Add(8*time.Minute).Equal(deadline))
		verified = append(verified, deadline)
	}
	initial := oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Minute)},
		Subject: "user", Issuer: "issuer", LastVerifiedAt: time.Now().Add(-time.Minute),
	}
	sess := oidcRefreshTestSession(t, initial)
	_, lost, err := a.RefreshSession(ctx, sess)
	require.NoError(t, err)
	require.False(t, lost)
	require.Len(t, verified, 1)
	require.WithinDuration(t, time.Now().Add(8*time.Minute), verified[0], time.Second)
	_, lost, err = a.RefreshSession(ctx, sess)
	require.NoError(t, err)
	require.False(t, lost)
	require.Len(t, verified, 1)

	failing := oidcRefreshTestSession(t, initial)
	failing.setTokenErr = errors.New("write failed")
	_, lost, err = a.RefreshSession(ctx, failing)
	require.ErrorContains(t, err, "write failed")
	require.True(t, lost)
	require.Len(t, verified, 1)
	var stored oidcToken
	require.NoError(t, json.Unmarshal(failing.token, &stored))
	require.Equal(t, "old", stored.AccessToken)

	a.conf.ForceDisposeSessionOn = "never"
	never := oidcRefreshTestSession(t, initial)
	_, lost, err = a.RefreshSession(ctx, never)
	require.NoError(t, err)
	require.False(t, lost)
	require.Len(t, verified, 1)
}

type oidcRefreshTestContext struct {
	essh.Context
	base context.Context
}

func (this oidcRefreshTestContext) Deadline() (time.Time, bool) { return this.base.Deadline() }
func (this oidcRefreshTestContext) Done() <-chan struct{}       { return this.base.Done() }
func (this oidcRefreshTestContext) Err() error                  { return this.base.Err() }
func (this oidcRefreshTestContext) Value(key any) any           { return this.base.Value(key) }

type oidcRefreshTestRemote struct{ net.Remote }

func (oidcRefreshTestRemote) User() string { return "user" }

type oidcRefreshTestConnection struct{ connection.Connection }

func (oidcRefreshTestConnection) Remote() net.Remote { return oidcRefreshTestRemote{} }

type oidcRefreshTestRepository struct {
	session.Repository
	candidate session.Session
}

func (this oidcRefreshTestRepository) FindByPublicKey(ctx context.Context, _ gossh.PublicKey, opts *session.FindOpts) (session.Session, error) {
	// The preceding repository predicates are not relevant to the refresh candidate path.
	match, err := opts.Predicates[len(opts.Predicates)-1](ctx, this.candidate)
	if err != nil {
		return nil, err
	}
	if !match {
		return nil, session.ErrNoSuchSession
	}
	return this.candidate, nil
}

type oidcRefreshTestPublicKeyRequest struct {
	PublicKeyRequest
	repository session.Repository
	ctx        essh.Context
}

func (this oidcRefreshTestPublicKeyRequest) Sessions() session.Repository { return this.repository }
func (this oidcRefreshTestPublicKeyRequest) Context() essh.Context        { return this.ctx }
func (oidcRefreshTestPublicKeyRequest) RemotePublicKey() gossh.PublicKey  { return nil }
func (oidcRefreshTestPublicKeyRequest) Connection() connection.Connection {
	return oidcRefreshTestConnection{}
}

func TestOidcPublicKeyOnLostAccess(t *testing.T) {
	const issuer = "https://issuer.example"
	idToken, claims := oidcRestoreTestIdToken(t, issuer, "client", time.Now().Add(-time.Minute))
	status := http.StatusBadRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusBadRequest {
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		} else {
			_, _ = w.Write([]byte(`{"error":"server_error"}`))
		}
	}))
	defer server.Close()
	a := &OidcDeviceAuthAuthorizer{
		flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{
			RetrieveIdToken: true, ForceDisposeSessionOn: "lostAccess",
		},
		oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: server.URL}},
		verifier:     coidc.NewVerifier(issuer, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{ClientID: "client"}),
	}
	ctx := oidcRefreshTestContext{base: context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())}
	var lost []session.Session
	a.OnLostAccess = func(sess session.Session) { lost = append(lost, sess) }
	for _, tc := range []struct {
		name  string
		token oidcToken
	}{
		{"valid access token", oidcToken{Token: &oauth2.Token{AccessToken: "old", Expiry: time.Now().Add(time.Hour)}, Subject: "user", Issuer: issuer, LastVerifiedAt: time.Now()}},
		{"expired access token", oidcToken{Token: &oauth2.Token{AccessToken: "old", Expiry: time.Now().Add(-time.Minute)}, Subject: "user", Issuer: issuer, LastVerifiedAt: time.Now()}},
		{"expired ID token", oidcToken{Token: &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour)}, IdToken: idToken, Subject: "subject", Issuer: issuer, LastVerifiedAt: time.Now(), ReceivedAt: time.Now()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := oidcRefreshTestSession(t, tc.token)
			req := oidcRefreshTestPublicKeyRequest{repository: oidcRefreshTestRepository{candidate: sess}, ctx: ctx}
			auth, err := a.AuthorizePublicKey(req)
			require.NoError(t, err)
			require.False(t, auth.IsAuthorized())
			require.Equal(t, []session.Session{sess}, lost)
			lost = nil
		})
	}

	transient := oidcRefreshTestSession(t, oidcToken{
		Token:   &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour)},
		Subject: "user", Issuer: issuer, LastVerifiedAt: time.Now(), ReceivedAt: time.Now().Add(-3 * time.Hour),
	})
	status = http.StatusServiceUnavailable
	req := oidcRefreshTestPublicKeyRequest{repository: oidcRefreshTestRepository{candidate: transient}, ctx: ctx}
	_, err := a.AuthorizePublicKey(req)
	require.ErrorContains(t, err, "OIDC token refresh failed")
	require.Empty(t, lost)

	a.conf.ForceDisposeSessionOn = "never"
	status = http.StatusBadRequest
	never := oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Minute)}})
	req.repository = oidcRefreshTestRepository{candidate: never}
	_, err = a.AuthorizePublicKey(req)
	require.ErrorContains(t, err, "refresh token was rejected")
	require.Empty(t, lost)
}
