package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestOidcPrimaryReuseDisabledRefreshIsSerializedAndMonotonic(t *testing.T) {
	identity := authentication.Identity{Principal: "subject", Issuer: "https://issuer.example", Subject: "subject"}
	a := &OidcDeviceAuthAuthorizer{flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "never", RefreshToken: configuration.AuthorizationOidcRefreshToken{Mode: "never"}}}
	now := time.Now()
	old := oidcToken{Token: &oauth2.Token{AccessToken: "old", Expiry: now.Add(-time.Minute)}, Subject: identity.Subject, Issuer: identity.Issuer, LastVerifiedAt: now.Add(-time.Hour)}
	sess := oidcRefreshTestSession(t, old)
	fresh := oidcToken{Token: &oauth2.Token{AccessToken: "fresh", Expiry: now.Add(time.Hour)}, Subject: identity.Subject, Issuer: identity.Issuer, LastVerifiedAt: now}
	ok, err := a.primarySessionReuse(identity, &fresh)(t.Context(), sess)
	require.NoError(t, err)
	require.True(t, ok)
	var stored oidcToken
	require.NoError(t, json.Unmarshal(sess.token, &stored))
	require.Equal(t, "fresh", stored.AccessToken)
	stale := fresh
	stale.Token = &oauth2.Token{AccessToken: "stale"}
	stale.LastVerifiedAt = now.Add(-time.Minute)
	ok, err = a.primarySessionReuse(identity, &stale)(t.Context(), sess)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, json.Unmarshal(sess.token, &stored))
	require.Equal(t, "fresh", stored.AccessToken)
	missing := oidcRefreshTestSession(t, old)
	missing.token = nil
	ok, err = a.primarySessionReuse(identity, &fresh)(t.Context(), missing)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, missing.token)
	other := old
	other.Subject = "different-subject"
	ok, err = a.primarySessionReuse(identity, &fresh)(t.Context(), oidcRefreshTestSession(t, other))
	require.Error(t, err)
	require.False(t, ok)
}

func TestOidcPrimaryReuseCannotPromoteUnverifiedPendingCredentials(t *testing.T) {
	identity := authentication.Identity{Principal: "subject", Issuer: "https://issuer.example", Subject: "subject"}
	idToken, _ := oidcRestoreTestIdToken(t, identity.Issuer, "client", time.Now().Add(time.Hour))
	a := &OidcDeviceAuthAuthorizer{flow: "flow", conf: &configuration.AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess"}, verifier: coidc.NewVerifier(identity.Issuer, oidcRestoreTestKeySet{err: errors.New("JWKS unavailable")}, &coidc.Config{ClientID: "client"})}
	old := oidcToken{Token: &oauth2.Token{AccessToken: "old", RefreshToken: "old-refresh"}, Subject: identity.Subject, Issuer: identity.Issuer, LastVerifiedAt: time.Now(), Pending: &oidcPendingVerification{Token: &oauth2.Token{AccessToken: "pending", RefreshToken: "pending-refresh"}, IdToken: idToken, ReceivedAt: time.Now()}}
	sess := oidcRefreshTestSession(t, old)
	before := append([]byte(nil), sess.token...)
	fresh := old
	fresh.Pending = nil
	fresh.Token = &oauth2.Token{AccessToken: "fresh", RefreshToken: "fresh-refresh"}
	ok, err := a.primarySessionReuse(identity, &fresh)(t.Context(), sess)
	require.ErrorContains(t, err, "pending ID token could not be verified")
	require.False(t, ok)
	require.Equal(t, before, sess.token)
	a.conf.ForceDisposeSessionOn = "never"
	a.conf.RefreshToken.Mode = "never"
	ok, err = a.primarySessionReuse(identity, &fresh)(t.Context(), sess)
	require.ErrorContains(t, err, "pending unverified credentials")
	require.False(t, ok)
	require.Equal(t, before, sess.token)
}

func TestOidcPrimaryReuseLockWaitHonorsCancellation(t *testing.T) {
	a := &OidcDeviceAuthAuthorizer{flow: "flow"}
	identity := authentication.Identity{Principal: "subject", Issuer: "https://issuer.example", Subject: "subject"}
	sess := oidcRefreshTestSession(t, oidcToken{Token: &oauth2.Token{AccessToken: "old"}})
	unlock, err := a.lockSession(t.Context(), sess)
	require.NoError(t, err)
	defer unlock()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ok, err := a.primarySessionReuse(identity, nil)(ctx, sess)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, ok)
}

type oidcReuseDeadlineKeySet struct {
	deadline time.Time
}

func (this *oidcReuseDeadlineKeySet) VerifySignature(ctx context.Context, _ string) ([]byte, error) {
	this.deadline, _ = ctx.Deadline()
	return nil, errors.New("JWKS unavailable")
}

func TestOidcPrimaryReuseProviderChecksKeepRetainedVerificationDeadline(t *testing.T) {
	identity := authentication.Identity{Principal: "subject", Issuer: "https://issuer.example", Subject: "subject"}
	conf := &configuration.AuthorizationOidcDeviceAuth{}
	require.NoError(t, conf.SetDefaults())
	keys := &oidcReuseDeadlineKeySet{}
	a := &OidcDeviceAuthAuthorizer{flow: "flow", conf: conf, verifier: coidc.NewVerifier(identity.Issuer, keys, &coidc.Config{ClientID: "client"})}
	idToken, _ := oidcRestoreTestIdToken(t, identity.Issuer, "client", time.Now().Add(time.Hour))
	now := time.Now()
	old := oidcToken{Token: &oauth2.Token{AccessToken: "old", RefreshToken: "old-refresh", Expiry: now.Add(time.Hour)}, IdToken: idToken, ReceivedAt: now, Subject: identity.Subject, Issuer: identity.Issuer, LastVerifiedAt: now.Add(-time.Minute)}
	fresh := old
	fresh.LastVerifiedAt = now
	sess := oidcRefreshTestSession(t, old)
	before := append([]byte(nil), sess.token...)
	ok, err := a.primarySessionReuse(identity, &fresh)(t.Context(), sess)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, old.LastVerifiedAt.Add(a.maxUnverifiedFor()).UTC(), keys.deadline.UTC())
	require.Equal(t, before, sess.token, "fresh login must not reset the old grant's verification deadline")
}
