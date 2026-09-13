package authorization

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestRestoreFromSessionClassifiesMalformedPersistedTokensAsUnusable(t *testing.T) {
	for name, authorizer := range map[string]Authorizer{
		"bifroest": &BifroestAuthorizer{flow: "flow"},
		"htpasswd": &HtpasswdAuthorizer{flow: "flow"},
		"oidc":     &OidcDeviceAuthAuthorizer{flow: "flow"},
		"simple":   &SimpleAuthorizer{flow: "flow", conf: &configuration.AuthorizationSimple{}},
	} {
		t.Run(name, func(t *testing.T) {
			sess := &authorizationRestoreTestSession{flow: "flow", token: []byte("not-json")}

			_, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{})

			require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
			require.Zero(t, sess.setTokenCalls)
		})
	}
}

func TestRestoreFromSessionAutoCleanupRemovesMalformedPersistedTokens(t *testing.T) {
	for name, authorizer := range map[string]Authorizer{
		"bifroest": &BifroestAuthorizer{flow: "flow"},
		"htpasswd": &HtpasswdAuthorizer{flow: "flow"},
		"oidc":     &OidcDeviceAuthAuthorizer{flow: "flow"},
		"simple":   &SimpleAuthorizer{flow: "flow", conf: &configuration.AuthorizationSimple{}},
	} {
		t.Run(name, func(t *testing.T) {
			sess := &authorizationRestoreTestSession{flow: "flow", token: []byte("not-json")}
			autoCleanup := true

			_, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{AutoCleanUpAllowed: &autoCleanup})

			require.ErrorIs(t, err, ErrNoSuchAuthorization)
			require.NotErrorIs(t, err, ErrUnusableAuthorizationToken)
			require.Equal(t, 1, sess.setTokenCalls)
			require.Empty(t, sess.token)
		})
	}
}

func TestSimpleRestoreClassifiesRemovedConfigurationEntryAsUnusable(t *testing.T) {
	authorizer := &SimpleAuthorizer{flow: "flow", conf: &configuration.AuthorizationSimple{}}
	sess := &authorizationRestoreTestSession{flow: "flow", token: []byte(`{"user":{"name":"removed"}}`)}

	_, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{})

	require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Zero(t, sess.setTokenCalls)
}

func TestSimpleRestoreAutoCleanupRemovesTokenForRemovedConfigurationEntry(t *testing.T) {
	authorizer := &SimpleAuthorizer{flow: "flow", conf: &configuration.AuthorizationSimple{}}
	sess := &authorizationRestoreTestSession{flow: "flow", token: []byte(`{"user":{"name":"removed"}}`)}
	autoCleanup := true

	_, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{AutoCleanUpAllowed: &autoCleanup})

	require.ErrorIs(t, err, ErrNoSuchAuthorization)
	require.Equal(t, 1, sess.setTokenCalls)
	require.Empty(t, sess.token)
}

func TestRestoreAutoCleanupKeepsTokenWhenStorageRemovalFails(t *testing.T) {
	storageErr := errors.New("storage temporarily unavailable")
	authorizer := &HtpasswdAuthorizer{flow: "flow"}
	sess := &authorizationRestoreTestSession{flow: "flow", token: []byte("not-json"), setTokenErr: storageErr}
	autoCleanup := true

	_, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{AutoCleanUpAllowed: &autoCleanup})

	require.ErrorIs(t, err, storageErr)
	require.NotErrorIs(t, err, ErrNoSuchAuthorization)
	require.NotErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Equal(t, []byte("not-json"), sess.token)
}

func TestRestoreDoesNotClassifyTokenReadFailureAsUnusable(t *testing.T) {
	readErr := errors.New("storage temporarily unavailable")
	authorizer := &HtpasswdAuthorizer{flow: "flow"}
	sess := &authorizationRestoreTestSession{flow: "flow", tokenErr: readErr}

	autoCleanup := true
	_, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{AutoCleanUpAllowed: &autoCleanup})

	require.ErrorIs(t, err, readErr)
	require.NotErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Zero(t, sess.setTokenCalls)
}

func TestOidcRestoreClassifiesExpiredPersistedTokenAsUnusable(t *testing.T) {
	raw, err := json.Marshal(oidcToken{Token: &oauth2.Token{
		AccessToken: "expired",
		Expiry:      time.Now().Add(-time.Minute),
	}})
	require.NoError(t, err)
	authorizer := &OidcDeviceAuthAuthorizer{flow: "flow"}

	withoutCleanup := &authorizationRestoreTestSession{flow: "flow", token: raw}
	_, err = authorizer.RestoreFromSession(context.Background(), withoutCleanup, &RestoreOpts{})
	require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Zero(t, withoutCleanup.setTokenCalls)

	withCleanup := &authorizationRestoreTestSession{flow: "flow", token: raw}
	autoCleanup := true
	_, err = authorizer.RestoreFromSession(context.Background(), withCleanup, &RestoreOpts{AutoCleanUpAllowed: &autoCleanup})
	require.ErrorIs(t, err, ErrNoSuchAuthorization)
	require.NotErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Equal(t, 1, withCleanup.setTokenCalls)
	require.Empty(t, withCleanup.token)
}

func TestOidcRestoreClassifiesExpiredIdTokenAsUnusable(t *testing.T) {
	const (
		issuer   = "https://issuer.example"
		clientId = "client"
	)
	now := time.Now().UTC().Truncate(time.Second)
	idToken, claims := oidcRestoreTestIdToken(t, issuer, clientId, now.Add(-time.Minute))
	verifier := coidc.NewVerifier(issuer, oidcRestoreTestKeySet{payload: claims}, &coidc.Config{
		ClientID: clientId,
		Now:      func() time.Time { return now },
	})
	_, err := verifier.Verify(context.Background(), idToken)
	var expired *coidc.TokenExpiredError
	require.ErrorAs(t, err, &expired)

	raw, err := json.Marshal(oidcToken{
		Token:   &oauth2.Token{AccessToken: "still-valid", Expiry: now.Add(time.Hour)},
		IdToken: idToken,
	})
	require.NoError(t, err)
	authorizer := &OidcDeviceAuthAuthorizer{
		flow:     "flow",
		conf:     &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: true},
		verifier: verifier,
	}

	withoutCleanup := &authorizationRestoreTestSession{flow: "flow", token: raw}
	_, err = authorizer.RestoreFromSession(context.Background(), withoutCleanup, &RestoreOpts{})
	require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Zero(t, withoutCleanup.setTokenCalls)

	withCleanup := &authorizationRestoreTestSession{flow: "flow", token: raw}
	autoCleanup := true
	_, err = authorizer.RestoreFromSession(context.Background(), withCleanup, &RestoreOpts{AutoCleanUpAllowed: &autoCleanup})
	require.ErrorIs(t, err, ErrNoSuchAuthorization)
	require.NotErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Equal(t, 1, withCleanup.setTokenCalls)
	require.Empty(t, withCleanup.token)
}

func TestOidcRestoreDoesNotClassifyVerifierFailureAsUnusable(t *testing.T) {
	const (
		issuer   = "https://issuer.example"
		clientId = "client"
	)
	now := time.Now().UTC().Truncate(time.Second)
	idToken, _ := oidcRestoreTestIdToken(t, issuer, clientId, now.Add(time.Hour))
	transientErr := errors.New("temporary verifier failure")
	verifier := coidc.NewVerifier(issuer, oidcRestoreTestKeySet{err: transientErr}, &coidc.Config{
		ClientID: clientId,
		Now:      func() time.Time { return now },
	})
	raw, err := json.Marshal(oidcToken{
		Token:   &oauth2.Token{AccessToken: "still-valid", Expiry: now.Add(time.Hour)},
		IdToken: idToken,
	})
	require.NoError(t, err)
	authorizer := &OidcDeviceAuthAuthorizer{
		flow:     "flow",
		conf:     &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: true},
		verifier: verifier,
	}
	autoCleanup := true
	sess := &authorizationRestoreTestSession{flow: "flow", token: raw}

	_, err = authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{AutoCleanUpAllowed: &autoCleanup})

	require.ErrorContains(t, err, transientErr.Error())
	require.NotErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.NotErrorIs(t, err, ErrNoSuchAuthorization)
	require.Zero(t, sess.setTokenCalls)
	require.Equal(t, raw, sess.token)
}

type oidcRestoreTestKeySet struct {
	payload []byte
	err     error
}

func (this oidcRestoreTestKeySet) VerifySignature(context.Context, string) ([]byte, error) {
	return this.payload, this.err
}

func oidcRestoreTestIdToken(t *testing.T, issuer, clientId string, expiry time.Time) (string, []byte) {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT"})
	require.NoError(t, err)
	claims, err := json.Marshal(map[string]any{
		"iss": issuer,
		"sub": "subject",
		"aud": clientId,
		"iat": expiry.Add(-time.Hour).Unix(),
		"exp": expiry.Unix(),
	})
	require.NoError(t, err)
	encode := base64.RawURLEncoding.EncodeToString
	return encode(header) + "." + encode(claims) + "." + encode([]byte("signature")), claims
}

type authorizationRestoreTestSession struct {
	session.Session
	flow          configuration.FlowName
	token         []byte
	tokenErr      error
	setTokenErr   error
	setTokenCalls int
}

func (this *authorizationRestoreTestSession) Flow() configuration.FlowName { return this.flow }
func (this *authorizationRestoreTestSession) AuthorizationToken(context.Context) ([]byte, error) {
	return append([]byte(nil), this.token...), this.tokenErr
}
func (this *authorizationRestoreTestSession) SetAuthorizationToken(_ context.Context, token []byte) error {
	this.setTokenCalls++
	if this.setTokenErr != nil {
		return this.setTokenErr
	}
	this.token = append(this.token[:0], token...)
	return nil
}
