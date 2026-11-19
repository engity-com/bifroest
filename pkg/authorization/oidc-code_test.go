package authorization

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestOidcCodePersistedGrantsRemainDistinctFromLegacyDeviceGrants(t *testing.T) {
	identity := authentication.Identity{Principal: "subject", Subject: "subject", Issuer: "https://idp.example.org"}
	legacy := oidcToken{Token: &oauth2.Token{AccessToken: "legacy"}, Subject: identity.Subject, Issuer: identity.Issuer, LastVerifiedAt: time.Now()}
	code := legacy
	code.Grant = "authorization_code"
	deviceAuthorizer := &OidcDeviceAuthAuthorizer{flow: "flow"}
	codeAuthorizer := &OidcDeviceAuthAuthorizer{flow: "flow", code: &configuration.AuthorizationOidcAuthorizationCode{}}
	legacySession, codeSession := oidcRefreshTestSession(t, legacy), oidcRefreshTestSession(t, code)
	_, err := deviceAuthorizer.readSessionToken(t.Context(), legacySession)
	require.NoError(t, err, "historical Device Auth tokens retain their meaning")
	_, err = codeAuthorizer.readSessionToken(t.Context(), codeSession)
	require.NoError(t, err)
	_, err = codeAuthorizer.readSessionToken(t.Context(), legacySession)
	require.ErrorIs(t, err, ErrNoSuchAuthorization)
	_, err = deviceAuthorizer.readSessionToken(t.Context(), codeSession)
	require.ErrorIs(t, err, ErrNoSuchAuthorization)
	compatible, err := codeAuthorizer.primarySessionReuse(identity, &code)(t.Context(), legacySession)
	require.NoError(t, err)
	require.False(t, compatible, "a fresh code login must not adopt a legacy device session")
	_, err = codeAuthorizer.RestoreFromSession(t.Context(), legacySession, nil)
	require.ErrorIs(t, err, ErrNoSuchAuthorization)
	_, err = deviceAuthorizer.RestoreFromSession(t.Context(), codeSession, nil)
	require.ErrorIs(t, err, ErrNoSuchAuthorization)
}
