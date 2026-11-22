package authorization

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
)

type principalMappingTestContext struct {
	ctx      context.Context
	identity authentication.Identity
	auth     Authorization
	marker   string
}

func (this *principalMappingTestContext) Context() context.Context { return this.ctx }

func (this *principalMappingTestContext) GetField(name string) (any, bool, error) {
	switch name {
	case "authentication":
		return this.identity, true, nil
	case "authorization":
		return this.auth, true, nil
	case "remote":
		return this.auth.Remote(), true, nil
	case "marker":
		return this.marker, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func newPrincipalMappingTestContext(t *testing.T, identity authentication.Identity, auth Authorization) *principalMappingTestContext {
	t.Helper()
	return &principalMappingTestContext{ctx: t.Context(), identity: identity, auth: auth}
}

func principalMappingTestFlows(mapping string) configuration.Flows {
	return configuration.Flows{
		{Name: "other", Authorization: configuration.Authorization{Principal: template.MustNewString("must-not-be-used")}},
		{Name: "flow", Authorization: configuration.Authorization{Principal: template.MustNewString(mapping)}},
	}
}

func newPrincipalMappingTestOidc() *oidc {
	identity := authentication.Identity{Principal: "subject-123", Issuer: "https://issuer.example", Subject: "subject-123"}
	auth := &oidc{
		flow: "flow", remote: authenticationTestRemote("requested-target"), identity: identity,
		idToken: OidcIdToken{IDToken: &coidc.IDToken{Issuer: identity.Issuer, Subject: identity.Subject}},
		userInfo: OidcUserInfo{UserInfo: &coidc.UserInfo{
			Subject: identity.Subject, Email: "alice@example.invalid", EmailVerified: true,
		}},
	}
	// Model already decoded, verified artifacts in the production wrappers. This
	// deliberately needs no JWT, provider, UserInfo request or live account.
	auth.idToken.init.Do(func() {
		auth.idToken.claims = map[string]any{"iss": identity.Issuer, "sub": identity.Subject}
	})
	auth.userInfo.init.Do(func() {
		auth.userInfo.claims = map[string]any{
			"sub": identity.Subject, "email": auth.userInfo.Email, "email_verified": true,
			"preferred_username": "alice", "groups": []any{"operations"},
		}
	})
	return auth
}

func TestAuthenticationWithPrincipalUsesProductionOidcContexts(t *testing.T) {
	for _, test := range []struct{ name, mapping, principal string }{
		{"default principal", "", "subject-123"},
		{"constant mapping", "mapped-user", "mapped-user"},
		{"default principal without recursion", "{{ .authentication.principal }}@example.org", "subject-123@example.org"},
		{"verified issuer", "{{ .authentication.issuer }}", "https://issuer.example"},
		{"ID token subject", "{{ .authorization.idToken.subject }}", "subject-123"},
		{"UserInfo email", "{{ .authorization.userInfo.email }}", "alice@example.invalid"},
		{"UserInfo custom claim", "{{ .authorization.userInfo.preferred_username }}", "alice"},
		{"UserInfo groups", `{{ if has "operations" .authorization.userInfo.groups }}operations-user{{ else }}other-user{{ end }}`, "operations-user"},
		{"UserInfo boolean", `{{ if .authorization.userInfo.emailVerified }}verified{{ else }}unverified{{ end }}`, "verified"},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := newPrincipalMappingTestOidc()
			original := auth.identity
			calls := 0
			identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(test.mapping), func(unmapped authentication.Identity) PrincipalMappingContext {
				calls++
				require.Equal(t, original, unmapped)
				return newPrincipalMappingTestContext(t, unmapped, auth)
			})
			require.NoError(t, err)
			require.Equal(t, test.principal, identity.Principal)
			require.Equal(t, original.Issuer, identity.Issuer)
			require.Equal(t, original.Subject, identity.Subject)
			require.Equal(t, original, auth.identity, "mapping must not mutate the verified source identity")
			require.Equal(t, "requested-target", auth.Remote().User())
			if test.mapping == "" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}

func TestAuthenticationWithPrincipalRejectsInvalidMappings(t *testing.T) {
	for _, mapping := range []string{
		"{{ .authorization.missing }}", "{{ .missing }}", "{{ .authorization.userInfo.missing }}",
		`{{ "" }}`, `{{ "\n" }}`, `{{ "   " }}`, strings.Repeat("x", 1025),
	} {
		t.Run(mapping, func(t *testing.T) {
			auth := newPrincipalMappingTestOidc()
			original := auth.identity
			identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(mapping), func(unmapped authentication.Identity) PrincipalMappingContext {
				return newPrincipalMappingTestContext(t, unmapped, auth)
			})
			require.Error(t, err)
			require.True(t, berrors.Config.IsErr(err))
			require.Equal(t, authentication.Identity{}, identity, "an invalid mapping must not fall back to the original identity")
			require.Equal(t, original, auth.identity)
		})
	}
}

func TestAuthenticationWithPrincipalIsolatesConcurrentContexts(t *testing.T) {
	auth := newPrincipalMappingTestOidc()
	flows := principalMappingTestFlows("{{ .authentication.principal }}-{{ .marker }}")
	for index := range 16 {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			t.Parallel()
			identity, err := AuthenticationWithPrincipal(auth, flows, func(unmapped authentication.Identity) PrincipalMappingContext {
				ctx := newPrincipalMappingTestContext(t, unmapped, auth)
				ctx.marker = t.Name()
				return ctx
			})
			require.NoError(t, err)
			require.Equal(t, "subject-123-"+t.Name(), identity.Principal)
			require.Equal(t, "subject-123", auth.identity.Principal)
		})
	}
}

func TestAuthenticationWithPrincipalDoesNotInventOidcArtifacts(t *testing.T) {
	for _, test := range []struct {
		name    string
		mapping string
		clear   func(*oidc)
	}{
		{"missing UserInfo", "{{ .authorization.userInfo.email }}", func(auth *oidc) { auth.userInfo = OidcUserInfo{} }},
		{"missing ID token", "{{ .authorization.idToken.subject }}", func(auth *oidc) { auth.idToken = OidcIdToken{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := newPrincipalMappingTestOidc()
			test.clear(auth)
			identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(test.mapping), func(unmapped authentication.Identity) PrincipalMappingContext {
				return newPrincipalMappingTestContext(t, unmapped, auth)
			})
			require.Error(t, err)
			require.Equal(t, authentication.Identity{}, identity)
		})
	}
}

func TestAuthenticationWithPrincipalWithoutMappingDoesNotBuildContext(t *testing.T) {
	auth := newPrincipalMappingTestOidc()
	for _, flows := range []configuration.Flows{nil, {}, {{Name: "other", Authorization: configuration.Authorization{Principal: template.MustNewString("other-user")}}}, principalMappingTestFlows("")} {
		identity, err := AuthenticationWithPrincipal(auth, flows, func(authentication.Identity) PrincipalMappingContext {
			panic("a missing or inapplicable mapping must not request a context")
		})
		require.NoError(t, err)
		require.Equal(t, auth.identity, identity)
	}
	identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(""), nil)
	require.NoError(t, err)
	require.Equal(t, auth.identity, identity)
}

func TestAuthenticationWithPrincipalRejectsUnavailableContexts(t *testing.T) {
	auth := newPrincipalMappingTestOidc()
	for _, contextFor := range []func(authentication.Identity) PrincipalMappingContext{
		nil,
		func(authentication.Identity) PrincipalMappingContext { return nil },
		func(authentication.Identity) PrincipalMappingContext { return (*principalMappingTestContext)(nil) },
	} {
		identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows("mapped-user"), contextFor)
		require.ErrorIs(t, err, ErrPrincipalMappingContextUnavailable)
		require.True(t, berrors.System.IsErr(err))
		require.Equal(t, authentication.Identity{}, identity)
	}
}

func TestAuthenticationWithPrincipalDoesNotAuthenticateAnonymousRequests(t *testing.T) {
	for _, auth := range []Authorization{nil, Forbidden(authenticationTestRemote("requested-admin")), &none{flow: "flow", remote: authenticationTestRemote("requested-admin")}} {
		identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(""), nil)
		require.NoError(t, err)
		require.Equal(t, authentication.Anonymous(), identity)
	}
	identity, err := AuthenticationWithPrincipal(&none{flow: "flow"}, principalMappingTestFlows("admin"), func(authentication.Identity) PrincipalMappingContext {
		panic("anonymous identities must be rejected before evaluating a mapping")
	})
	require.ErrorContains(t, err, "cannot map an anonymous authentication principal")
	require.True(t, berrors.Config.IsErr(err))
	require.Equal(t, authentication.Identity{}, identity)
}

type principalMappingFailingAuthorization struct {
	Authorization
	identity authentication.Identity
	err      error
}

func (principalMappingFailingAuthorization) IsAuthorized() bool { return true }
func (this principalMappingFailingAuthorization) Authentication() (authentication.Identity, error) {
	return this.identity, this.err
}

func TestAuthenticationWithPrincipalPreservesIdentityErrors(t *testing.T) {
	providerErr := errors.New("identity unavailable")
	for _, test := range []struct {
		name string
		auth Authorization
		err  error
	}{
		{"missing identity provider", unknownAuthenticationAuthorization{}, ErrAuthenticationUnavailable},
		{"provider error", principalMappingFailingAuthorization{err: providerErr}, providerErr},
		{"invalid identity", principalMappingFailingAuthorization{identity: authentication.Identity{Principal: "unverified-user"}}, ErrAuthenticationUnavailable},
		{"unverified OIDC identity", &oidc{flow: "flow"}, ErrAuthenticationUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity, err := AuthenticationWithPrincipal(test.auth, principalMappingTestFlows("admin"), func(authentication.Identity) PrincipalMappingContext {
				panic("identity errors must not be hidden by principal mapping")
			})
			require.ErrorIs(t, err, test.err)
			require.Equal(t, authentication.Identity{}, identity)
		})
	}
}
