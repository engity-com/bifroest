package service

import (
	"context"
	"fmt"
	"testing"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/template"
)

type principalTestAuthorization struct {
	authorization.Authorization
	identity authentication.Identity
}

func (principalTestAuthorization) IsAuthorized() bool           { return true }
func (principalTestAuthorization) Flow() configuration.FlowName { return "flow" }
func (this principalTestAuthorization) Authentication() (authentication.Identity, error) {
	return this.identity, nil
}
func (principalTestAuthorization) GetField(name string, ctx authorization.ContextEnabled) (any, bool, error) {
	switch name {
	case "entry":
		return map[string]any{"name": "canonical-entry"}, true, nil
	case "contextValue":
		return ctx.Context().Value(principalTestContextKey{}), true, nil
	case "requestingName":
		request, ok := ctx.(bconn.Context)
		if !ok {
			return nil, false, fmt.Errorf("request context capability is unavailable")
		}
		return request.Connection().Remote().User(), true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

type principalTestContextKey struct{}

type principalTestSshContext struct{ essh.Context }

func (principalTestSshContext) User() string { return "requested-target" }

func newPrincipalTestContext(mapping string) *environmentContext {
	return &environmentContext{
		service: &service{Service: &Service{Configuration: configuration.Configuration{Flows: configuration.Flows{{
			Name: "flow", Authorization: configuration.Authorization{Principal: template.MustNewString(mapping)},
		}}}}},
		connection:       &connection{context: principalTestSshContext{}},
		authorization:    principalTestAuthorization{identity: authentication.Identity{Principal: "verified-user", Issuer: "issuer", Subject: "subject"}},
		executionContext: context.Background(),
	}
}

func TestAuthenticationPrincipalTemplateAndMapping(t *testing.T) {
	for _, test := range []struct{ mapping, principal string }{
		{"", "verified-user"},
		{"{{ .authorization.entry.name }}", "canonical-entry"},
		{"{{ .authentication.principal }}@example.org", "verified-user@example.org"},
	} {
		t.Run(test.mapping, func(t *testing.T) {
			ctx := newPrincipalTestContext(test.mapping)
			actual, err := template.MustNewString("{{ .authentication.principal }}|{{ .authentication.issuer }}|{{ .authentication.subject }}|{{ .remote.user }}").Render(ctx)
			require.NoError(t, err)
			require.Equal(t, test.principal+"|issuer|subject|requested-target", actual)
			require.Equal(t, "requested-target", ctx.connection.Remote().User())
		})
	}
}

func TestAuthenticationPrincipalInvalidMappingDoesNotFallBack(t *testing.T) {
	for _, mapping := range []string{"{{ .authorization.missing }}", `{{ "" }}`, `{{ "\n" }}`} {
		ctx := newPrincipalTestContext(mapping)
		_, err := template.MustNewString("{{ .authentication.principal }}").Render(ctx)
		require.Error(t, err)
	}
}

func TestAnonymousPrincipalIsNotMappedIntoAuthenticatedIdentity(t *testing.T) {
	ctx := newPrincipalTestContext("")
	ctx.authorization = principalTestAuthorization{identity: authentication.Anonymous()}
	identity, err := ctx.Authentication()
	require.NoError(t, err)
	require.Equal(t, authentication.AnonymousPrincipal, identity.Principal)
	require.False(t, identity.IsAuthenticated())
	ctx.service.Configuration.Flows[0].Authorization.Principal = template.MustNewString("admin")
	_, err = ctx.Authentication()
	require.Error(t, err)
}

func TestAuthenticationContextAvailableDuringEnvironmentValidation(t *testing.T) {
	ctx := newPrincipalTestContext("{{ .authentication.principal }}@example.org")
	request := authorizeRequest{service: ctx.service, connection: ctx.connection}
	request.SetAuthorizationContext(ctx.authorization)
	actual, err := template.MustNewString("{{ .authentication.principal }}").Render(&request)
	require.NoError(t, err)
	require.Equal(t, "verified-user@example.org", actual)
	wrapped := &sessionCompatibilityAuthorization{Authorization: ctx.authorization}
	identity, err := authorization.AuthenticationOf(wrapped)
	require.NoError(t, err)
	require.Equal(t, "verified-user", identity.Principal)
}

func TestAuthenticationContextAvailableInRememberMeNotification(t *testing.T) {
	ctx := newPrincipalTestContext("{{ .authentication.principal }}@example.org")
	notification := newRememberMeNotificationContext(principalTestSshContext{}, ctx.authorization, false, nil)
	notification.authentication = ctx.Authentication
	actual, err := template.MustNewString("{{ .authentication.principal }}").Render(notification)
	require.NoError(t, err)
	require.Equal(t, "verified-user@example.org", actual)
}

func TestAuthenticationPrincipalPreservesConcreteRequestContext(t *testing.T) {
	ctx := newPrincipalTestContext("{{ .authorization.contextValue }}|{{ .authorization.requestingName }}|{{ .authentication.principal }}")
	ctx.executionContext = context.WithValue(t.Context(), principalTestContextKey{}, "request-marker")
	identity, err := ctx.Authentication()
	require.NoError(t, err)
	require.Equal(t, authentication.Identity{
		Principal: "request-marker|requested-target|verified-user", Issuer: "issuer", Subject: "subject",
	}, identity)
	base, err := authorization.AuthenticationOf(ctx.authorization)
	require.NoError(t, err)
	require.Equal(t, "verified-user", base.Principal)
}

func TestAuthenticationPrincipalWithoutServiceUsesVerifiedIdentity(t *testing.T) {
	for _, service := range []*service{nil, {}} {
		ctx := newPrincipalTestContext("must-not-be-used")
		ctx.service = service
		identity, err := ctx.Authentication()
		require.NoError(t, err)
		require.Equal(t, authentication.Identity{Principal: "verified-user", Issuer: "issuer", Subject: "subject"}, identity)
	}
	ctx := newPrincipalTestContext("must-not-be-used")
	ctx.authorization = nil
	identity, err := ctx.Authentication()
	require.NoError(t, err)
	require.Equal(t, authentication.Anonymous(), identity)
}
