package service

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestPolicyRegressionServicePrincipalIdentityAndFlowSelection(t *testing.T) {
	for _, test := range []struct{ label, mapping, principal string }{
		{"unmapped", "", "verified-user"},
		{"constant", "mapped", "mapped"},
		{"nonrecursive identity", `{{ .authentication.principal }}-mapped`, "verified-user-mapped"},
		{"authorization data", `{{ .authorization.entry.name }}`, "canonical-entry"},
		{"issuer and subject", `{{ .authentication.issuer }}:{{ .authentication.subject }}`, "issuer:subject"},
		{"request name remains independent", `{{ .remote.user }}`, "requested-target"},
	} {
		t.Run(test.label, func(t *testing.T) {
			ctx := newPrincipalTestContext(test.mapping)
			identity, err := ctx.Authentication()
			require.NoError(t, err)
			require.Equal(t, authentication.Identity{Principal: test.principal, Issuer: "issuer", Subject: "subject"}, identity)
			original, err := authorization.AuthenticationOf(ctx.authorization)
			require.NoError(t, err)
			require.Equal(t, "verified-user", original.Principal)
			require.Equal(t, "requested-target", ctx.connection.Remote().User())
		})
	}
	ctx := newPrincipalTestContext("mapped")
	ctx.service.Configuration.Flows = configuration.Flows{
		{Name: "other", Authorization: configuration.Authorization{Principal: template.MustNewString(`{{ fail "must not evaluate another flow" }}`)}},
		{Name: "flow"}, {Name: "flow", Authorization: configuration.Authorization{Principal: template.MustNewString("second-mapping")}},
	}
	identity, err := ctx.Authentication()
	require.NoError(t, err)
	require.Equal(t, "second-mapping", identity.Principal)
	for _, change := range []func(*environmentContext){
		func(c *environmentContext) { c.service = nil },
		func(c *environmentContext) { c.service = &service{} },
		func(c *environmentContext) { c.service.Configuration.Flows[0].Name = "other" },
	} {
		ctx := newPrincipalTestContext(`{{ fail "must not map" }}`)
		change(ctx)
		identity, err := ctx.Authentication()
		require.NoError(t, err)
		require.Equal(t, "verified-user", identity.Principal)
	}
}

func TestPolicyRegressionServicePrincipalFailuresAreConfigurationErrors(t *testing.T) {
	for _, mapping := range []string{`{{ .authorization.missing }}`, `{{ "" }}`, `{{ "\n" }}`, `{{ "   " }}`, strings.Repeat("x", 1025)} {
		t.Run(mapping, func(t *testing.T) {
			identity, err := newPrincipalTestContext(mapping).Authentication()
			require.Error(t, err)
			require.Equal(t, authentication.Identity{}, identity)
			require.True(t, berrors.Config.IsErr(err))
		})
	}
	ctx := newPrincipalTestContext("mapped")
	ctx.authorization = principalTestAuthorization{identity: authentication.Anonymous()}
	_, err := ctx.Authentication()
	require.EqualError(t, err, "cannot map an anonymous authentication principal")
	require.True(t, berrors.Config.IsErr(err))
}

type characterizationSession struct{ session.Session }

func TestPolicyRegressionAssociationContextsPreserveDataAndDeadlines(t *testing.T) {
	t.Setenv("BIFROEST_CHARACTERIZATION_ASSOCIATION", "host")
	base := associationAdapter(t, "requested", "ssh")
	bounded, cancel := context.WithCancel(t.Context())
	defer cancel()
	candidate := &characterizationSession{}
	ctx := &associationCandidateContext{associationBaseContext: base, ctx: bounded, auth: base.auth, session: candidate}
	require.Same(t, bounded, ctx.Context())
	require.Equal(t, base.auth, ctx.Authorization())
	value, present, err := ctx.GetField("session")
	require.NoError(t, err)
	require.True(t, present)
	require.Same(t, candidate, value)
	for _, render := range []any{ctx, newAssociationTargetContext(bounded, base, session.Reference{Flow: "work"})} {
		value, err := template.MustNewString(`{{ .authentication.principal }}:{{ .remote.user }}:{{ env "BIFROEST_CHARACTERIZATION_ASSOCIATION" }}`).Render(render)
		require.NoError(t, err)
		require.Equal(t, "alice:requested:host", value)
	}
	target := newAssociationTargetContext(bounded, base, session.Reference{Flow: "work"})
	value, present, err = target.GetField("session")
	require.NoError(t, err)
	require.True(t, present)
	reference := value.(associationTargetReference)
	flow, _, err := reference.GetField("flow")
	require.NoError(t, err)
	require.Equal(t, configuration.FlowName("work"), flow)
	_, _, err = reference.GetField("created")
	require.ErrorContains(t, err, "creation metadata unavailable")
	_, _, err = reference.GetField("mutable")
	require.ErrorContains(t, err, "immutable session fields")
	cancel()
	require.ErrorIs(t, ctx.Context().Err(), context.Canceled)
	require.ErrorIs(t, target.Context().Err(), context.Canceled)
}
