//go:build unix

package environment

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestAssumedLocalAuthenticationAndTargetAccountsRemainSeparate(t *testing.T) {
	actorUID, targetUID := user.Id(0), user.Id(2000)
	actor, err := user.NewSnapshot(user.AccountFacts{Name: "actor", Uid: &actorUID})
	require.NoError(t, err)
	authenticationAccounts, err := user.NewMemoryLookup(user.AccountLookupFacts{Accounts: []*user.Snapshot{actor}})
	require.NoError(t, err)
	flow := &configuration.Flow{Name: "flow", Authorization: configuration.Authorization{V: &configuration.AuthorizationLocal{}}}
	bound, err := authorization.BindAssumedLocalUnixAuthentication(t.Context(), flow, "actor", authenticationAccounts)
	require.NoError(t, err)
	identity, err := bound.Authentication()
	require.NoError(t, err)
	ctx := targetTestContext{ctx: t.Context(), principal: identity.Principal}

	targetAccount, err := user.NewSnapshot(user.AccountFacts{Name: "target", Uid: &targetUID})
	require.NoError(t, err)
	environmentAccounts, err := user.NewMemoryLookup(user.AccountLookupFacts{Accounts: []*user.Snapshot{targetAccount}})
	require.NoError(t, err)
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.User.Name = template.MustNewString("target")
	projection, err := ProjectLocalUnixTarget(ctx, conf, environmentAccounts)
	require.NoError(t, err)
	raw, found := projection.Field("account")
	require.True(t, found)
	var selector user.Requirement
	require.NoError(t, json.Unmarshal([]byte(raw.(string)), &selector))
	require.Equal(t, "target", selector.Name)
	require.Nil(t, selector.Uid)
	require.Equal(t, "actor", identity.Principal)
	require.Equal(t, "0", identity.Subject)

	conf.User.Name = template.MustNewString(`{{ .authentication.principal }}`)
	projection, err = ProjectLocalUnixTarget(ctx, conf, environmentAccounts)
	require.ErrorIs(t, err, user.ErrAccountNotModeled, "authentication facts must not become a fallback environment inventory")
	require.Equal(t, TargetProjection{}, projection)
	_, err = authorization.BindAssumedLocalUnixAuthentication(t.Context(), flow, "target", authenticationAccounts)
	require.ErrorIs(t, err, user.ErrAccountNotModeled, "a target account is not an assumed authenticated actor")
}
