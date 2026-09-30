//go:build unix

package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/user"
)

type localManagedServiceAuthorization struct {
	authorization.Authorization
	flow configuration.FlowName
}

func (this localManagedServiceAuthorization) Flow() configuration.FlowName { return this.flow }

func TestEnvironmentContextResolvesLocalUserManagedForCurrentFlow(t *testing.T) {
	flow := configuration.FlowName("local")
	ctx := &environmentContext{
		service: &service{Service: &Service{Configuration: configuration.Configuration{Flows: configuration.Flows{{
			Name: flow, Environment: configuration.Environment{V: &configuration.EnvironmentLocal{
				EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{ManagedGroup: "bifroest-managed"},
			}},
		}}}}},
		authorization: localManagedServiceAuthorization{flow: flow},
	}
	account := &user.User{Name: "alice", Group: user.Group{Name: "users"}, Groups: user.Groups{{Name: "bifroest-managed"}}}
	managed, available, err := ctx.ResolveLocalUserManaged(flow, account)
	require.NoError(t, err)
	require.True(t, available)
	require.True(t, managed)
	account.Groups = nil
	managed, available, err = ctx.ResolveLocalUserManaged(flow, account)
	require.NoError(t, err)
	require.True(t, available)
	require.False(t, managed)
	_, available, err = ctx.ResolveLocalUserManaged("other", account)
	require.NoError(t, err)
	require.False(t, available)
}
