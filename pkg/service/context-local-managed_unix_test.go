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

// Compatibility cases checked against the original service implementation
// before sharing its name-based membership decision with controlled account views.
func TestLocalUserManagedCompatibilityVectors(t *testing.T) {
	ctx := &environmentContext{
		service: &service{Service: &Service{Configuration: configuration.Configuration{Flows: configuration.Flows{{
			Name: "flow", Environment: configuration.Environment{V: &configuration.EnvironmentLocal{
				EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{ManagedGroup: "managed"},
			}},
		}}}}}, authorization: localManagedServiceAuthorization{flow: "flow"},
	}
	for _, test := range []struct {
		label   string
		primary user.Group
		groups  user.Groups
		managed bool
	}{
		{"primary group", user.Group{Name: "managed", Gid: 1}, nil, true},
		{"supplementary group", user.Group{Name: "users", Gid: 1}, user.Groups{{Name: "managed", Gid: 2}}, true},
		{"name takes precedence over GID", user.Group{Name: "users", Gid: 2}, user.Groups{{Name: "other", Gid: 2}, {Name: "managed", Gid: 99}}, true},
		{"matching GID is not matching name", user.Group{Name: "other", Gid: 2}, nil, false},
		{"case sensitive", user.Group{Name: "Managed"}, user.Groups{{Name: "MANAGED"}}, false},
		{"known empty groups", user.Group{Name: "users"}, user.Groups{}, false},
	} {
		t.Run(test.label, func(t *testing.T) {
			managed, available, err := ctx.ResolveLocalUserManaged("flow", &user.User{Group: test.primary, Groups: test.groups})
			require.NoError(t, err)
			require.True(t, available)
			require.Equal(t, test.managed, managed)
		})
	}
}
