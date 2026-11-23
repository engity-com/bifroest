//go:build unix

package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/user"
)

func characterizationManagementContext(group string) *environmentContext {
	return &environmentContext{
		service: &service{Service: &Service{Configuration: configuration.Configuration{Flows: configuration.Flows{{
			Name: "flow", Environment: configuration.Environment{V: &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{ManagedGroup: group}}},
		}}}}}, authorization: localManagedServiceAuthorization{flow: "flow"},
	}
}

func TestPolicyRegressionServiceUnixManagement(t *testing.T) {
	for _, test := range []struct {
		label   string
		primary user.Group
		groups  user.Groups
		managed bool
	}{
		{"primary", user.Group{Name: "managed", Gid: 2}, nil, true},
		{"supplementary", user.Group{Name: "users", Gid: 2}, user.Groups{{Name: "other", Gid: 2}, {Name: "managed", Gid: 99}}, true},
		{"GID is not name", user.Group{Name: "other", Gid: 2}, nil, false},
		{"case sensitive", user.Group{Name: "Managed"}, user.Groups{{Name: "MANAGED"}}, false},
		{"known empty", user.Group{Name: "users"}, user.Groups{}, false},
	} {
		t.Run(test.label, func(t *testing.T) {
			managed, available, err := characterizationManagementContext("managed").ResolveLocalUserManaged("flow", &user.User{Group: test.primary, Groups: test.groups})
			require.NoError(t, err)
			require.True(t, available)
			require.Equal(t, test.managed, managed)
		})
	}
	for _, change := range []func(*environmentContext){
		func(c *environmentContext) { c.service = nil },
		func(c *environmentContext) { c.service.Service = nil },
		func(c *environmentContext) { c.authorization = nil },
		func(c *environmentContext) { c.authorization = localManagedServiceAuthorization{flow: "other"} },
		func(c *environmentContext) { c.service.Configuration.Flows[0].Name = "other" },
		func(c *environmentContext) {
			c.service.Configuration.Flows[0].Environment.V = &configuration.EnvironmentSsh{}
		},
		func(c *environmentContext) {
			c.service.Configuration.Flows[0].Environment.V.(*configuration.EnvironmentLocal).ManagedGroup = ""
		},
	} {
		ctx := characterizationManagementContext("managed")
		change(ctx)
		managed, available, err := ctx.ResolveLocalUserManaged("flow", &user.User{})
		require.NoError(t, err)
		require.False(t, managed)
		require.False(t, available)
	}
}

func TestPolicyRegressionServiceTypedNilEnvironmentHasNoManagementCapability(t *testing.T) {
	ctx := characterizationManagementContext("managed")
	ctx.service.Configuration.Flows[0].Environment.V = (*configuration.EnvironmentLocal)(nil)
	account := &user.User{Name: "fixture", Uid: 1234}
	managed, available, err := ctx.ResolveLocalUserManaged("flow", account)
	require.NoError(t, err)
	require.False(t, available, "a nil environment does not supply management evidence")
	require.False(t, managed)
	// TestPolicyRegressionUnixLocalIdentityAndManagementView separately verifies
	// that the production authorization overlay maps available=false to a
	// present nil field, not a known false membership observation.
}
