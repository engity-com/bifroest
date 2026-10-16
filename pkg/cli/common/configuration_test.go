package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

func TestResolveConfigurationSelectsInvocationSource(t *testing.T) {
	local := &configuration.Configuration{}
	server := &configuration.Configuration{}
	options := ExecutableConfigurationOpts{Configuration: local}

	resolved, err := ResolveConfiguration(t.Context(), options)
	require.NoError(t, err)
	require.Same(t, local, resolved)

	ctx := ContextWithManagementAccess(t.Context(), ManagementAccess{Configuration: server})
	resolved, err = ResolveConfiguration(ctx, options)
	require.NoError(t, err)
	require.Same(t, server, resolved)

	ctx = ContextWithManagementAccess(t.Context(), ManagementAccess{})
	_, err = ResolveConfiguration(ctx, options)
	require.ErrorContains(t, err, "management configuration is unavailable")

	ctx = ContextWithRemoteTarget(t.Context(), management.Target{Host: "example.invalid"})
	resolved, err = ResolveConfiguration(ctx, ExecutableConfigurationOpts{})
	require.NoError(t, err)
	require.Nil(t, resolved)
	resolved, err = ResolveConfiguration(ctx, options)
	require.NoError(t, err)
	require.Same(t, local, resolved)
}
