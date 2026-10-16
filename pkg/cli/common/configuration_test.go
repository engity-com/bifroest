package common

import (
	"context"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
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

	_, err = ResolveConfiguration(t.Context(), ExecutableConfigurationOpts{})
	require.ErrorContains(t, err, "local configuration requires the executable profile")
}

func TestResolveConfigurationRemoteProfileDoesNotLoadLocalDefaults(t *testing.T) {
	var options ExecutableConfigurationOpts
	var resolved *configuration.Configuration
	app := cli.NewSimpleApplication("test").
		WithErrorHandlerEnabled(false).
		WithCommand(cli.NewSimpleCommand("resolve").
			WithProfiles(ProfileRemote).
			WithHandler(func(ctx context.Context, _ cli.NoOptions) error {
				var err error
				resolved, err = ResolveConfiguration(ctx, options)
				return err
			})).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	remote := &cli.ParseOpts{Profiles: []string{ProfileRemote}}
	require.NoError(t, app.ParseAndExecute(t.Context(), remote, "resolve"))
	require.Nil(t, resolved)
	options.Configuration = &configuration.Configuration{}
	require.NoError(t, app.ParseAndExecute(t.Context(), remote, "resolve"))
	require.Same(t, options.Configuration, resolved)
}
