package environment

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
)

type managementTestRunner struct{}

func (managementTestRunner) RunManagementCommand(Task, bool) (int, error) { return 0, nil }

func TestManagementEnvironmentRejectsNonCommandAccess(t *testing.T) {
	_, err := NewManagementRepository(context.Background(), "admin", &configuration.EnvironmentManagement{}, nil, nil)
	require.ErrorContains(t, err, "requires a service command runner")

	ctx := context.WithValue(context.Background(), repositoryDependenciesContextKey{}, repositoryDependencies{management: managementTestRunner{}})
	repository, err := NewManagementRepository(ctx, "admin", &configuration.EnvironmentManagement{}, nil, nil)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	instance := &managementEnvironment{repository: repository}
	allowed, err := instance.IsPortForwardingAllowed(net.HostPort{})
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = instance.IsReversePortForwardingAllowed(net.HostPort{})
	require.NoError(t, err)
	require.False(t, allowed)
	_, err = instance.NewDestinationConnection(ctx, net.HostPort{})
	require.ErrorContains(t, err, "does not support port forwarding")
	_, err = instance.RunSubsystem(nil, nil)
	require.ErrorIs(t, err, ErrSubsystemNotAllowed)
}
