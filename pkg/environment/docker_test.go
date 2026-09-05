package environment

import (
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/imp"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func TestDockerResolveImpBindingUsesConfiguredPublishHost(t *testing.T) {
	repository := &DockerRepository{
		conf: &configuration.EnvironmentDocker{
			ImpPublishHost: bnet.MustNewHost("127.0.0.1"),
		},
	}
	environment := docker{repository: repository}
	container := &types.Container{
		Ports: []types.Port{{
			IP:          "0.0.0.0",
			PrivatePort: imp.ServicePort,
			PublicPort:  44807,
			Type:        "tcp",
		}},
	}

	actual, err := environment.resolveImpBinding(container)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", actual.Host.String())
	require.Equal(t, uint16(44807), actual.Port)
}
