package environment

import (
	"context"
	gonet "net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/imp"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func TestWaitForDockerImpRetriesConnectionRefused(t *testing.T) {
	attempts := 0
	err := waitForDockerImp(context.Background(), log.GetLogger("test"), time.Second, 0, func(context.Context) error {
		attempts++
		if attempts == 1 {
			return &gonet.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: syscall.ECONNREFUSED,
			}
		}
		return nil
	})

	require.NoError(t, err)
	require.Equal(t, 2, attempts)
}

func TestWaitForDockerImpRetriesConnectionReset(t *testing.T) {
	attempts := 0
	err := waitForDockerImp(context.Background(), log.GetLogger("test"), time.Second, 0, func(context.Context) error {
		attempts++
		if attempts == 1 {
			return &gonet.OpError{
				Op:  "read",
				Net: "tcp",
				Err: syscall.ECONNRESET,
			}
		}
		return nil
	})

	require.NoError(t, err)
	require.Equal(t, 2, attempts)
}

func TestWaitForDockerImpStopsAtReadinessTimeout(t *testing.T) {
	const timeout = 20 * time.Millisecond
	started := time.Now()
	err := waitForDockerImp(context.Background(), log.GetLogger("test"), timeout, time.Hour, func(context.Context) error {
		return &gonet.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: syscall.ECONNREFUSED,
		}
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, "last error: dial tcp: connection refused")
	require.Less(t, time.Since(started), time.Second)
}

func TestWaitForDockerImpCancelsInFlightPingAtReadinessTimeout(t *testing.T) {
	const timeout = 20 * time.Millisecond
	started := time.Now()
	err := waitForDockerImp(context.Background(), log.GetLogger("test"), timeout, time.Hour, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
}

func TestDockerResolveImpBindingUsesConfiguredPublishHost(t *testing.T) {
	repository := &DockerRepository{
		conf: &configuration.EnvironmentDocker{
			ImpPublishHost: bnet.MustNewHost("127.0.0.1"),
		},
	}
	environment := docker{repository: repository}
	container := &container.Summary{
		Ports: []container.PortSummary{{
			IP:          netip.MustParseAddr("0.0.0.0"),
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

func TestDockerResolveImpBindingUsesContainerNetworkWithoutPublishHost(t *testing.T) {
	repository := &DockerRepository{conf: &configuration.EnvironmentDocker{}}
	environment := docker{repository: repository}
	container := &container.Summary{
		NetworkSettings: &container.NetworkSettingsSummary{
			Networks: map[string]*network.EndpointSettings{
				"bridge": {IPAddress: netip.MustParseAddr("172.18.0.4")},
			},
		},
		Ports: []container.PortSummary{{
			PrivatePort: imp.ServicePort,
			PublicPort:  44807,
			Type:        "tcp",
		}},
	}

	actual, err := environment.resolveImpBinding(container)
	require.NoError(t, err)
	require.Equal(t, "172.18.0.4", actual.Host.String())
	require.Equal(t, uint16(imp.ServicePort), actual.Port)
}

func TestDockerResolveImpBindingRequiresPublishedPortForPublishHost(t *testing.T) {
	repository := &DockerRepository{
		conf: &configuration.EnvironmentDocker{
			ImpPublishHost: bnet.MustNewHost("host.docker.internal"),
		},
	}
	environment := docker{repository: repository}
	container := &container.Summary{
		NetworkSettings: &container.NetworkSettingsSummary{
			Networks: map[string]*network.EndpointSettings{
				"bridge": {IPAddress: netip.MustParseAddr("172.18.0.4")},
			},
		},
	}

	_, err := environment.resolveImpBinding(container)
	require.ErrorContains(t, err, "does not have any valid exposed port")
}

func TestDockerImpPortBindingLetsDaemonChooseHostInterfaceAndPort(t *testing.T) {
	bindings := dockerImpPortBindings()
	port := bindings[network.MustParsePort("8683/tcp")]

	require.Len(t, bindings, 1)
	require.Len(t, port, 1)
	require.False(t, port[0].HostIP.IsValid())
	require.Empty(t, port[0].HostPort)
}
