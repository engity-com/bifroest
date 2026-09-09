package environment

import (
	"context"
	gonet "net"
	"syscall"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	log "github.com/echocat/slf4g"
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

func TestDockerImpPortBindingLetsDaemonChooseHostInterfaceAndPort(t *testing.T) {
	bindings := dockerImpPortBindings()
	port := bindings["8683/tcp"]

	require.Len(t, bindings, 1)
	require.Len(t, port, 1)
	require.Empty(t, port[0].HostIP)
	require.Empty(t, port[0].HostPort)
}
