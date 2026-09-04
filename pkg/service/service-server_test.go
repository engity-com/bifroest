package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestPrepareServerAppliesSshLifecycleAndLimits(t *testing.T) {
	var conf configuration.Configuration
	require.NoError(t, conf.Ssh.SetDefaults())
	svc := &service{Service: &Service{Configuration: conf}}

	require.NoError(t, svc.Service.prepareServer(context.Background(), svc, nil))

	server := &svc.server
	require.True(t, server.RequireHostSigners)
	require.True(t, server.RequireClientAuth)
	require.Equal(t, conf.Ssh.HandshakeTimeout.Native(), *server.HandshakeTimeout)
	require.Zero(t, *server.IdleTimeout)
	require.Zero(t, *server.MaxTimeout)
	require.Equal(t, conf.Ssh.SessionRequestTimeout.Native(), *server.SessionRequestTimeout)
	require.Equal(t, int(conf.Ssh.MaxStartupsStart), server.MaxStartups.Start)
	require.Equal(t, int(conf.Ssh.MaxStartupsRate), server.MaxStartups.Rate)
	require.Equal(t, int(conf.Ssh.MaxStartupsFull), server.MaxStartups.Full)
	require.Equal(t, int(conf.Ssh.MaxSessionsPerConnection), *server.MaxSessionsPerConnection)
	require.Equal(t, int(conf.Ssh.MaxChannelsPerConnection), *server.MaxChannelsPerConnection)
	require.Equal(t, int(conf.Ssh.MaxReverseForwardsPerConnection), *server.MaxReverseForwardsPerConnection)
	require.Zero(t, *server.MaxConnections, "Bifroest enforces its global pre-authentication connection limit")
	require.Equal(t, int(conf.Ssh.MaxChannels), *server.MaxChannels)
	require.Equal(t, int(conf.Ssh.MaxReverseForwards), *server.MaxReverseForwards)
	require.NotNil(t, server.GracefulShutdownHandler)
	require.NotNil(t, server.AgentForwardingCallback)
	require.NotNil(t, server.ConnectionFailedCallback)
	require.NotNil(t, server.DisconnectCallback)
	require.Nil(t, server.ProxyProtocol)

	gracePeriod, err := server.GracefulShutdownHandler(context.Background())
	require.NoError(t, err)
	require.Equal(t, conf.Ssh.GracefulShutdownTimeout.Native(), gracePeriod)
}

func TestPrepareServerPreservesExplicitlyDisabledLimits(t *testing.T) {
	var conf configuration.Configuration
	require.NoError(t, conf.Ssh.SetDefaults())
	require.NoError(t, conf.Ssh.GracefulShutdownTimeout.Set("0"))
	require.NoError(t, conf.Ssh.HandshakeTimeout.Set("0"))
	require.NoError(t, conf.Ssh.SessionRequestTimeout.Set("0"))
	conf.Ssh.MaxStartupsFull = 0
	conf.Ssh.MaxSessionsPerConnection = 0
	conf.Ssh.MaxChannelsPerConnection = 0
	conf.Ssh.MaxReverseForwardsPerConnection = 0
	conf.Ssh.MaxChannels = 0
	conf.Ssh.MaxReverseForwards = 0
	svc := &service{Service: &Service{Configuration: conf}}

	require.NoError(t, svc.Service.prepareServer(context.Background(), svc, nil))

	server := &svc.server
	require.Zero(t, *server.HandshakeTimeout)
	require.Zero(t, *server.SessionRequestTimeout)
	require.Zero(t, server.MaxStartups.Full)
	require.Zero(t, *server.MaxSessionsPerConnection)
	require.Zero(t, *server.MaxChannelsPerConnection)
	require.Zero(t, *server.MaxReverseForwardsPerConnection)
	require.Zero(t, *server.MaxChannels)
	require.Zero(t, *server.MaxReverseForwards)
	gracePeriod, err := server.GracefulShutdownHandler(context.Background())
	require.NoError(t, err)
	require.Zero(t, gracePeriod)
}

func TestPrepareServerUsesIntegratedProxyProtocol(t *testing.T) {
	var conf configuration.Configuration
	require.NoError(t, conf.Ssh.SetDefaults())
	conf.Ssh.ProxyProtocol = true
	svc := &service{Service: &Service{Configuration: conf}}

	require.NoError(t, svc.Service.prepareServer(context.Background(), svc, nil))
	require.NotNil(t, svc.server.ProxyProtocol)
}

func TestSshMaxAuthTriesMapsDisabledLimit(t *testing.T) {
	require.Equal(t, -1, sshMaxAuthTries(0))
	require.Equal(t, 6, sshMaxAuthTries(6))
}
