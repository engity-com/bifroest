package service

import (
	"context"
	"fmt"
	"io"
	gonet "net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/environment"
)

// Keep the existing authorized-key forwarding tests backed by an actual listener.
func (this *authorizedKeysTestEnvironment) ListenReverseTCP(ctx context.Context, host string, port uint16) (gonet.Listener, error) {
	if !this.portForwardingAllowed {
		return nil, fmt.Errorf("reverse forwarding disabled")
	}
	var config gonet.ListenConfig
	return config.Listen(ctx, "tcp", gonet.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)))
}

func TestReverseTCPListenerForwardsAndReleasesPort(t *testing.T) {
	server := newAuthorizedKeysTestServer(t, `permitlisten="127.0.0.1:*"`, &authorizedKeysTestEnvironment{portForwardingAllowed: true})
	client := server.mustDial(t)
	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().(*gonet.TCPAddr)
	require.NotZero(t, addr.Port)

	peer, err := gonet.DialTimeout("tcp", addr.String(), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = peer.Close() })
	require.NoError(t, peer.SetDeadline(time.Now().Add(2*time.Second)))
	forwarded, err := listener.Accept()
	require.NoError(t, err)
	defer func() { _ = forwarded.Close() }()
	_, err = peer.Write([]byte("local"))
	require.NoError(t, err)
	buffer := make([]byte, 5)
	_, err = io.ReadFull(forwarded, buffer)
	require.NoError(t, err)
	require.Equal(t, "local", string(buffer))
	_, err = forwarded.Write([]byte("reply"))
	require.NoError(t, err)
	_, err = io.ReadFull(peer, buffer)
	require.NoError(t, err)
	require.Equal(t, "reply", string(buffer))

	require.NoError(t, listener.Close())
	rebound, err := gonet.Listen("tcp", addr.String())
	require.NoError(t, err)
	require.NoError(t, rebound.Close())
}

type reverseTCPTestRepository struct {
	*authorizedKeysTestRepository
	ensure func() environment.Environment
}

func (this *reverseTCPTestRepository) Ensure(environment.Request) (environment.Environment, error) {
	return this.ensure(), nil
}

type reverseTCPTrackedEnvironment struct {
	*authorizedKeysTestEnvironment
	closed *atomic.Int32
}

func (this *reverseTCPTrackedEnvironment) Close() error {
	this.closed.Add(1)
	return nil
}

func TestReverseTCPListenerOwnsEnvironmentUntilClose(t *testing.T) {
	base := &authorizedKeysTestEnvironment{portForwardingAllowed: true}
	server := newAuthorizedKeysTestServer(t, "", base)
	var policyClosed, listenerClosed atomic.Int32
	var calls atomic.Int32
	server.service.environments = &reverseTCPTestRepository{
		authorizedKeysTestRepository: &authorizedKeysTestRepository{environment: base},
		ensure: func() environment.Environment {
			if calls.Add(1) == 1 {
				return &reverseTCPTrackedEnvironment{base, &policyClosed}
			}
			return &reverseTCPTrackedEnvironment{base, &listenerClosed}
		},
	}
	client := server.mustDial(t)
	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load(), "policy and bind each ensure their own environment")
	require.EqualValues(t, 1, policyClosed.Load())
	require.Zero(t, listenerClosed.Load())
	require.NoError(t, listener.Close())
	require.Eventually(t, func() bool { return listenerClosed.Load() == 1 }, time.Second, 10*time.Millisecond)
}

type reverseTCPUnsupportedEnvironment struct {
	environment.Environment
	closed *atomic.Int32
}

func (this *reverseTCPUnsupportedEnvironment) Close() error {
	this.closed.Add(1)
	return nil
}

func TestReverseTCPListenerRejectsUnsupportedEnvironment(t *testing.T) {
	base := &authorizedKeysTestEnvironment{portForwardingAllowed: true}
	server := newAuthorizedKeysTestServer(t, "", base)
	var closed atomic.Int32
	var calls atomic.Int32
	server.service.environments = &reverseTCPTestRepository{
		authorizedKeysTestRepository: &authorizedKeysTestRepository{environment: base},
		ensure: func() environment.Environment {
			if calls.Add(1) == 1 {
				return base
			}
			return &reverseTCPUnsupportedEnvironment{base, &closed}
		},
	}
	client := server.mustDial(t)
	listener, err := client.Listen("tcp", "127.0.0.1:0")
	if listener != nil {
		_ = listener.Close()
	}
	require.Error(t, err)
	require.EqualValues(t, 2, calls.Load())
	require.EqualValues(t, 1, closed.Load())
}

func TestReverseTCPListenerClosesEnvironmentOnBindFailure(t *testing.T) {
	occupied, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()
	base := &authorizedKeysTestEnvironment{portForwardingAllowed: true}
	server := newAuthorizedKeysTestServer(t, "", base)
	var closed, calls atomic.Int32
	server.service.environments = &reverseTCPTestRepository{
		authorizedKeysTestRepository: &authorizedKeysTestRepository{environment: base},
		ensure: func() environment.Environment {
			if calls.Add(1) == 1 {
				return base
			}
			return &reverseTCPTrackedEnvironment{base, &closed}
		},
	}
	client := server.mustDial(t)
	listener, err := client.Listen("tcp", occupied.Addr().String())
	if listener != nil {
		_ = listener.Close()
	}
	require.Error(t, err)
	require.EqualValues(t, 2, calls.Load())
	require.EqualValues(t, 1, closed.Load())
}

func TestReverseTCPListenerCloseIsIdempotent(t *testing.T) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var closed atomic.Int32
	owner := &reverseTCPTrackedEnvironment{&authorizedKeysTestEnvironment{}, &closed}
	wrapped := &environmentReverseTCPListener{Listener: listener, owner: owner}
	require.NoError(t, wrapped.Close())
	require.ErrorIs(t, listener.Close(), gonet.ErrClosed)
	require.NoError(t, wrapped.Close())
	require.EqualValues(t, 1, closed.Load())
}
