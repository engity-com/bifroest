package crypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestFetchKnownHostKeyStopsBeforeAuthentication(t *testing.T) {
	address, expected, authenticationCalls, serverDone := startHostKeyScanTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, err := FetchKnownHostKey(ctx, address)
	require.NoError(t, err)

	marker, hosts, actual, _, rest, err := ssh.ParseKnownHosts(raw)
	require.NoError(t, err)
	require.Empty(t, marker)
	require.Equal(t, []string{knownhosts.Normalize(address)}, hosts)
	require.Equal(t, expected.Marshal(), actual.Marshal())
	require.Empty(t, rest)
	require.Zero(t, authenticationCalls.Load())
	require.Error(t, <-serverDone)
}

func TestFetchKnownHostKeyHonorsContextDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = FetchKnownHostKey(ctx, listener.Addr().String())
	require.ErrorIs(t, err, context.DeadlineExceeded)
	connection := <-accepted
	require.NoError(t, connection.Close())
}

func TestFetchKnownHostKeyRejectsNonSshPeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = FetchKnownHostKey(ctx, listener.Addr().String())
	require.Error(t, err)
	require.False(t, errors.Is(err, errHostKeyCaptured))
}

func startHostKeyScanTestServer(t *testing.T) (string, ssh.PublicKey, *atomic.Int32, <-chan error) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	var authenticationCalls atomic.Int32
	config := &ssh.ServerConfig{
		NoClientAuth: true,
		NoClientAuthCallback: func(ssh.ConnMetadata) (*ssh.Permissions, error) {
			authenticationCalls.Add(1)
			return nil, nil
		},
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		server, _, _, serverErr := ssh.NewServerConn(connection, config)
		if server != nil {
			_ = server.Close()
		}
		serverDone <- serverErr
	}()
	return listener.Addr().String(), signer.PublicKey(), &authenticationCalls, serverDone
}
