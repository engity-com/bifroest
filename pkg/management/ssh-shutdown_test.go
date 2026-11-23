package management

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Model a full OS send buffer without depending on macOS/Linux TCP buffer sizes.
// A pending write may finish only when the local transport is actually closed.
type managementSSHBlockedWriter struct {
	net.Conn
	block                atomic.Bool
	started, closed      chan struct{}
	startOnce, closeOnce sync.Once
}

func (conn *managementSSHBlockedWriter) Write(data []byte) (int, error) {
	if conn.block.Load() {
		conn.startOnce.Do(func() { close(conn.started) })
		<-conn.closed
		return 0, net.ErrClosed
	}
	return conn.Conn.Write(data)
}

func (conn *managementSSHBlockedWriter) Close() error {
	conn.closeOnce.Do(func() { close(conn.closed) })
	return conn.Conn.Close()
}

func TestManagementSSHPeerEOFRetiresBlockedServerWriter(t *testing.T) {
	transport := make(chan *managementSSHBlockedWriter, 1)
	observed := make(chan *managementSSHBlockedWriter, 1)
	target, serverDone := managementSSHAuthTestServerWithTransport(t, "version", func(channel ssh.Channel) error {
		conn := <-transport
		conn.block.Store(true)
		_, err := channel.Write([]byte("output blocked in the TCP writer"))
		return err
	}, nil, func(raw net.Conn) net.Conn {
		conn := &managementSSHBlockedWriter{Conn: raw, started: make(chan struct{}), closed: make(chan struct{})}
		t.Cleanup(func() { _ = conn.Close() })
		transport <- conn
		observed <- conn
		return conn
	})
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
	clientDone := make(chan error, 1)
	go func() { clientDone <- target.RunDirect(ctx, "version") }()
	// Synchronize with the actual encrypted transport write, not a sleep or a
	// guessed number of bytes needed to fill this platform's socket buffers.
	select {
	case <-time.After(5 * time.Second):
		t.Fatal("server writer did not start")
	case conn := <-observed:
		select {
		case <-conn.started:
		case <-time.After(5 * time.Second):
			t.Fatal("server writer did not block")
		}
	}
	cancel()
	select {
	case err := <-clientDone:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("client did not stop after cancellation")
	}
	select {
	case err := <-serverDone:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("peer EOF left the server writer holding the SSH channel lock")
	}
	require.Empty(t, output.Bytes())
}
