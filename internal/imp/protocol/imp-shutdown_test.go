package protocol

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type shutdownGatedConn struct {
	net.Conn
	entered             chan struct{}
	release             chan struct{}
	closed              chan struct{}
	readOnce, closeOnce sync.Once
}

func (c *shutdownGatedConn) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.entered) })
	<-c.release
	return 0, net.ErrClosed
}
func (c *shutdownGatedConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func (c *shutdownGatedConn) NetConn() net.Conn { return c.Conn }

type shutdownGatedListener struct {
	net.Listener
	accepted chan *shutdownGatedConn
	release  chan struct{}
}

func (l *shutdownGatedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped := &shutdownGatedConn{Conn: conn, entered: make(chan struct{}), release: l.release, closed: make(chan struct{})}
	l.accepted <- wrapped
	return wrapped, nil
}

func TestImpServeJoinsActiveConnectionBeforeReturning(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	defer listener.Close()
	wrapped := &shutdownGatedListener{Listener: listener, accepted: make(chan *shutdownGatedConn, 1), release: release}
	server := &imp{Imp: &Imp{}}
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, wrapped) }()
	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	var conn *shutdownGatedConn
	select {
	case conn = <-wrapped.accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("owned connection was not accepted")
	}
	select {
	case <-conn.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("owned handler did not enter its read")
	}
	cancel()
	_ = listener.Close()
	returned := false
	select {
	case err := <-done:
		t.Errorf("serve returned while connection handler was still running: %v", err)
		returned = true
	case <-time.After(30 * time.Millisecond):
	}
	if !returned {
		select {
		case <-conn.closed:
		case <-time.After(2 * time.Second):
			t.Error("shutdown did not close the active connection")
		}
	}
	once.Do(func() { close(release) })
	if !returned {
		select {
		case err := <-done:
			require.True(t, errors.Is(err, net.ErrClosed))
		case <-time.After(2 * time.Second):
			t.Fatal("serve did not join released handler")
		}
	}
}
