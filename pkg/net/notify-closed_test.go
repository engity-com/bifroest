package net

import (
	"context"
	gonet "net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNotifyClosedStopsWhenContextIsCanceled(t *testing.T) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	client, err := gonet.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	server, err := listener.Accept()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	closed := make(chan struct{}, 1)
	unexpected := make(chan error, 1)
	go func() {
		NotifyClosedContext(ctx, server, func() { closed <- struct{}{} }, func(err error) { unexpected <- err })
		close(done)
	}()
	time.Sleep(2 * notifyClosedPollInterval)
	cancel()

	select {
	case err := <-unexpected:
		t.Fatal(err)
	case <-closed:
		t.Fatal("local cancellation was reported as a remote close")
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close notification did not stop after cancellation")
	}
	require.NoError(t, server.Close())
}
