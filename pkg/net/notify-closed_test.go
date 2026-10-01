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
	select {
	case err := <-unexpected:
		t.Fatal(err)
	case <-closed:
		t.Fatal("local cancellation was reported as a remote close")
	default:
	}
	require.NoError(t, server.Close())
}

func TestNotifyClosedReportsPeerClose(t *testing.T) {
	testNotifyClosedReportsPeerClose(t, false)
}

func TestNotifyClosedReportsPeerCloseWrite(t *testing.T) {
	testNotifyClosedReportsPeerClose(t, true)
}

func testNotifyClosedReportsPeerClose(t *testing.T, closeWrite bool) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	client, err := gonet.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	server, err := listener.Accept()
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	closed := make(chan struct{}, 1)
	unexpected := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		NotifyClosed(server, func() { closed <- struct{}{} }, func(err error) { unexpected <- err })
		close(done)
	}()
	if closeWrite {
		require.NoError(t, client.(*gonet.TCPConn).CloseWrite())
		defer func() { _ = client.Close() }()
	} else {
		require.NoError(t, client.Close())
	}

	select {
	case err := <-unexpected:
		t.Fatal(err)
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("peer close notification timed out")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close notification did not return")
	}
}

func TestNotifyClosedDoesNotTreatReadableDataAsClose(t *testing.T) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	client, err := gonet.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	server, err := listener.Accept()
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	closed := make(chan struct{}, 1)
	unexpected := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		NotifyClosed(server, func() { closed <- struct{}{} }, func(err error) { unexpected <- err })
		close(done)
	}()
	n, err := client.Write([]byte("readable"))
	require.NoError(t, err)
	require.Equal(t, len("readable"), n)

	select {
	case err := <-unexpected:
		t.Fatal(err)
	case <-closed:
		t.Fatal("readable data was reported as a close")
	case <-done:
		t.Fatal("close notification stopped for readable data")
	case <-time.After(2 * notifyClosedPollInterval):
	}
	require.NoError(t, client.(*gonet.TCPConn).CloseWrite())

	select {
	case err := <-unexpected:
		t.Fatal(err)
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("peer close notification timed out")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close notification did not return")
	}
}
