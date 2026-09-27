//go:build darwin

package net

import (
	"context"
	gonet "net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDarwinNotifyClosedIgnoresReadableData(t *testing.T) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	client, err := gonet.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	server, err := listener.Accept()
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	ctx, cancel := context.WithCancel(t.Context())
	closed := make(chan struct{}, 1)
	unexpected := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		NotifyClosedContext(ctx, server, func() { closed <- struct{}{} }, func(err error) { unexpected <- err })
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
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close notification did not stop after cancellation")
	}
}

func TestDarwinNotifyClosedStopsAfterLocalCloseAndCancellation(t *testing.T) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	client, err := gonet.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	server, err := listener.Accept()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	closed := make(chan struct{}, 1)
	unexpected := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		NotifyClosedContext(ctx, server, func() { closed <- struct{}{} }, func(err error) { unexpected <- err })
		close(done)
	}()
	time.Sleep(notifyClosedPollInterval)
	require.NoError(t, server.Close())
	cancel()

	select {
	case err := <-unexpected:
		t.Fatal(err)
	case <-closed:
		t.Fatal("local close was reported as a peer close")
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close notification did not stop after local close and cancellation")
	}
}

func TestDarwinNotifyClosedReleasesKqueueDescriptors(t *testing.T) {
	run := func() {
		listener, err := gonet.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		client, err := gonet.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		server, err := listener.Accept()
		require.NoError(t, err)
		done := make(chan struct{})
		go func() {
			NotifyClosed(server, func() {}, func(err error) { t.Error(err) })
			close(done)
		}()
		require.NoError(t, client.Close())
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("close notification timed out")
		}
		require.NoError(t, server.Close())
		require.NoError(t, listener.Close())
	}

	for range 32 {
		run()
	}
	before := openFileDescriptorCount(t)
	for range 32 {
		run()
	}
	after := openFileDescriptorCount(t)
	require.LessOrEqual(t, after, before+8, "kqueue descriptors leaked: before=%d, after=%d", before, after)
}

func openFileDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	require.NoError(t, err)
	return len(entries)
}
