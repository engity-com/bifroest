//go:build windows

package net

import (
	gonet "net"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var procGetProcessHandleCount = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")

func TestNotifyClosedReleasesEventHandles(t *testing.T) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	run := func() {
		t.Helper()
		client, err := gonet.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		server, err := listener.Accept()
		require.NoError(t, err)
		defer func() { _ = server.Close() }()
		var closed bool
		var unexpected error
		done := make(chan struct{})
		go func() {
			NotifyClosed(server, func() { closed = true }, func(err error) { unexpected = err })
			close(done)
		}()
		require.NoError(t, client.Close())
		// The callback runs before deferred event cleanup; wait for NotifyClosed to return.
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("close notification timed out")
		}
		require.NoError(t, unexpected)
		require.True(t, closed, "close notification was not received")
		require.NoError(t, server.Close())
	}

	// Warm up networking and runtime resources before counting process-wide handles.
	for range 64 {
		run()
	}
	before := processHandleCount(t)
	for range 64 {
		run()
	}
	after := processHandleCount(t)
	require.LessOrEqual(t, after, before+8, "event handles leaked: before=%d, after=%d", before, after)
}

func processHandleCount(t *testing.T) uint32 {
	t.Helper()
	var result uint32
	ret, _, err := procGetProcessHandleCount.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&result)))
	require.NotZero(t, ret, err)
	return result
}
