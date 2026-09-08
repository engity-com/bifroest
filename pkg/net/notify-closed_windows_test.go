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
	before := processHandleCount(t)

	for range 64 {
		client, err := gonet.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		server, err := listener.Accept()
		require.NoError(t, err)
		closed := make(chan struct{})
		unexpected := make(chan error, 1)
		go NotifyClosed(server, func() { close(closed) }, func(err error) { unexpected <- err })
		require.NoError(t, client.Close())
		select {
		case err := <-unexpected:
			t.Fatal(err)
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("close notification timed out")
		}
		require.NoError(t, server.Close())
	}

	after := processHandleCount(t)
	require.LessOrEqual(t, after, before+8)
}

func processHandleCount(t *testing.T) uint32 {
	t.Helper()
	var result uint32
	ret, _, err := procGetProcessHandleCount.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&result)))
	require.NotZero(t, ret, err)
	return result
}
