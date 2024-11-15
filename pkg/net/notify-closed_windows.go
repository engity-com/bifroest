//go:build windows

package net

import (
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	modws232           = windows.NewLazySystemDLL("ws2_32.dll")
	procWSAEventSelect = modws232.NewProc("WSAEventSelect")
	procWSAResetEvent  = modws232.NewProc("WSAResetEvent")
	procWSACreateEvent = modws232.NewProc("WSACreateEvent")
)

const (
	typeFdClose = 1 << 5
)

func notifyClosed(rc syscall.RawConn, onClosed func(), onUnexpectedEnd func(error)) {
	var success atomic.Bool
	fail := func(kind string, err error) {
		if sys.IsClosedError(err) {
			success.Store(true)
		} else if err != nil {
			onUnexpectedEnd(err)
		}
	}
	if err := rc.Control(func(fd uintptr) {
		eventHandle, err := wsaEventSelect(windows.Handle(fd), typeFdClose)
		if err != nil {
			fail("WSAEventSelect", err)
			return
		}
		defer func() {
			_ = wsaResetEvent(eventHandle)
		}()

		_, err = windows.WaitForSingleObject(eventHandle, windows.INFINITE)
		//goland:noinspection GoTypeAssertionOnErrors
		if sce, ok := err.(syscall.Errno); ok && sce == 0 {
			// Ok
		} else if err != nil {
			fail("WaitForSingleObject", err)
			return
		}
		success.Store(true)
	}); sys.IsClosedError(err) {
		success.Store(true)
		onClosed()
	} else if err != nil {
		onUnexpectedEnd(errors.Network.Newf("cannot execute control operations on connection %v", rc))
		return
	}

	if success.Load() {
		onClosed()
	}
}

func wsaCreateEvent() (windows.Handle, error) {
	ret, _, err := procWSACreateEvent.Call()
	//goland:noinspection GoTypeAssertionOnErrors
	if sce, ok := err.(syscall.Errno); ok && sce == 0 {
		return windows.Handle(ret), nil
	}
	return 0, err
}

func wsaResetEvent(event windows.Handle) error {
	if ret, _, err := procWSAResetEvent.Call(uintptr(event)); ret != 0 {
		return err
	}
	return nil
}

func wsaEventSelect(fd windows.Handle, kind uint32) (windows.Handle, error) {
	event, err := wsaCreateEvent()
	if err != nil {
		return 0, err
	}
	_, _, err = procWSAEventSelect.Call(uintptr(fd), uintptr(event), uintptr(kind))
	//goland:noinspection GoTypeAssertionOnErrors
	if sce, ok := err.(syscall.Errno); ok && sce == 0 {
		return event, nil
	}
	return 0, err
}
