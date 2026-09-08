//go:build windows

package net

import (
	"context"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	modws232           = windows.NewLazySystemDLL("ws2_32.dll")
	procWSAEventSelect = modws232.NewProc("WSAEventSelect")
	procWSACreateEvent = modws232.NewProc("WSACreateEvent")
	procWSACloseEvent  = modws232.NewProc("WSACloseEvent")
)

const (
	typeFdClose = 1 << 5
)

func notifyClosed(ctx context.Context, rc syscall.RawConn, onClosed func(), onUnexpectedEnd func(error)) {
	if ctx.Err() != nil {
		return
	}
	var eventHandle windows.Handle
	var registrationErr error
	if err := rc.Control(func(fd uintptr) {
		eventHandle, registrationErr = wsaEventSelect(windows.Handle(fd), typeFdClose)
	}); sys.IsClosedError(err) {
		if ctx.Err() == nil {
			onClosed()
		}
		return
	} else if err != nil {
		onUnexpectedEnd(errors.Network.Newf("cannot execute control operations on connection %v", rc))
		return
	}
	if registrationErr != nil {
		onUnexpectedEnd(errors.Network.Newf("failed to register socket for close notifications: %w", registrationErr))
		return
	}
	defer func() {
		_ = rc.Control(func(fd uintptr) {
			_, _, _ = procWSAEventSelect.Call(fd, 0, 0)
		})
		_ = wsaCloseEvent(eventHandle)
	}()

	for ctx.Err() == nil {
		result, err := windows.WaitForSingleObject(eventHandle, uint32(notifyClosedPollInterval/time.Millisecond))
		if err != nil {
			onUnexpectedEnd(errors.Network.Newf("failed to wait for close notifications: %w", err))
			return
		}
		switch result {
		case windows.WAIT_OBJECT_0:
			if ctx.Err() == nil {
				onClosed()
			}
			return
		case uint32(windows.WAIT_TIMEOUT):
		default:
			onUnexpectedEnd(errors.Network.Newf("waiting for close notifications returned unexpected result %d", result))
			return
		}
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

func wsaCloseEvent(event windows.Handle) error {
	if ret, _, err := procWSACloseEvent.Call(uintptr(event)); ret == 0 {
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
	_ = wsaCloseEvent(event)
	return 0, err
}
