//go:build darwin

package net

import (
	"context"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func notifyClosed(ctx context.Context, rc syscall.RawConn, onClosed func(), onUnexpectedEnd func(error)) {
	if ctx.Err() != nil {
		return
	}

	kq, err := kqueueCreate()
	if err != nil {
		onUnexpectedEnd(errors.Network.Newf("failed to create kqueue fd: %w", err))
		return
	}
	defer func() { _ = unix.Close(kq) }()

	var registrationErr error
	if err := rc.Control(func(fd uintptr) {
		changes := make([]unix.Kevent_t, 1)
		unix.SetKevent(&changes[0], int(fd), unix.EVFILT_READ, unix.EV_ADD|unix.EV_CLEAR)
		_, registrationErr = kevent(kq, changes, nil, nil)
	}); err != nil {
		if sys.IsClosedError(err) {
			if ctx.Err() == nil {
				onClosed()
			}
			return
		}
		onUnexpectedEnd(errors.Network.Newf("failed to register for close notifications: %w", err))
		return
	}
	if registrationErr != nil {
		onUnexpectedEnd(errors.Network.Newf("failed to register fd for close notifications: %w", registrationErr))
		return
	}

	events := make([]unix.Kevent_t, 1)
	for ctx.Err() == nil {
		timeout := unix.NsecToTimespec(notifyClosedPollInterval.Nanoseconds())
		n, err := kevent(kq, nil, events, &timeout)
		if err != nil {
			onUnexpectedEnd(errors.Network.Newf("failed to wait for close notifications: %w", err))
			return
		}
		if n == 0 {
			continue
		}

		event := events[0]
		if event.Flags&unix.EV_ERROR != 0 {
			onUnexpectedEnd(errors.Network.Newf("failed to wait for close notifications: %w", syscall.Errno(event.Data)))
			return
		}
		if event.Flags&unix.EV_EOF == 0 {
			continue
		}
		if ctx.Err() == nil {
			onClosed()
		}
		return
	}
}

func kqueueCreate() (int, error) {
	for {
		fd, err := unix.Kqueue()
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err == nil {
			unix.CloseOnExec(fd)
		}
		return fd, err
	}
}

func kevent(kq int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
	for {
		n, err := unix.Kevent(kq, changes, events, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return n, err
	}
}
