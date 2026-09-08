//go:build unix

package net

import (
	"context"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func notifyClosed(ctx context.Context, rc syscall.RawConn, onClosed func(), onUnexpectedEnd func(error)) {
	if ctx.Err() != nil {
		return
	}
	epFd, err := epollCreate()
	if err != nil {
		onUnexpectedEnd(errors.Network.Newf("failed to create epoll fd: %w", err))
		return
	}
	defer func() {
		_ = unix.Close(epFd)
	}()

	var registrationErr error
	if err := rc.Control(func(fd uintptr) {
		registrationErr = epollCtl(epFd, unix.EPOLL_CTL_ADD, int(fd), &unix.EpollEvent{
			Events: unix.EPOLLHUP | unix.EPOLLRDHUP,
			Fd:     int32(fd),
		})
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

	events := make([]unix.EpollEvent, 1)
	for ctx.Err() == nil {
		n, err := epollWait(epFd, events, int(notifyClosedPollInterval/time.Millisecond))
		if err != nil {
			onUnexpectedEnd(errors.Network.Newf("failed to wait for close notifications: %w", err))
			return
		}
		if n > 0 {
			if ctx.Err() == nil {
				onClosed()
			}
			return
		}
	}
}

func epollCreate() (int, error) {
	for {
		fd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return fd, err
	}
}

func epollCtl(epFd int, op int, fd int, event *unix.EpollEvent) error {
	for {
		err := unix.EpollCtl(epFd, op, fd, event)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func epollWait(epFd int, events []unix.EpollEvent, msec int) (int, error) {
	for {
		n, err := unix.EpollWait(epFd, events, msec)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return n, err
	}
}
