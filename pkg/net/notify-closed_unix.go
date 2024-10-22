//go:build unix

package net

import (
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/errors"
)

func notifyClosed(rc syscall.RawConn, onClosed func(), onUnexpectedEnd func(error)) {
	epFd, err := epollCreate()
	if err != nil {
		onUnexpectedEnd(errors.Network.Newf("failed to create epoll fd: %w", err))
		return
	}
	defer func() {
		_ = unix.Close(epFd)
	}()

	if err := rc.Control(func(fd uintptr) {
		if err := epollCtl(epFd, unix.EPOLL_CTL_ADD, int(fd), &unix.EpollEvent{
			Events: unix.EPOLLHUP | unix.EPOLLRDHUP,
			Fd:     int32(fd),
		}); err != nil {
			onUnexpectedEnd(errors.Network.Newf("failed to register fd for close notifications: %w", err))
			return
		}

		events := make([]unix.EpollEvent, 1)
		if _, err := epollWait(epFd, events, -1); err != nil {
			onUnexpectedEnd(errors.Network.Newf("failed to wait for close notifications: %w", err))
			return
		}
		onClosed()
	}); err != nil {
		onUnexpectedEnd(errors.Network.Newf("failed to register for close notifications: %w", err))
		return
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
