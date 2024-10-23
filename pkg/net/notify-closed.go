package net

import (
	gonet "net"
	"syscall"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrNotifyClosedUnsupported = errors.Network.Newf("notify closed is not supported for this connection")
)

func NotifyClosed(conn gonet.Conn, onClosed func(), onUnexpectedEnd func(error)) {
	if onClosed == nil {
		panic(errors.System.Newf("onClosed is nil"))
	}
	if onUnexpectedEnd == nil {
		onUnexpectedEnd = func(error) {}
	}

	for {
		nce, ok := conn.(interface{ NetConn() gonet.Conn })
		if !ok {
			break
		}
		candidate := nce.NetConn()
		if candidate == nil {
			break
		}
		conn = candidate
	}

	sc, ok := conn.(syscall.Conn)
	if !ok {
		onUnexpectedEnd(ErrNotifyClosedUnsupported)
		return
	}

	rc, err := sc.SyscallConn()
	if err != nil {
		onUnexpectedEnd(errors.Network.Newf("failed get raw conn for close notifications: %w", err))
		return
	}

	notifyClosed(rc, onClosed, onUnexpectedEnd)
}
