package net

import (
	"context"
	gonet "net"
	"syscall"
	"time"

	"github.com/engity-com/bifroest/pkg/errors"
)

const notifyClosedPollInterval = 100 * time.Millisecond

var (
	ErrNotifyClosedUnsupported = errors.Network.Newf("notify closed is not supported for this connection")
)

func NotifyClosed(conn gonet.Conn, onClosed func(), onUnexpectedEnd func(error)) {
	NotifyClosedContext(context.Background(), conn, onClosed, onUnexpectedEnd)
}

func NotifyClosedContext(ctx context.Context, conn gonet.Conn, onClosed func(), onUnexpectedEnd func(error)) {
	if ctx == nil {
		panic(errors.System.Newf("ctx is nil"))
	}
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

	notifyClosed(ctx, rc, onClosed, onUnexpectedEnd)
}
