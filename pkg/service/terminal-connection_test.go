package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestNeutralConnectionSharesSessionLimitWithSshLease(t *testing.T) {
	t.Parallel()
	svc, transport, auth := terminalConnectionTestFixture(t, func(conf *configuration.SessionFs) { conf.MaxConnections = 1 })
	ssh := newTrackedSessionConnection(t, svc)
	ssh.context.SetValue(authorizationCtxKey, auth)
	require.NoError(t, ssh.doWithInterceptor(func(session.ConnectionInterceptor) error { return nil }))
	svc.sessionConnections.track(ssh, auth.FindSession())
	conn, err := svc.registerTerminalConnection(transport, auth)
	require.ErrorIs(t, err, session.ErrMaxConnectionsPerSessionReached)
	require.Nil(t, conn)
	require.NoError(t, ssh.Close())
	registered := registerTerminalConnectionForTest(t, svc, transport, auth)
	require.False(t, registered.IsClosed())
}

func TestNeutralConnectionIdleWatchDoesNotRenewItsOwnDeadline(t *testing.T) {
	t.Parallel()
	svc, transport, auth := terminalConnectionTestFixture(t, func(conf *configuration.SessionFs) {
		conf.IdleTimeout = common.DurationOf(400 * time.Millisecond)
	})
	conn := registerTerminalConnectionForTest(t, svc, transport, auth)
	for range 8 {
		require.NoError(t, conn.activity())
		time.Sleep(70 * time.Millisecond)
	}
	require.False(t, conn.IsClosed(), "real activity must extend the shared idle timeout")
	require.Eventually(t, conn.IsClosed, 2*time.Second, 10*time.Millisecond, "validity checks must not keep an unused connection alive")
	info, err := auth.FindSession().Info(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, session.StateDisposed, info.State(), "expiry watcher only closes access; normal housekeeping owns disposal")
}

func TestNeutralConnectionMaximumLifetimeIsNotExtendedByActivity(t *testing.T) {
	t.Parallel()
	svc, transport, auth := terminalConnectionTestFixture(t, func(conf *configuration.SessionFs) {
		conf.MaxTimeout = common.DurationOf(400 * time.Millisecond)
	})
	conn := registerTerminalConnectionForTest(t, svc, transport, auth)
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(30 * time.Millisecond)
	defer tick.Stop()
	for !conn.IsClosed() {
		select {
		case <-tick.C:
			_ = conn.activity()
		case <-deadline.C:
			t.Fatal("maximum session lifetime was renewed by activity")
		}
	}
}

func TestNeutralConnectionDirectDisposalAndParentCancelCloseTransport(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"dispose", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			svc, transport, auth := terminalConnectionTestFixture(t)
			conn := registerTerminalConnectionForTest(t, svc, transport, auth)
			if mode == "dispose" {
				_, err := auth.FindSession().Dispose(t.Context())
				require.NoError(t, err)
			} else {
				transport.cancel()
			}
			require.Eventually(t, func() bool {
				return conn.IsClosed() && errors.Is(transport.Lifetime().Err(), context.Canceled)
			}, 2*time.Second, 10*time.Millisecond, "closing admission precedes actual transport cancellation")
			require.ErrorIs(t, transport.Lifetime().Err(), context.Canceled)
		})
	}
}

type blockedTerminalClose struct {
	terminalTransport
	started chan struct{}
	allow   chan struct{}
}

func (this *blockedTerminalClose) Close() error {
	close(this.started)
	<-this.allow
	return this.terminalTransport.Close()
}

func TestNeutralConnectionClosingAdmissionDoesNotClaimCompletedTransportCleanup(t *testing.T) {
	t.Parallel()
	svc, transport, auth := terminalConnectionTestFixture(t)
	blocked := &blockedTerminalClose{terminalTransport: transport, started: make(chan struct{}), allow: make(chan struct{})}
	conn, err := svc.registerTerminalConnection(blocked, auth)
	require.NoError(t, err)
	t.Cleanup(func() {
		select {
		case <-blocked.allow:
		default:
			close(blocked.allow)
		}
		require.NoError(t, conn.Close())
		waitTerminalConnectionForTest(t, conn)
	})
	_, err = auth.FindSession().Dispose(t.Context())
	require.NoError(t, err)
	select {
	case <-blocked.started:
	case <-time.After(2 * time.Second):
		t.Fatal("disposed connection did not start transport cleanup")
	}
	require.True(t, conn.IsClosed(), "new operations must already be denied while cleanup is blocked")
	require.NoError(t, transport.Lifetime().Err(), "the fixture holds actual transport cancellation")
	select {
	case <-conn.done:
		t.Fatal("watcher claimed completion while its transport close was blocked")
	default:
	}
	close(blocked.allow)
	select {
	case <-conn.done:
	case <-time.After(2 * time.Second):
		t.Fatal("transport cleanup did not complete after release")
	}
	require.ErrorIs(t, transport.Lifetime().Err(), context.Canceled)
}
