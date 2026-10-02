package service

import (
	gonet "net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/session"
)

func newTrackedSessionConnection(t *testing.T, svc *service) *connection {
	t.Helper()
	server, peer := gonet.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = peer.Close()
	})
	ctx := newLimiterSSHContext("192.0.2.1")
	conn := &connection{Conn: server, context: ctx, service: svc}
	svc.activeConnections.Add(1)
	return conn
}

func TestSessionConnectionRegistryRevokesOnlyMatchingFlowAndSession(t *testing.T) {
	svc := &service{}
	id, otherId := session.MustNewId(), session.MustNewId()
	first := &houseKeeperTestSession{flow: "one", id: id}
	otherFlow := &houseKeeperTestSession{flow: "two", id: id}
	otherSession := &houseKeeperTestSession{flow: "one", id: otherId}
	conns := []*connection{
		newTrackedSessionConnection(t, svc),
		newTrackedSessionConnection(t, svc),
		newTrackedSessionConnection(t, svc),
		newTrackedSessionConnection(t, svc),
	}
	for i, sess := range []session.Session{first, first, otherFlow, otherSession} {
		svc.sessionConnections.track(conns[i], sess)
	}

	svc.sessionConnections.revoke(first.flow, first.id)
	require.True(t, conns[0].closed.Load())
	require.True(t, conns[1].closed.Load())
	require.False(t, conns[2].closed.Load())
	require.False(t, conns[3].closed.Load())
	require.EqualValues(t, 2, svc.activeConnections.Load())
	svc.sessionConnections.revoke(first.flow, first.id)
	require.EqualValues(t, 2, svc.activeConnections.Load())

	for _, conn := range conns[2:] {
		require.NoError(t, conn.Close())
	}
	require.Empty(t, svc.sessionConnections.connections)
	require.EqualValues(t, 0, svc.activeConnections.Load())
}

func TestSessionConnectionRegistryRejectsRegistrationAfterRevoke(t *testing.T) {
	svc := &service{}
	sess := &houseKeeperTestSession{flow: "main", id: session.MustNewId()}
	svc.sessionConnections.revoke(sess.flow, sess.id)
	conn := newTrackedSessionConnection(t, svc)
	svc.sessionConnections.track(conn, sess)
	require.True(t, conn.closed.Load())
	require.Empty(t, svc.sessionConnections.connections)
	require.EqualValues(t, 0, svc.activeConnections.Load())
}

func TestSessionConnectionRegistryRetainsRevokeUntilFinalDeletion(t *testing.T) {
	svc := &service{}
	sess := &houseKeeperTestSession{flow: "main", id: session.MustNewId()}
	svc.sessionConnections.revoke(sess.flow, sess.id)
	for range 2 {
		conn := newTrackedSessionConnection(t, svc)
		svc.sessionConnections.track(conn, sess)
		require.True(t, conn.closed.Load())
	}
	require.Len(t, svc.sessionConnections.sessions, 1)
	svc.sessionConnections.finalSessionDeleted(sess.flow, sess.id)
	require.Empty(t, svc.sessionConnections.sessions)
}

func TestSessionConnectionRegistryUntrackAndClosedRegistration(t *testing.T) {
	svc := &service{}
	sess := &houseKeeperTestSession{flow: "main", id: session.MustNewId()}
	conn := newTrackedSessionConnection(t, svc)
	svc.sessionConnections.track(conn, sess)
	require.NoError(t, conn.Close())
	svc.sessionConnections.track(conn, sess)
	require.Empty(t, svc.sessionConnections.connections)
	require.Empty(t, svc.sessionConnections.sessions)
	svc.sessionConnections.revoke(sess.flow, sess.id)
	require.EqualValues(t, 0, svc.activeConnections.Load())
}

func TestSessionConnectionRegistryRetrackMovesConnection(t *testing.T) {
	svc := &service{}
	first := &houseKeeperTestSession{flow: "first", id: session.MustNewId()}
	second := &houseKeeperTestSession{flow: "second", id: session.MustNewId()}
	conn := newTrackedSessionConnection(t, svc)
	svc.sessionConnections.track(conn, first)
	svc.sessionConnections.track(conn, second)
	svc.sessionConnections.revoke(first.flow, first.id)
	require.False(t, conn.closed.Load())
	svc.sessionConnections.revoke(second.flow, second.id)
	require.True(t, conn.closed.Load())
	require.EqualValues(t, 0, svc.activeConnections.Load())
}

func TestSessionConnectionRegistryTrackRacesRevoke(t *testing.T) {
	for i := 0; i < 100; i++ {
		svc := &service{}
		sess := &houseKeeperTestSession{flow: "main", id: session.MustNewId()}
		conn := newTrackedSessionConnection(t, svc)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			svc.sessionConnections.track(conn, sess)
		}()
		go func() {
			defer wg.Done()
			svc.sessionConnections.revoke(sess.flow, sess.id)
		}()
		wg.Wait()
		require.True(t, conn.closed.Load())
		require.EqualValues(t, 0, svc.activeConnections.Load())
	}
}

type blockingSessionCloseConn struct {
	gonet.Conn
	entered chan struct{}
	release chan struct{}
}

func (this *blockingSessionCloseConn) Close() error {
	close(this.entered)
	<-this.release
	return this.Conn.Close()
}

func TestSessionConnectionRegistryDoesNotHoldLockWhileClosing(t *testing.T) {
	svc := &service{}
	sess := &houseKeeperTestSession{flow: "main", id: session.MustNewId()}
	conn := newTrackedSessionConnection(t, svc)
	blocked := &blockingSessionCloseConn{Conn: conn.Conn, entered: make(chan struct{}), release: make(chan struct{})}
	conn.Conn = blocked
	svc.sessionConnections.track(conn, sess)
	done := make(chan struct{})
	go func() {
		svc.sessionConnections.revoke(sess.flow, sess.id)
		close(done)
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("revoke did not close the connection")
	}
	defer func() {
		select {
		case <-blocked.release:
		default:
			close(blocked.release)
		}
	}()
	other := newTrackedSessionConnection(t, svc)
	tracked := make(chan struct{})
	go func() {
		svc.sessionConnections.track(other, &houseKeeperTestSession{flow: "other", id: sess.id})
		close(tracked)
	}()
	select {
	case <-tracked:
	case <-time.After(time.Second):
		t.Fatal("registry lock held while closing a connection")
	}
	require.NoError(t, other.Close())
	close(blocked.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revoke did not finish")
	}
}

func TestSessionConnectionRegistryClosesOtherConnectionsWhileOneCloseBlocks(t *testing.T) {
	svc := &service{}
	sess := &houseKeeperTestSession{flow: "main", id: session.MustNewId()}
	blockedConn := newTrackedSessionConnection(t, svc)
	blocked := &blockingSessionCloseConn{Conn: blockedConn.Conn, entered: make(chan struct{}), release: make(chan struct{})}
	blockedConn.Conn = blocked
	other := newTrackedSessionConnection(t, svc)
	svc.sessionConnections.track(blockedConn, sess)
	svc.sessionConnections.track(other, sess)
	done := make(chan struct{})
	go func() {
		svc.sessionConnections.revoke(sess.flow, sess.id)
		close(done)
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("first connection close was not started")
	}
	defer func() {
		select {
		case <-blocked.release:
		default:
			close(blocked.release)
		}
	}()
	require.Eventually(t, func() bool { return other.closed.Load() }, time.Second, time.Millisecond)
	close(blocked.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("revocation did not finish")
	}
	require.Zero(t, svc.activeConnections.Load())
}
