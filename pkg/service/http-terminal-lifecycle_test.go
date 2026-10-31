package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
)

func webSocketWaitTask(task environment.TerminalTask) (int, error) {
	<-task.Context().Done()
	return -1, task.Context().Err()
}

func requireWebSocketsDrained(t *testing.T, svc *service) {
	t.Helper()
	require.Eventually(t, func() bool {
		svc.web.mutex.Lock()
		defer svc.web.mutex.Unlock()
		return svc.web.sockets == 0
	}, 3*time.Second, 10*time.Millisecond)
}

func TestWebSocketQuotaAndDisconnectReleaseTheSharedLease(t *testing.T) {
	fixture := newWebSocketFixture(t, webSocketWaitTask, func(conf *configuration.Configuration) {
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
	token := fixture.login(t)
	first := fixture.dial(t)
	require.NoError(t, first.WriteJSON(webSocketOpen(token)))
	requireWebSocketReady(t, first)
	second := fixture.dial(t)
	require.NoError(t, second.WriteJSON(webSocketOpen(token)))
	require.Equal(t, `"connection-denied"`, string(webSocketStatus(t, second)["code"]))
	require.NoError(t, first.Close()) // No browser unload/close API is needed.
	requireWebSocketsDrained(t, fixture.svc)
	third := fixture.dial(t)
	require.NoError(t, third.WriteJSON(webSocketOpen(token)))
	requireWebSocketReady(t, third)
}

func TestWebSocketGrantExpiryLogoutAndSessionRevocationAreDistinct(t *testing.T) {
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		_, err := io.Copy(task.Terminal(), task.Terminal())
		return 0, err
	})
	one, two := fixture.login(t), fixture.login(t)
	access := webTestAccess(t, fixture.svc, one, "Work")
	first, sibling := fixture.dial(t), fixture.dial(t)
	for _, pair := range []struct {
		conn  *websocket.Conn
		token string
	}{{first, one}, {sibling, two}} {
		require.NoError(t, pair.conn.WriteJSON(webSocketOpen(pair.token)))
		requireWebSocketReady(t, pair.conn)
	}
	access.mutex.Lock()
	access.expires = time.Now().Add(-time.Second)
	access.mutex.Unlock()
	late := fixture.dial(t)
	require.NoError(t, late.WriteJSON(webSocketOpen(one)))
	require.Equal(t, `"authentication-denied"`, string(webSocketStatus(t, late)["code"]))
	echo := func(conn *websocket.Conn) {
		require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, []byte("still authenticated")))
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
		kind, data, err := conn.ReadMessage()
		require.NoError(t, err)
		require.Equal(t, websocket.BinaryMessage, kind)
		require.Equal(t, append([]byte{0}, []byte("still authenticated")...), data)
	}
	echo(first)
	request, err := http.NewRequest("POST", "https://app.example.org"+webAPI+"logout", strings.NewReader(`{"slug":"Work"}`))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://app.example.org")
	request.Header.Set("Authorization", "Bearer "+one)
	response, err := fixture.client.Do(request)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	_, _, err = first.ReadMessage()
	require.Error(t, err)
	echo(sibling)
	info, err := access.auth.FindSession().Info(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, session.StateDisposed, info.State())
	require.NoError(t, fixture.svc.sessionConnections.revoke(access.auth.Flow(), access.auth.FindSession().Id()))
	_, _, err = sibling.ReadMessage()
	require.Error(t, err)
	requireWebSocketsDrained(t, fixture.svc)
	late = fixture.dial(t)
	require.NoError(t, late.WriteJSON(webSocketOpen(two)))
	require.Equal(t, `"connection-denied"`, string(webSocketStatus(t, late)["code"]))
}

func TestWebSocketFloodsAndInvalidControlsCancelExecution(t *testing.T) {
	fixture := newWebSocketFixture(t, webSocketWaitTask)
	token := fixture.login(t)
	for _, mode := range []string{"oversized", "input queue", "control queue", "fragment flood", "second open", "stdin after eof", "unknown signal", "resize without pty", "duplicate", "unknown field", "null", "non-UTF8"} {
		t.Run(mode, func(t *testing.T) {
			conn := fixture.dial(t)
			require.NoError(t, conn.WriteJSON(webSocketOpen(token)))
			requireWebSocketReady(t, conn)
			var messages [][]byte
			kind := websocket.TextMessage
			switch mode {
			case "oversized":
				kind, messages = websocket.BinaryMessage, [][]byte{bytes.Repeat([]byte{'x'}, webTerminalMessageLimit+1)}
			case "input queue":
				kind = websocket.BinaryMessage
				for range webTerminalInputQueue + 1 {
					messages = append(messages, bytes.Repeat([]byte{'x'}, webTerminalMessageLimit))
				}
			case "control queue":
				for range webTerminalControlQueue + 1 {
					messages = append(messages, []byte(`{"type":"signal","signal":"TERM"}`))
				}
			case "fragment flood":
				// Start one masked binary message followed by empty non-final
				// continuations. A payload-only limit cannot bound this attack.
				require.NoError(t, conn.SetWriteDeadline(time.Now().Add(time.Second)))
				wire := append([]byte{0x02, 0x80, 0, 0, 0, 0}, bytes.Repeat([]byte{0x00, 0x80, 0, 0, 0, 0}, webTerminalWireBytesPerSecond/6+1)...)
				_, _ = conn.NetConn().Write(wire)
			case "second open":
				messages = [][]byte{[]byte(`{"type":"open"}`)}
			case "stdin after eof":
				require.NoError(t, conn.WriteJSON(map[string]string{"type": "eof"}))
				kind, messages = websocket.BinaryMessage, [][]byte{[]byte("too late")}
			case "unknown signal":
				messages = [][]byte{[]byte(`{"type":"signal","signal":"MAGIC"}`)}
			case "resize without pty":
				messages = [][]byte{[]byte(`{"type":"resize","columns":80,"rows":24}`)}
			case "duplicate":
				messages = [][]byte{[]byte(`{"type":"eof","type":"eof"}`)}
			case "unknown field":
				messages = [][]byte{[]byte(`{"type":"eof","sessionId":"other"}`)}
			case "null":
				messages = [][]byte{[]byte(`{"type":null}`)}
			case "non-UTF8":
				messages = [][]byte{{255}}
			}
			for _, message := range messages {
				if conn.WriteMessage(kind, message) != nil {
					break
				}
			}
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
			_, _, err := conn.ReadMessage()
			require.Error(t, err)
			requireWebSocketsDrained(t, fixture.svc)
		})
	}
}

func TestWebSocketSlowReaderHasBoundedWriteAndNoDetachedExecution(t *testing.T) {
	finished := make(chan error, 1)
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		chunk := bytes.Repeat([]byte{'x'}, webTerminalMessageLimit)
		for range 1024 {
			if _, err := task.Terminal().Write(chunk); err != nil {
				finished <- err
				return -1, err
			}
		}
		finished <- nil
		return 0, nil
	})
	fixture.svc.web.terminalTimings = webTerminalTimings{open: time.Second, write: 150 * time.Millisecond, ping: time.Second, pong: 3 * time.Second}
	dial := fixture.dialer.NetDialContext
	fixture.dialer.NetDialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err == nil {
			require.NoError(t, conn.(*net.TCPConn).SetReadBuffer(1024))
		}
		return conn, err
	}
	conn := fixture.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen(fixture.login(t))))
	requireWebSocketReady(t, conn)
	// Deliberately stop reading output and therefore also stop answering pings.
	select {
	case err := <-finished:
		require.Error(t, err)
		var timeout net.Error
		require.ErrorAs(t, err, &timeout)
		require.True(t, timeout.Timeout(), "output must hit its write deadline, not merely the later heartbeat timeout")
	case <-time.After(2 * time.Second):
		t.Fatal("slow reader kept backend output blocked")
	}
	requireWebSocketsDrained(t, fixture.svc)
	require.Len(t, requireAuditEventsNamedEventually(t, fixture.recorder, audit.EventNameSessionTaskCompleted, 1), 1)
}

func TestWebSocketShutdownDrainsOpenAndAuthenticatedSockets(t *testing.T) {
	entered, returned := make(chan struct{}), make(chan struct{})
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		close(entered)
		<-task.Context().Done()
		close(returned)
		return -1, task.Context().Err()
	})
	conn := fixture.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen(fixture.login(t))))
	requireWebSocketReady(t, conn)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("task did not start")
	}
	abandoned := fixture.dial(t)
	require.NoError(t, fixture.svc.environments.(*executionTestRepository).shutdown())
	select {
	case <-returned:
	default:
		t.Fatal("shutdown returned without draining execution")
	}
	for _, socket := range []*websocket.Conn{conn, abandoned} {
		_, _, err := socket.ReadMessage()
		require.Error(t, err)
	}
	requireWebSocketsDrained(t, fixture.svc)
}

func TestWebSocketConnectionBudgetsAreGlobalAndPerDirectPeer(t *testing.T) {
	web := newWebService(nil)
	t.Cleanup(func() { require.NoError(t, web.Close()) })
	var release []func()
	for index := range webTerminalMaximumSockets {
		peer := netip.AddrFrom4([4]byte{192, 0, 2, byte(index/webTerminalMaximumSocketsPerPeer + 1)})
		fn, ok := web.reserveTerminalSocket(peer)
		require.True(t, ok)
		release = append(release, fn)
	}
	_, ok := web.reserveTerminalSocket(netip.MustParseAddr("192.0.2.1"))
	require.False(t, ok)
	_, ok = web.reserveTerminalSocket(netip.MustParseAddr("198.51.100.1"))
	require.False(t, ok)
	for _, fn := range release {
		fn()
	}
	release = nil
	for range webTerminalMaximumSocketsPerPeer {
		fn, ok := web.reserveTerminalSocket(netip.MustParseAddr("192.0.2.1"))
		require.True(t, ok)
		release = append(release, fn)
	}
	_, ok = web.reserveTerminalSocket(netip.MustParseAddr("192.0.2.1"))
	require.False(t, ok, "per-peer limit applies even while global capacity is free")
	other, ok := web.reserveTerminalSocket(netip.MustParseAddr("198.51.100.1"))
	require.True(t, ok)
	other()
	for _, fn := range release {
		fn()
	}
	require.Empty(t, web.socketPeers)
}

func TestWebSocketExecutionErrorIsRedacted(t *testing.T) {
	fixture := newWebSocketFixture(t, func(environment.TerminalTask) (int, error) { return -1, errors.New("secret backend material") })
	conn := fixture.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen(fixture.login(t))))
	requireWebSocketReady(t, conn)
	status := webSocketStatus(t, conn)
	require.Equal(t, `"execution-failed"`, string(status["code"]))
	require.Len(t, status, 2)
}
