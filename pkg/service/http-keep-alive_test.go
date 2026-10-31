package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestWebKeepAliveIsPrivateAndRenderedWithAuthenticatedSession(t *testing.T) {
	_, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Http.KeepAlive = template.MustNewString(`{{if .session}}{{if eq .authentication.principal "alice"}}!10s{{else}}20s{{end}}{{else}}PRIVATE_INVALID{{end}}`)
	})
	discovery := webTestRequest(handler, http.MethodGet, "app.example.org", "/Work", "", "")
	require.NotContains(t, discovery.Body.String(), "keepAlive")
	denied := webTestPassword(handler, "alice", "wrong", "Work")
	require.Equal(t, http.StatusUnauthorized, denied.Code)
	require.NotContains(t, denied.Body.String(), "keepAlive")
	response := webTestPassword(handler, "alice", "correct", "Work")
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var body struct {
		KeepAlive webKeepAlive `json:"keepAlive"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.Equal(t, webKeepAlive{Interval: "10s", Locked: true}, body.KeepAlive)
	require.NotContains(t, response.Body.String(), "PRIVATE_INVALID")
}

func keepAliveTestStream(t *testing.T, fixture *webSocketFixture, token string) *webTerminalStream {
	t.Helper()
	access := webTestAccess(t, fixture.svc, token, "Work")
	access.mutex.Lock()
	children := make([]*terminalConnection, 0, len(access.children))
	for child := range access.children {
		children = append(children, child)
	}
	access.mutex.Unlock()
	require.Len(t, children, 1)
	return children[0].terminalTransport.(*webAccessTransport).terminalTransport.(*webTerminalStream)
}

func TestWebSocketKeepAliveShorteningRequiresRealPongWithoutExtendingOldDeadline(t *testing.T) {
	for _, responds := range []bool{true, false} {
		t.Run(fmt.Sprint(responds), func(t *testing.T) {
			fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
				<-task.Context().Done()
				return -1, task.Context().Err()
			}, func(conf *configuration.Configuration) {
				conf.Flows[0].Http.KeepAlive = template.MustNewString("5m")
			})
			token := fixture.login(t)
			conn := fixture.dial(t)
			require.NoError(t, conn.WriteJSON(webSocketOpen(token)))
			requireWebSocketReady(t, conn)
			stream := keepAliveTestStream(t, fixture, token)
			// Reproduce a long interval's silent first minute without sleeping a
			// minute. The new 45s window would already be in the past.
			stream.pingMutex.Lock()
			stream.lastPong = time.Now().Add(-time.Minute)
			stream.pingMutex.Unlock()
			if !responds {
				require.NoError(t, stream.socket.SetReadDeadline(time.Now().Add(250*time.Millisecond)))
			}
			pings := 0
			conn.SetPingHandler(func(nonce string) error {
				pings++
				if !responds {
					return nil
				}
				return conn.WriteControl(websocket.PongMessage, []byte(nonce), time.Now().Add(time.Second))
			})
			start := time.Now()
			require.NoError(t, conn.WriteJSON(map[string]string{"type": "keepalive", "interval": "1s", "requestId": "1"}))
			if responds {
				ack := webSocketStatus(t, conn)
				require.Equal(t, `"keepalive"`, string(ack["type"]))
				require.GreaterOrEqual(t, pings, 1, "an actual matched nonce proves liveness before shortening")
				stream.pingMutex.Lock()
				interval := stream.pingInterval
				stream.pingMutex.Unlock()
				require.Equal(t, time.Second, interval)
			} else {
				_, _, err := conn.ReadMessage()
				require.Error(t, err)
				require.GreaterOrEqual(t, pings, 1)
				require.Less(t, time.Since(start), time.Second, "a settings request cannot extend an unproven peer's previous deadline")
			}
		})
	}
}

func TestWebSocketKeepAliveReevaluatesLockedFlowAndUsesNoNewExecution(t *testing.T) {
	var executions atomic.Int32
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		executions.Add(1)
		<-task.Context().Done()
		return -1, task.Context().Err()
	})
	token := fixture.login(t)
	// Change after authentication: a historical editable UI policy is not an
	// authority to override the current authenticated flow policy.
	fixture.svc.Configuration.Flows[0].Http.KeepAlive = template.MustNewString("!10s")
	conn := fixture.dial(t)
	open := webSocketOpen(token)
	open["keepAlive"] = "1s"
	require.NoError(t, conn.WriteJSON(open))
	ready := webSocketStatus(t, conn)
	require.Equal(t, `"ready"`, string(ready["type"]))
	var policy webKeepAlive
	require.NoError(t, json.Unmarshal(ready["keepAlive"], &policy))
	require.Equal(t, webKeepAlive{Interval: "10s", Locked: true}, policy)
	require.NoError(t, conn.WriteJSON(map[string]string{"type": "keepalive", "interval": "1s", "requestId": "1"}))
	ack := webSocketStatus(t, conn)
	require.Equal(t, `"keepalive"`, string(ack["type"]))
	require.Equal(t, `"1"`, string(ack["requestId"]))
	require.NoError(t, json.Unmarshal(ack["keepAlive"], &policy))
	require.Equal(t, webKeepAlive{Interval: "10s", Locked: true}, policy)
	access := webTestAccess(t, fixture.svc, token, "Work")
	access.mutex.Lock()
	children := make([]*terminalConnection, 0, len(access.children))
	for current := range access.children {
		children = append(children, current)
	}
	access.mutex.Unlock()
	require.Len(t, children, 1)
	child := children[0]
	stream := child.terminalTransport.(*webAccessTransport).terminalTransport.(*webTerminalStream)
	stream.pingMutex.Lock()
	ping, pong := stream.pingInterval, stream.pongInterval
	stream.pingMutex.Unlock()
	require.Equal(t, 10*time.Second, ping)
	require.Equal(t, 45*time.Second, pong)
	require.Eventually(t, func() bool { return executions.Load() == 1 }, time.Second, time.Millisecond)
}

func TestWebSocketKeepAliveSettingsNeverRenewSessionIdle(t *testing.T) {
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		<-task.Context().Done()
		return -1, task.Context().Err()
	}, func(conf *configuration.Configuration) {
		conf.Session.V.(*configuration.SessionFs).IdleTimeout = common.DurationOf(600 * time.Millisecond)
	})
	conn := fixture.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen(fixture.login(t))))
	requireWebSocketReady(t, conn)
	ctx, stop := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for id := 1; ; id++ {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if conn.WriteJSON(map[string]string{"type": "keepalive", "interval": "1s", "requestId": fmt.Sprint(id)}) != nil {
					return
				}
			}
		}
	}()
	defer func() { stop(); <-done }()
	start := time.Now()
	acks := 0
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var reply struct {
			Type string `json:"type"`
		}
		require.NoError(t, json.Unmarshal(data, &reply))
		if reply.Type == "keepalive" {
			acks++
		}
	}
	require.Greater(t, acks, 2)
	require.Less(t, time.Since(start), 1400*time.Millisecond, "settings and pongs are not user activity")
}
