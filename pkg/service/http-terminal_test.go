package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/terminal"
)

type webSocketFixture struct {
	svc      *service
	root     string
	recorder *recordingAuditRecorder
	client   *http.Client
	dialer   websocket.Dialer
}

// A small real TCP send buffer makes backpressure reproducible without writing
// megabytes of recordings merely to exhaust a host-dependent socket buffer.
type webSocketTestListener struct{ net.Listener }

func (this webSocketTestListener) Accept() (net.Conn, error) {
	conn, err := this.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if err := conn.(*net.TCPConn).SetWriteBuffer(16 << 10); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func newWebSocketFixture(t *testing.T, run func(environment.TerminalTask) (int, error), configure ...func(*configuration.Configuration)) *webSocketFixture {
	t.Helper()
	var certificate *x509.Certificate
	setup := func(conf *configuration.Configuration) {
		conf.Http = &configuration.Http{}
		require.NoError(t, conf.Http.SetDefaults())
		conf.Http.Enabled = true
		conf.Http.Domains = configuration.HttpDomains{"app.example.org", "other.example.org"}
		conf.Http.GracefulShutdownTimeout = common.DurationOf(100 * time.Millisecond)
		certificate = httpListenerTestCertificate(t, conf, nil)
		for _, fn := range configure {
			fn(conf)
		}
	}
	svc, recorder, root := executionTestFixture(t, run, setup)
	if run == nil {
		svc.environments = svc.environments.(*executionTestRepository).CloseableRepository
	}
	require.NoError(t, svc.https.Prepare(t.Context()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- svc.https.Serve(webSocketTestListener{listener}) }()
	t.Cleanup(func() {
		require.NoError(t, svc.https.Close())
		select {
		case err := <-done:
			require.ErrorIs(t, err, http.ErrServerClosed)
		case <-time.After(2 * time.Second):
			t.Error("HTTPS did not stop")
		}
	})
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, DialContext: dial}
	t.Cleanup(transport.CloseIdleConnections)
	return &webSocketFixture{svc: svc, root: root, recorder: recorder, client: &http.Client{Transport: transport, Timeout: 3 * time.Second}, dialer: websocket.Dialer{NetDialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, Subprotocols: []string{webTerminalProtocol}, HandshakeTimeout: 2 * time.Second}}
}

func (this *webSocketFixture) login(t *testing.T) string {
	t.Helper()
	request, err := http.NewRequest("POST", "https://app.example.org"+webAPI+"login/password", strings.NewReader(`{"slug":"Work","user":"alice","password":"correct"}`))
	require.NoError(t, err)
	request.Header.Set("Origin", "https://app.example.org")
	request.Header.Set("Content-Type", "application/json")
	response, err := this.client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode, string(data))
	var value struct {
		Token string `json:"accessToken"`
	}
	require.NoError(t, json.Unmarshal(data, &value))
	require.NotEmpty(t, value.Token)
	return value.Token
}
func (this *webSocketFixture) dial(t *testing.T) *websocket.Conn {
	t.Helper()
	conn, response, err := this.dialer.Dial("wss://app.example.org"+webAPI+"terminal", http.Header{"Origin": []string{"https://app.example.org"}})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.Equal(t, webTerminalProtocol, conn.Subprotocol())
	return conn
}
func webSocketOpen(token string) map[string]any {
	return map[string]any{"type": "open", "slug": "Work", "accessToken": token, "task": "exec", "command": "run"}
}
func webSocketStatus(t *testing.T, conn *websocket.Conn) map[string]json.RawMessage {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	kind, data, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, websocket.TextMessage, kind, string(data))
	var value map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &value))
	return value
}
func requireWebSocketReady(t *testing.T, conn *websocket.Conn) {
	t.Helper()
	value := webSocketStatus(t, conn)
	require.Equal(t, `"ready"`, string(value["type"]), "%s", value)
	require.NotEmpty(t, value["connectionId"])
}
func webSocketResult(t *testing.T, conn *websocket.Conn) ([]byte, []byte, map[string]json.RawMessage) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	for {
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
		kind, data, err := conn.ReadMessage()
		require.NoError(t, err)
		if kind == websocket.TextMessage {
			var status map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(data, &status))
			return stdout.Bytes(), stderr.Bytes(), status
		}
		require.Equal(t, websocket.BinaryMessage, kind)
		require.NotEmpty(t, data)
		switch data[0] {
		case 0:
			_, _ = stdout.Write(data[1:])
		case 1:
			_, _ = stderr.Write(data[1:])
		default:
			t.Fatalf("unknown output channel %d", data[0])
		}
	}
}

func TestWebSocketExecutionUsesSharedDriverRecordingAndInputHalfClose(t *testing.T) {
	executions := make(chan environment.TerminalTask, 1)
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		executions <- task
		if _, legacy := task.(environment.Task); legacy {
			return -1, errors.New("unexpected SSH source task")
		}
		data, err := io.ReadAll(task.Terminal())
		if err != nil {
			return -1, err
		}
		if err := task.Context().Err(); err != nil {
			return -1, err
		}
		if _, err := task.Terminal().Write(append([]byte("after EOF:"), data...)); err != nil {
			return -1, err
		}
		if _, err := io.WriteString(task.Terminal().Stderr(), "separate stderr"); err != nil {
			return -1, err
		}
		return 7, nil
	})
	token := fixture.login(t)
	conn := fixture.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen(token)))
	requireWebSocketReady(t, conn)
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, []byte{0, 1, 2, 255, 'x'}))
	require.NoError(t, conn.WriteJSON(map[string]string{"type": "eof"}))
	stdout, stderr, status := webSocketResult(t, conn)
	require.Equal(t, append([]byte("after EOF:"), 0, 1, 2, 255, 'x'), stdout)
	require.Equal(t, "separate stderr", string(stderr))
	require.Equal(t, `"exit"`, string(status["type"]))
	require.Equal(t, "7", string(status["status"]))
	verification := verifyOnlySessionRecording(t, fixture.svc, fixture.root)
	require.Equal(t, recording.CastStatusCompleted, verification.Cast.Result.Status)
	require.Equal(t, uint32(7), *verification.Cast.ExitStatus)
	require.Equal(t, (<-executions).Connection().Id(), verification.Cast.Metadata.ConnectionId)
	events := fixture.recorder.eventsSnapshot()
	started := auditEventsNamed(events, audit.EventNameSessionRecordingStarted)
	completed := auditEventsNamed(events, audit.EventNameSessionRecordingCompleted)
	require.Len(t, started, 1)
	require.Len(t, completed, 1)
	requireSessionRecordingAuditCorrelation(t, verification, started[0], completed[0])
	_, _, err := conn.ReadMessage()
	require.True(t, websocket.IsCloseError(err, websocket.CloseNormalClosure), "exit status must precede normal close: %v", err)
}

func TestWebSocketNewConnectionStartsNewExecutionInOneSession(t *testing.T) {
	var calls atomic.Int32
	var mutex sync.Mutex
	var sessions []session.Id
	var connections []string
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		calls.Add(1)
		mutex.Lock()
		sessions = append(sessions, task.Authorization().FindSession().Id())
		connections = append(connections, task.Connection().Id().String())
		mutex.Unlock()
		_, err := io.WriteString(task.Terminal(), "fresh execution")
		return 0, err
	})
	token := fixture.login(t)
	for range 2 {
		conn := fixture.dial(t)
		require.NoError(t, conn.WriteJSON(webSocketOpen(token)))
		requireWebSocketReady(t, conn)
		stdout, _, status := webSocketResult(t, conn)
		require.Equal(t, "fresh execution", string(stdout))
		require.Equal(t, `"exit"`, string(status["type"]))
		_ = conn.Close()
	}
	require.EqualValues(t, 2, calls.Load())
	mutex.Lock()
	require.Equal(t, sessions[0], sessions[1])
	require.NotEqual(t, connections[0], connections[1])
	mutex.Unlock()
	ids, err := fixture.svc.recordingRepositories[fixture.svc.Configuration.Auditlogs[0].Name].native.ListSealed(t.Context())
	require.NoError(t, err)
	require.Len(t, ids, 2)
}

func TestWebSocketResizeAndSymbolicSignalShareCaptureAndPolicies(t *testing.T) {
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		pty, windows, hasPty := task.Terminal().Pty()
		if !hasPty || pty.Window.Width != 80 {
			return -1, errors.New("missing initial PTY")
		}
		signals := make(chan terminal.Signal, 1)
		task.Terminal().Signals(signals)
		defer task.Terminal().Signals(nil)
		resized, signaled := false, false
		for !resized || !signaled {
			select {
			case window := <-windows:
				resized = resized || window.Width == 100
			case signal := <-signals:
				signaled = signal == "TERM"
			case <-task.Context().Done():
				return -1, task.Context().Err()
			}
		}
		_, err := io.WriteString(task.Terminal(), "resized\n")
		return 0, err
	})
	conn := fixture.dial(t)
	open := webSocketOpen(fixture.login(t))
	open["pty"] = map[string]any{"term": "xterm-256color", "columns": 80, "rows": 24}
	require.NoError(t, conn.WriteJSON(open))
	requireWebSocketReady(t, conn)
	require.NoError(t, conn.WriteJSON(map[string]any{"type": "resize", "columns": 90, "rows": 30}))
	require.NoError(t, conn.WriteJSON(map[string]any{"type": "resize", "columns": 100, "rows": 40}))
	require.NoError(t, conn.WriteJSON(map[string]string{"type": "signal", "signal": "SIGTERM"}))
	stdout, _, status := webSocketResult(t, conn)
	require.Equal(t, "resized\n", string(stdout), "the transport preserves backend bytes; recording normalization is separate")
	require.Equal(t, `"exit"`, string(status["type"]))
	verification := verifyOnlySessionRecording(t, fixture.svc, fixture.root)
	require.True(t, verification.Cast.Metadata.Pty)
	require.EqualValues(t, 2, verification.Cast.ResizeEvents)
}

func TestWebSocketOriginAndQueryBoundaryPrecedeUpgrade(t *testing.T) {
	fixture := newWebSocketFixture(t, func(environment.TerminalTask) (int, error) { t.Error("unexpected run"); return 0, nil })
	for _, test := range []struct {
		origin, path string
		status       int
	}{{"", webAPI + "terminal", 403}, {"https://other.example.org", webAPI + "terminal", 403}, {"https://app.example.org:444", webAPI + "terminal", 403}, {"https://app.example.org", webAPI + "terminal?accessToken=secret", 400}} {
		header := http.Header{}
		if test.origin != "" {
			header.Set("Origin", test.origin)
		}
		conn, response, err := fixture.dialer.Dial("wss://app.example.org"+test.path, header)
		if conn != nil {
			_ = conn.Close()
		}
		require.Error(t, err)
		require.NotNil(t, response)
		_ = response.Body.Close()
		require.Equal(t, test.status, response.StatusCode)
	}
	require.Zero(t, webSessionCount(t, fixture.svc))
}

func TestWebSocketInvalidProofNeverRegistersOrRuns(t *testing.T) {
	var calls atomic.Int32
	fixture := newWebSocketFixture(t, func(environment.TerminalTask) (int, error) { calls.Add(1); return 0, nil })
	token := fixture.login(t)
	access := webTestAccess(t, fixture.svc, token, "Work")
	for _, proof := range []string{"", access.auth.FindSession().Id().String(), "bwl1." + strings.Repeat("x", 43)} {
		conn := fixture.dial(t)
		require.NoError(t, conn.WriteJSON(webSocketOpen(proof)))
		status := webSocketStatus(t, conn)
		require.Equal(t, `"error"`, string(status["type"]))
		_ = conn.Close()
	}
	require.Zero(t, calls.Load())
	require.Empty(t, auditEventsNamed(fixture.recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted))
}

func TestWebSocketProofScopeCannotChangeOriginPortOrSlug(t *testing.T) {
	fixture := newWebSocketFixture(t, func(environment.TerminalTask) (int, error) { t.Error("scope mismatch ran task"); return 0, nil })
	token := fixture.login(t)
	for _, scope := range []struct{ authority, slug string }{{"other.example.org", "Work"}, {"app.example.org:444", "Work"}, {"app.example.org", "Other"}} {
		conn, response, err := fixture.dialer.Dial("wss://"+scope.authority+webAPI+"terminal", http.Header{"Origin": []string{"https://" + scope.authority}})
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		open := webSocketOpen(token)
		open["slug"] = scope.slug
		require.NoError(t, conn.WriteJSON(open))
		require.Equal(t, `"authentication-denied"`, string(webSocketStatus(t, conn)["code"]))
	}
	require.Empty(t, auditEventsNamed(fixture.recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted))
}

func TestWebSocketHeartbeatDoesNotRenewSessionIdle(t *testing.T) {
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		<-task.Context().Done()
		return -1, task.Context().Err()
	}, func(conf *configuration.Configuration) {
		conf.Session.V.(*configuration.SessionFs).IdleTimeout = common.DurationOf(600 * time.Millisecond)
	})
	fixture.svc.web.terminalTimings = webTerminalTimings{open: time.Second, write: time.Second, ping: 50 * time.Millisecond, pong: 400 * time.Millisecond}
	conn := fixture.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen(fixture.login(t))))
	requireWebSocketReady(t, conn)
	pings := 0
	conn.SetPingHandler(func(payload string) error {
		pings++
		return conn.WriteControl(websocket.PongMessage, []byte(payload), time.Now().Add(time.Second))
	})
	start := time.Now()
	_, _, err := conn.ReadMessage()
	require.Error(t, err)
	require.Less(t, time.Since(start), 2*time.Second)
	require.GreaterOrEqual(t, pings, 2, "valid pongs keep transport alive while the session becomes idle")
	require.Eventually(t, func() bool {
		fixture.svc.web.mutex.Lock()
		defer fixture.svc.web.mutex.Unlock()
		return fixture.svc.web.sockets == 0
	}, time.Second, 10*time.Millisecond)
	verification := verifyOnlySessionRecording(t, fixture.svc, fixture.root)
	require.Equal(t, recording.CastStatusIncomplete, verification.Cast.Result.Status)
}

func TestWebSocketMissingPongAndAbandonedOpenAreClosed(t *testing.T) {
	for _, mode := range []string{"open timeout", "missing pong", "wrong pong"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
				<-task.Context().Done()
				return -1, task.Context().Err()
			})
			fixture.svc.web.terminalTimings = webTerminalTimings{open: 100 * time.Millisecond, write: time.Second, ping: 50 * time.Millisecond, pong: 250 * time.Millisecond}
			var token string
			if mode != "open timeout" {
				token = fixture.login(t)
			}
			conn := fixture.dial(t)
			if mode != "open timeout" {
				require.NoError(t, conn.WriteJSON(webSocketOpen(token)))
				requireWebSocketReady(t, conn)
				conn.SetPingHandler(func(string) error { return nil })
				if mode == "wrong pong" {
					conn.SetPingHandler(func(string) error {
						return conn.WriteControl(websocket.PongMessage, []byte("not-the-ping-nonce"), time.Now().Add(time.Second))
					})
				}
			}
			_, _, err := conn.ReadMessage()
			if mode == "open timeout" && err == nil {
				_, _, err = conn.ReadMessage()
			}
			require.Error(t, err)
			require.Eventually(t, func() bool {
				fixture.svc.web.mutex.Lock()
				defer fixture.svc.web.mutex.Unlock()
				return fixture.svc.web.sockets == 0
			}, 2*time.Second, 10*time.Millisecond)
		})
	}
}

func TestWebSocketStrictRecordingFailureCannotReportSuccessfulExit(t *testing.T) {
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		task.Terminal().(*recordedTerminal).sink = &captureTestSink{outputErr: errors.New("private capture failure")}
		_, err := io.WriteString(task.Terminal(), "must not arrive")
		return -1, err
	})
	conn := fixture.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen(fixture.login(t))))
	requireWebSocketReady(t, conn)
	_, data, err := conn.ReadMessage()
	require.Error(t, err)
	require.NotContains(t, string(data), "must not arrive")
	require.NotContains(t, string(data), "private capture failure")
	require.Eventually(t, func() bool {
		files, _ := filepath.Glob(filepath.Join(fixture.root, "recordings", "sealed", "*.bcast"))
		return len(files) == 1
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, recording.CastStatusFailed, verifyOnlySessionRecording(t, fixture.svc, fixture.root).Cast.Result.Status)
}

func TestRealWebSocketAndSshExecuteAgainstOnePersistentSession(t *testing.T) {
	fixture := newWebSocketFixture(t, nil) // Real built-in Dummy backend, no task replacement.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- fixture.svc.server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SSH did not stop")
		}
	})
	client, err := gossh.Dial("tcp", listener.Addr().String(), &gossh.ClientConfig{
		User: "alice", Auth: []gossh.AuthMethod{gossh.Password("correct")}, Timeout: 3 * time.Second,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // Test-local server.
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.Run("first"))
	token := fixture.login(t)
	for range 2 {
		conn := fixture.dial(t)
		require.NoError(t, conn.WriteJSON(webSocketOpen(token)))
		requireWebSocketReady(t, conn)
		_, _, status := webSocketResult(t, conn)
		require.Equal(t, `"exit"`, string(status["type"]))
		require.Equal(t, "0", string(status["status"]))
	}
	require.Equal(t, 1, webSessionCount(t, fixture.svc))
	completed := requireAuditEventsNamedEventually(t, fixture.recorder, audit.EventNameSessionTaskCompleted, 3)
	for _, event := range completed {
		require.Equal(t, completed[0].SessionId, event.SessionId)
	}
	require.NotEqual(t, completed[0].ConnectionId, completed[1].ConnectionId)
	require.NotEqual(t, completed[1].ConnectionId, completed[2].ConnectionId)
}

func TestWebSocketManagementFlowCannotUseTerminalOrCliWorkaround(t *testing.T) {
	fixture := newWebSocketFixture(t, func(environment.TerminalTask) (int, error) {
		t.Error("management cannot run terminal tasks")
		return 0, nil
	}, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	conn := fixture.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen(fixture.login(t))))
	require.Equal(t, `"terminal-unavailable"`, string(webSocketStatus(t, conn)["code"]))
	require.Empty(t, auditEventsNamed(fixture.recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted))
}
