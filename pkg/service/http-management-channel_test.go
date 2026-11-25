package service

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type cancelManagementChannelRepository struct {
	environment.CloseableRepository
	entered  chan struct{}
	canceled chan struct{}
}

func (this *cancelManagementChannelRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, _ := environment.SessionTargetResolverFor(this.CloseableRepository, ctx.Authorization().Flow())
	return resolver.ResolveSessionTarget(ctx)
}
func (this *cancelManagementChannelRepository) Ensure(request environment.Request) (environment.Environment, error) {
	value, err := this.CloseableRepository.Ensure(request)
	if err != nil {
		return nil, err
	}
	return &cancelManagementChannelEnvironment{Environment: value, entered: this.entered, canceled: this.canceled}, nil
}

type cancelManagementChannelEnvironment struct {
	environment.Environment
	entered  chan struct{}
	canceled chan struct{}
}

func (this *cancelManagementChannelEnvironment) ReadManagement(task environment.TaskContext, request protocol.ReadRequest, output io.Writer) (int, error) {
	if request.Operation != protocol.ListFlows {
		return this.Environment.(environment.ManagementReader).ReadManagement(task, request, output)
	}
	close(this.entered)
	<-task.Context().Done()
	close(this.canceled)
	return -1, task.Context().Err()
}

func TestManagementChannelCancellationDoesNotCloseOrReplaceItsAdmission(t *testing.T) {
	fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	blocked := &cancelManagementChannelRepository{CloseableRepository: fixture.svc.environments, entered: make(chan struct{}), canceled: make(chan struct{})}
	fixture.svc.environments = blocked
	socket := managementChannelDial(t, fixture, fixture.login(t))
	requireWebSocketReady(t, socket)
	require.NoError(t, socket.WriteJSON(map[string]any{"type": "request", "requestId": "1", "action": "management/flows/list", "fields": map[string]string{}}))
	select {
	case <-blocked.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("management read did not start")
	}
	completion := newManagementChannelTestCompletion(t, socket)
	require.NoError(t, socket.WriteJSON(map[string]string{"type": "cancel", "requestId": "1"}))
	completion.waitFor(t, blocked.canceled, "backend cancellation")
	for {
		kind, data := completion.read(t)
		require.Equal(t, websocket.TextMessage, kind)
		var status map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(data, &status))
		require.Equal(t, `"1"`, string(status["requestId"]))
		if string(status["type"]) == `"canceled"` {
			break
		}
		require.Equal(t, `"response"`, string(status["type"]))
	}
	code, data := managementChannelRead(t, socket, "2", "version/show", map[string]string{"long": "false"})
	require.Equal(t, 200, code, string(data))
	require.Contains(t, string(data), `"detail":"short"`)
}

type managementChannelTestCompletion struct {
	socket   *websocket.Conn
	deadline time.Time
	frames   []string
}

func newManagementChannelTestCompletion(t *testing.T, socket *websocket.Conn) *managementChannelTestCompletion {
	t.Helper()
	result := &managementChannelTestCompletion{socket: socket, deadline: time.Now().Add(15 * time.Second)}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("management completion frames (last 16, metadata only): %v", result.frames)
			stack := make([]byte, 256<<10)
			stack = stack[:runtime.Stack(stack, true)]
			t.Logf("management completion goroutines:\n%s", stack)
		}
	})
	// Bound the entire cancellation/finalization phase independently of prior
	// status reads. Progress frames must not extend this overall deadline.
	require.NoError(t, socket.SetReadDeadline(result.deadline))
	return result
}

func (this *managementChannelTestCompletion) waitFor(t *testing.T, done <-chan struct{}, phase string) {
	t.Helper()
	timer := time.NewTimer(time.Until(this.deadline))
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		t.Fatalf("management completion timed out waiting for %s", phase)
	}
}

func (this *managementChannelTestCompletion) read(t *testing.T) (int, []byte) {
	t.Helper()
	kind, data, err := this.socket.ReadMessage()
	require.NoError(t, err, "waiting for management finalization")
	description := fmt.Sprintf("kind=%d bytes=%d", kind, len(data))
	if kind == websocket.TextMessage {
		var status struct {
			Type      string `json:"type"`
			RequestID string `json:"requestId"`
			Phase     string `json:"phase"`
			Status    int    `json:"status"`
		}
		if json.Unmarshal(data, &status) == nil {
			description += fmt.Sprintf(" type=%q requestId=%q phase=%q status=%d", status.Type, status.RequestID, status.Phase, status.Status)
		}
	}
	this.frames = append(this.frames, description)
	if len(this.frames) > 16 {
		this.frames = this.frames[len(this.frames)-16:]
	}
	return kind, data
}

func managementChannelDial(t *testing.T, fixture *webSocketFixture, token string, progress ...bool) *websocket.Conn {
	t.Helper()
	dialer := fixture.dialer
	dialer.Subprotocols = []string{webManagementProtocol}
	socket, response, err := dialer.Dial("wss://app.example.org"+webAPI+"management/channel", http.Header{"Origin": []string{"https://app.example.org"}})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	fields := map[string]string{"type": "open", "accessToken": token, "slug": "Work"}
	if len(progress) == 0 || progress[0] {
		fields["progress"] = "counts-v1"
	}
	require.NoError(t, socket.WriteJSON(fields))
	return socket
}
func managementChannelRead(t *testing.T, socket *websocket.Conn, id, action string, fields map[string]string) (int, []byte) {
	t.Helper()
	if fields == nil {
		fields = map[string]string{}
	}
	require.NoError(t, socket.WriteJSON(map[string]any{"type": "request", "requestId": id, "action": "management/" + action, "fields": fields}))
	status := webSocketStatus(t, socket)
	require.Equal(t, `"response"`, string(status["type"]))
	require.Equal(t, `"`+id+`"`, string(status["requestId"]))
	var code int
	require.NoError(t, json.Unmarshal(status["status"], &code))
	var result []byte
	for {
		kind, data, err := socket.ReadMessage()
		require.NoError(t, err)
		if kind == websocket.TextMessage {
			var end map[string]string
			require.NoError(t, json.Unmarshal(data, &end))
			require.Equal(t, map[string]string{"type": "complete", "requestId": id}, end)
			return code, result
		}
		require.Equal(t, websocket.BinaryMessage, kind)
		require.Greater(t, len(data), 8)
		require.Equal(t, id, jsonNumberID(binary.BigEndian.Uint64(data[:8])))
		result = append(result, data[8:]...)
	}
}
func jsonNumberID(value uint64) string { raw, _ := json.Marshal(value); return string(raw) }

func TestManagementChannelKeepsOneAdmissionAfterBearerExpiryWithoutStartingShell(t *testing.T) {
	fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).RemoteName = template.MustNewString(`{{if eq .connection.transport "http"}}alice{{else}}unmapped-ssh-principal{{end}}`)
		conf.Flows[0].Http.KeepAlive = template.MustNewEnforceable[template.Duration](`{{if eq .connection.transport "http"}}{{if eq .connection.http.slug "Work"}}15s{{else}}invalid-slug{{end}}{{else}}invalid-transport{{end}}`)
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
	token := fixture.login(t)
	socket := managementChannelDial(t, fixture, token)
	requireWebSocketReady(t, socket)
	require.Empty(t, auditEventsNamed(fixture.recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted), "opening management is not a shell/task")
	access := webTestAccess(t, fixture.svc, token, "Work")
	access.mutex.Lock()
	expires := time.Now().Add(-time.Second)
	access.expires = expires
	access.mutex.Unlock()
	code, data := managementChannelRead(t, socket, "1", "flows/list", nil)
	require.Equal(t, 200, code, string(data))
	require.Contains(t, string(data), `"environment":"management"`)
	code, data = managementChannelRead(t, socket, "2", "sessions/list", map[string]string{"state": "all"})
	require.Equal(t, 200, code, string(data))
	access.mutex.Lock()
	require.Equal(t, expires, access.expires)
	require.Len(t, access.children, 1, "operations borrow the one admitted channel, not extra quota slots")
	access.mutex.Unlock()
	response := webTestRequest(fixture.svc.web, "POST", "app.example.org", webAPI+"management/flows/list", `{"slug":"Work"}`, token)
	require.Equal(t, 401, response.Code, "the expired bearer never authorizes a fresh HTTP operation")
	other := managementChannelDial(t, fixture, token)
	status := webSocketStatus(t, other)
	require.Equal(t, `"error"`, string(status["type"]))
	require.Len(t, auditEventsNamed(fixture.recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted), 2)
	request, err := http.NewRequest("POST", "https://app.example.org"+webAPI+"logout", strings.NewReader(`{"slug":"Work"}`))
	require.NoError(t, err)
	request.Header.Set("Origin", "https://app.example.org")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	result, err := fixture.client.Do(request)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, result.Body)
	_ = result.Body.Close()
	require.Equal(t, 204, result.StatusCode)
	_, _, err = socket.ReadMessage()
	require.Error(t, err, "own logout closes the admitted channel")
}

func TestManagementChannelRejectsTerminalControlsAndOtherOrigins(t *testing.T) {
	for _, control := range []string{`{"type":"eof","requestId":"1"}`, `{"type":"request","requestId":"1","action":"login/password","fields":{}}`, `{"type":"request","requestId":"1","action":"management/flows/list","fields":{"slug":"other"}}`} {
		t.Run(control, func(t *testing.T) {
			fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
			})
			socket := managementChannelDial(t, fixture, fixture.login(t))
			requireWebSocketReady(t, socket)
			require.NoError(t, socket.WriteMessage(websocket.TextMessage, []byte(control)))
			_, _, err := socket.ReadMessage()
			require.Error(t, err)
			require.Empty(t, auditEventsNamed(fixture.recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted))
		})
	}
}
