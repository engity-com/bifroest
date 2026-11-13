package service

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
	"time"
)

type heldVerificationRepository struct {
	environment.CloseableRepository
	entered chan bool
}

func (r *heldVerificationRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, _ := environment.SessionTargetResolverFor(r.CloseableRepository, ctx.Authorization().Flow())
	return resolver.ResolveSessionTarget(ctx)
}
func (r *heldVerificationRepository) Ensure(req environment.Request) (environment.Environment, error) {
	value, err := r.CloseableRepository.Ensure(req)
	if err != nil {
		return nil, err
	}
	return &heldVerificationEnvironment{Environment: value, entered: r.entered}, nil
}

type heldVerificationEnvironment struct {
	environment.Environment
	entered chan bool
}

func (e *heldVerificationEnvironment) ReadManagement(task environment.TaskContext, request protocol.ReadRequest, output io.Writer) (int, error) {
	if request.Operation == protocol.VerifyRecordings {
		_, deadline := task.Context().Deadline()
		e.entered <- deadline
		if err := reportManagementProgress(task.Context(), "verifying", 0, 10); err != nil {
			return -1, err
		}
		<-task.Context().Done()
		return -1, task.Context().Err()
	}
	return e.Environment.(environment.ManagementReader).ReadManagement(task, request, output)
}
func TestExplicitVerificationDoesNotBlockNormalReadsOrReplaceItsAdmission(t *testing.T) {
	fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
	blocked := &heldVerificationRepository{CloseableRepository: fixture.svc.environments, entered: make(chan bool, 1)}
	fixture.svc.environments = blocked
	token := fixture.login(t)
	socket := managementChannelDial(t, fixture, token)
	requireWebSocketReady(t, socket)
	require.NoError(t, socket.WriteJSON(map[string]any{"type": "request", "requestId": "1", "action": "management/recordings/verify", "fields": map[string]string{"auditlog": "default"}}))
	select {
	case deadline := <-blocked.entered:
		require.False(t, deadline, "the authenticated verification task must not inherit the HTTP bootstrap's old total deadline")
	case <-time.After(2 * time.Second):
		t.Fatal("verification did not start")
	}
	status := webSocketStatus(t, socket)
	require.Equal(t, `"progress"`, string(status["type"]))
	require.Equal(t, `"1"`, string(status["requestId"]))
	code, body := managementChannelRead(t, socket, "2", "flows/list", nil)
	require.Equal(t, 200, code, string(body))
	require.Contains(t, string(body), `"flows"`)
	access := webTestAccess(t, fixture.svc, token, "Work")
	access.mutex.Lock()
	require.Len(t, access.children, 1, "both workers borrow the same admitted channel, not extra quota or a different actor")
	access.mutex.Unlock()
	require.NoError(t, socket.WriteJSON(map[string]string{"type": "cancel", "requestId": "1"}))
	for {
		status = webSocketStatus(t, socket)
		require.Equal(t, `"1"`, string(status["requestId"]))
		if string(status["type"]) == `"canceled"` {
			break
		}
		require.Equal(t, `"response"`, string(status["type"]))
	}
	code, body = managementChannelRead(t, socket, "3", "version/show", map[string]string{"long": "false"})
	require.Equal(t, 200, code, string(body))
}
