package service

import (
	"context"
	"errors"
	gonet "net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
)

type managementControlTestTask struct {
	environment.Task
	caller session.Session
	conn   bconn.Connection
}

func (this managementControlTestTask) Authorization() authorization.Authorization {
	return managementControlTestAuthorization{caller: this.caller}
}

func (this managementControlTestTask) Connection() bconn.Connection { return this.conn }

type managementControlTestAuthorization struct {
	authorization.Authorization
	caller session.Session
}

func (this managementControlTestAuthorization) FindSession() session.Session { return this.caller }

type managementControlTestConnection struct{ bconn.Connection }

func (managementControlTestConnection) Id() bconn.Id {
	return bconn.Id{1}
}

func newManagementSessionControlTest(t *testing.T) (managementSessionControl, *houseKeeperTestSession, *recordingAuditRecorder) {
	t.Helper()
	target := &houseKeeperTestSession{flow: "current", id: session.MustNewId()}
	repository := &houseKeeperTestSessionRepository{
		findAll: func(ctx context.Context, consume session.Consumer, _ *session.FindOpts) error {
			_, err := consume(ctx, target)
			return err
		},
	}
	hk := newHouseKeeperForTest(repository, &houseKeeperTestAuthorizer{restoreErr: authorization.ErrNoSuchAuthorization})
	hk.service.houseKeeper.service = hk.service
	recorder := &recordingAuditRecorder{}
	hk.service.flowAuditRecorders["current"] = recorder
	hk.service.flowAuditRecorders["administration"] = &recordingAuditRecorder{}
	task := managementControlTestTask{
		caller: &houseKeeperTestSession{flow: "administration", id: session.MustNewId()},
		conn:   managementControlTestConnection{},
	}
	return managementSessionControl{service: hk.service, task: task}, target, recorder
}

func TestManagementSessionDisconnectPreservesSessionAndAllowsNewConnections(t *testing.T) {
	control, target, recorder := newManagementSessionControlTest(t)
	conn := newTrackedSessionConnection(t, control.service)
	control.service.sessionConnections.track(conn, target)
	result, err := control.Disconnect(t.Context(), target.id)
	require.NoError(t, err)
	require.Equal(t, "disconnect", result.Action)
	require.True(t, conn.closed.Load())
	require.Zero(t, target.disposeCalls)
	require.Zero(t, control.service.environments.(*houseKeeperTestEnvironmentRepository).findCalls)
	require.Zero(t, control.service.authorizer.(*houseKeeperTestAuthorizer).restoreCalls)
	late := newTrackedSessionConnection(t, control.service)
	control.service.sessionConnections.track(late, target)
	require.False(t, late.closed.Load())
	require.NoError(t, late.Close())
	for _, events := range [][]audit.Event{recorder.eventsSnapshot(), control.service.flowAuditRecorders["administration"].(*recordingAuditRecorder).eventsSnapshot()} {
		require.Len(t, events, 2)
		require.Equal(t, audit.EventNameSessionDisconnectStarted, events[0].Name)
		require.Equal(t, audit.EventNameSessionDisconnectCompleted, events[1].Name)
		require.Equal(t, target.id.String(), events[0].SessionId)
		require.Equal(t, "current", events[0].Flow)
		require.NotEmpty(t, events[0].ConnectionId)
		require.Equal(t, events[0].OperationId, events[1].OperationId)
		require.Equal(t, audit.EventOutcomeSuccess, events[1].Outcome)
	}
}

func TestManagementSessionDisposeUsesLifecycleAndRejectsLateConnections(t *testing.T) {
	for _, failure := range []string{"none", "persist", "environment", "authorization"} {
		t.Run(failure, func(t *testing.T) {
			control, target, recorder := newManagementSessionControlTest(t)
			env := &houseKeeperTestEnvironment{}
			control.service.environments.(*houseKeeperTestEnvironmentRepository).findResult = env
			sentinel := errors.New("injected failure")
			switch failure {
			case "persist":
				target.disposeErr = sentinel
			case "environment":
				env.disposeErr = sentinel
			case "authorization":
				control.service.authorizer.(*houseKeeperTestAuthorizer).restoreErr = sentinel
			}
			conn := newTrackedSessionConnection(t, control.service)
			control.service.sessionConnections.track(conn, target)
			result, err := control.Dispose(t.Context(), target.id)
			require.Equal(t, "dispose", result.Action)
			if failure == "none" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, sentinel)
			}
			require.True(t, conn.closed.Load())
			require.Equal(t, 1, target.disposeCalls)
			if failure == "persist" {
				require.Zero(t, env.disposeCalls)
			} else {
				require.Equal(t, 1, env.disposeCalls)
			}
			require.Zero(t, control.service.sessions.(*houseKeeperTestSessionRepository).deleteCalls)
			late := newTrackedSessionConnection(t, control.service)
			control.service.sessionConnections.track(late, target)
			require.True(t, late.closed.Load())
			events := recorder.eventsSnapshot()
			require.Len(t, events, 2)
			require.Equal(t, audit.EventNameSessionDisposeStarted, events[0].Name)
			require.Equal(t, audit.EventNameSessionDisposeCompleted, events[1].Name)
			require.Equal(t, events[0].OperationId, events[1].OperationId)
			if failure == "none" {
				require.Equal(t, audit.EventOutcomeSuccess, events[1].Outcome)
			} else {
				require.Equal(t, audit.EventOutcomeFailure, events[1].Outcome)
			}
		})
	}
}

func TestManagementSessionControlRejectsUnsafeTargetsBeforeMutation(t *testing.T) {
	for _, action := range []string{"disconnect", "dispose"} {
		for _, scenario := range []string{"missing", "ambiguous", "self", "canceled", "scan-error", "audit-error"} {
			t.Run(action+"/"+scenario, func(t *testing.T) {
				control, target, recorder := newManagementSessionControlTest(t)
				conn := newTrackedSessionConnection(t, control.service)
				control.service.sessionConnections.track(conn, target)
				defer func() { require.NoError(t, conn.Close()) }()
				ctx := t.Context()
				id := target.id
				switch scenario {
				case "missing":
					id = session.MustNewId()
				case "ambiguous":
					control.service.sessions.(*houseKeeperTestSessionRepository).findAll = func(ctx context.Context, consume session.Consumer, _ *session.FindOpts) error {
						_, err := consume(ctx, target)
						if err != nil {
							return err
						}
						_, err = consume(ctx, &houseKeeperTestSession{flow: "other", id: id})
						return err
					}
				case "self":
					task := control.task.(managementControlTestTask)
					task.caller = target
					control.task = task
				case "canceled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				case "scan-error":
					control.service.sessions.(*houseKeeperTestSessionRepository).findAll = func(context.Context, session.Consumer, *session.FindOpts) error {
						return errors.New("storage unavailable")
					}
				case "audit-error":
					delete(control.service.flowAuditRecorders, target.flow)
				}
				operation := control.Disconnect
				if action == "dispose" {
					operation = control.Dispose
				}
				_, err := operation(ctx, id)
				require.Error(t, err)
				require.False(t, conn.closed.Load())
				require.Zero(t, target.disposeCalls)
				require.Empty(t, recorder.eventsSnapshot())
			})
		}
	}
}

func TestManagementSessionControlPropagatesCompletionAuditFailure(t *testing.T) {
	for _, dispose := range []bool{false, true} {
		control, target, recorder := newManagementSessionControlTest(t)
		name := audit.EventNameSessionDisconnectCompleted
		operation := control.Disconnect
		if dispose {
			name = audit.EventNameSessionDisposeCompleted
			operation = control.Dispose
		}
		sentinel := errors.New("audit storage failed")
		recorder.setErrorForName(name, sentinel)
		conn := newTrackedSessionConnection(t, control.service)
		control.service.sessionConnections.track(conn, target)
		_, err := operation(t.Context(), target.id)
		require.ErrorIs(t, err, sentinel)
		require.True(t, conn.closed.Load())
		require.Equal(t, dispose, target.disposeCalls > 0)
		// A failure in one log must not prevent the other completion attempt.
		events := control.service.flowAuditRecorders["administration"].(*recordingAuditRecorder).eventsSnapshot()
		require.Len(t, events, 2)
		require.Equal(t, name, events[1].Name)
	}
}

type managementErrorCloseConn struct {
	gonet.Conn
	err error
}

func (this managementErrorCloseConn) Close() error {
	return errors.Join(this.Conn.Close(), this.err)
}

func TestManagementSessionControlPropagatesDisconnectErrors(t *testing.T) {
	for _, dispose := range []bool{false, true} {
		control, target, recorder := newManagementSessionControlTest(t)
		conn := newTrackedSessionConnection(t, control.service)
		sentinel := errors.New("connection cleanup failed")
		conn.Conn = managementErrorCloseConn{Conn: conn.Conn, err: sentinel}
		control.service.sessionConnections.track(conn, target)
		operation := control.Disconnect
		if dispose {
			operation = control.Dispose
		}
		_, err := operation(t.Context(), target.id)
		require.ErrorIs(t, err, sentinel)
		require.True(t, conn.closed.Load())
		require.Equal(t, dispose, target.disposeCalls > 0, "connection errors must not skip durable revocation")
		require.Equal(t, audit.EventOutcomeFailure, recorder.eventsSnapshot()[1].Outcome)
	}
}
