package service

import (
	"context"
	goerrors "errors"
	"io"
	"math"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/terminal"
)

// Transport adapters own protocol-specific acknowledgement, remembered SSH keys,
// agent/subsystem support and status delivery. The driver owns the environment,
// audit and recording lifecycle for every execution, independently of transport.
type executionSource interface {
	Terminal() terminal.Stream
	Close() error
	Capture(recordingSink, func() time.Duration, func(error)) (*terminalCapture, error)
	DiscardCapture()
	Request(environmentContext) environment.Request
	Prepared(session.State) error
	Run(environment.Environment, environmentContext, environment.TaskType) (int, error)
}

type executionRequest struct {
	base                             environmentContext
	connection                       managedConnection
	source                           executionSource
	taskType                         environment.TaskType
	requestedTask                    audit.SessionTask
	subsystem                        string
	command, forced, agentForwarding bool
	verifiedKey                      ssh.PublicKey // Trusted adapter evidence; never a payload key alone.
	pty                              terminalRecordingPty
}

func (this *service) execute(request *executionRequest) (exitCode int, rErr error) {
	fail := func(err error) (int, error) { return -1, err }
	auth := request.base.Authorization()
	if auth == nil || !auth.IsAuthorized() {
		return fail(errors.System.Newf("no authorization resolved, but it should"))
	}
	sess := auth.FindSession()
	if sess == nil || sess.Flow() != auth.Flow() {
		return fail(errors.System.Newf("authorization resolved, but does not have a valid session"))
	}
	if isNilDependency(request.connection) || request.connection.IsClosed() {
		return fail(context.Canceled)
	}
	if this.executions != nil {
		release, ok := this.executions.register()
		if !ok {
			return fail(context.Canceled)
		}
		defer release()
	}
	ctx := context.WithValue(request.base.Context(), auditConnectionContextKey{}, request.connection)
	base := request.base
	base.executionContext = ctx
	operationId, err := uuid.NewRandom()
	if err != nil {
		return fail(errors.System.Newf("cannot generate audit operation ID: %w", err))
	}
	taskAudit := sessionTaskAuditLifecycle{service: this, ctx: ctx, connection: request.connection, auth: auth, operationId: operationId.String(), task: request.requestedTask, subsystem: request.subsystem}
	if err := taskAudit.start(request.pty.hasPty, request.agentForwarding, request.forced); err != nil {
		return fail(err)
	}
	defer func() {
		if err := taskAudit.complete(exitCode, rErr); err != nil {
			rErr = goerrors.Join(rErr, err)
		}
	}()
	_, recordingLifecycle, err := this.beginRecording(&recordingExecution{ctx: ctx, close: request.source.Close, capture: request.source.Capture}, request.pty, request.connection, sess, operationId, auth.Flow(), auditSessionTask(request.taskType, request.command))
	if recordingLifecycle == nil {
		request.source.DiscardCapture()
	}
	if err != nil {
		return fail(markSessionRecordingFailure(err))
	}
	if recordingLifecycle != nil {
		defer func() {
			if err := recordingLifecycle.finish(exitCode, rErr, request.connection); err != nil {
				exitCode = -1
				rErr = goerrors.Join(rErr, markSessionRecordingFailure(err))
			}
		}()
	}
	oldState, err := activateExecutionSession(ctx, request.connection, sess, request.verifiedKey)
	if err != nil {
		return fail(err)
	}
	req := request.source.Request(base)
	env, err := this.environments.Ensure(req)
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, env)
	management := this.isManagementFlow(auth.Flow())
	if recordingLifecycle != nil && !management {
		if err := recordingLifecycle.showNotice(request.source.Terminal(), !request.command); err != nil {
			return fail(err)
		}
	}
	if err := request.source.Prepared(oldState); err != nil {
		return fail(err)
	}
	if !request.command && request.taskType == environment.TaskTypeShell {
		banner, err := env.Banner(req)
		if err != nil {
			return fail(errors.System.Newf("cannot render banner: %w", err))
		}
		if banner != nil {
			defer common.IgnoreCloseError(banner)
			if _, err := io.Copy(request.source.Terminal(), banner); err != nil {
				return fail(errors.System.Newf("cannot print banner: %w", err))
			}
		}
	}
	if valid, err := session.IsStillValid(ctx, sess); err != nil {
		return fail(err)
	} else if !valid {
		return fail(errors.Permission.Newf("session is no longer valid"))
	}
	if request.connection.IsClosed() {
		return fail(context.Canceled)
	}
	exitCode, err = request.source.Run(env, base, request.taskType)
	if err != nil {
		return fail(errors.System.Newf("run of environment failed: %w", err))
	}
	if exitCode < 0 {
		if err := ctx.Err(); err != nil {
			return exitCode, err
		}
		return fail(&invalidSessionExitStatusError{cause: errors.System.Newf("environment returned invalid exit code %d", exitCode)})
	}
	if uint64(exitCode) > math.MaxUint32 {
		return fail(&invalidSessionExitStatusError{cause: errors.System.Newf("environment returned unsupported exit code %d", exitCode)})
	}
	return exitCode, nil
}

func activateExecutionSession(ctx context.Context, conn managedConnection, sess session.Session, verifiedKey ssh.PublicKey) (session.State, error) {
	if valid, err := session.IsStillValid(ctx, sess); err != nil {
		return 0, err
	} else if !valid {
		return 0, errors.Permission.Newf("session is no longer valid")
	}
	oldState, err := sess.NotifyLastAccess(ctx, conn.Remote(), session.StateAuthorized)
	if err != nil {
		return 0, errors.System.Newf("cannot update session state: %w", err)
	}
	if oldState == session.StateNew && verifiedKey != nil {
		if err := sess.AddPublicKey(ctx, verifiedKey); err != nil {
			return 0, errors.System.Newf("cannot add public key to session: %w", err)
		}
	}
	return oldState, nil
}
