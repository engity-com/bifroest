package service

import (
	"context"
	goerrors "errors"
	"io"
	"time"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/google/uuid"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	bssh "github.com/engity-com/bifroest/pkg/ssh"
)

func (this *service) handleNewSshSession(srv *essh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx essh.Context) error {
	plainContext, cancel := context.WithCancel(ctx)
	sessionContext := &sshSessionContext{Context: ctx, plainContext: plainContext}
	defer cancel()
	return essh.DefaultSessionHandler(srv, conn, &sessionNewChannel{
		NewChannel: newChan,
		ctx:        plainContext,
		cancel:     cancel,
	}, sessionContext)
}

type sshSessionContext struct {
	essh.Context
	plainContext context.Context
}

func (this *sshSessionContext) Deadline() (time.Time, bool) { return this.plainContext.Deadline() }
func (this *sshSessionContext) Done() <-chan struct{}       { return this.plainContext.Done() }
func (this *sshSessionContext) Err() error                  { return this.plainContext.Err() }
func (this *sshSessionContext) Value(key any) any           { return this.plainContext.Value(key) }

type sessionNewChannel struct {
	gossh.NewChannel
	ctx    context.Context
	cancel context.CancelFunc
}

func (this *sessionNewChannel) Accept() (gossh.Channel, <-chan *gossh.Request, error) {
	channel, requests, err := this.NewChannel.Accept()
	if err != nil {
		return nil, nil, err
	}
	forwarded := make(chan *gossh.Request)
	go func() {
		defer close(forwarded)
		for {
			select {
			case request, ok := <-requests:
				if !ok {
					this.cancel()
					return
				}
				select {
				case forwarded <- request:
				case <-this.ctx.Done():
					for range requests {
					}
					return
				}
			case <-this.ctx.Done():
				for range requests {
				}
				return
			}
		}
	}()
	return channel, forwarded, nil
}

func (this *service) handleSshShellSession(sess essh.Session) error {
	return this.uncheckedExecuteSshSession(sess, environment.TaskTypeShell)
}

func (this *service) handleSshSftpSession(sess essh.Session) error {
	return this.uncheckedExecuteSshSession(sess, environment.TaskTypeSftp)
}

func (this *service) uncheckedExecuteSshSession(sshSess essh.Session, taskType environment.TaskType) error {
	conn := this.connection(sshSess.Context())
	l := conn.logger

	l.With("type", taskType).
		With("env", sshSess.Environ()).
		With("command", sshSess.RawCommand()).
		Info("new remote session")

	if exitCode, err := this.executeSession(sshSess, conn, taskType); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			l.Info("session ended unexpectedly; maybe timeout")
			if exitCode < 0 {
				exitCode = 61
			}
			return essh.NewSessionExitError(exitCode, "")
		}
		le := l.WithError(err)
		if errors.IsType(err, errors.User) {
			le.Warn("cannot execute session")
			if exitCode < 0 {
				exitCode = 62
			}
		} else {
			le.Error("cannot execute session")
			if exitCode < 0 {
				exitCode = 63
			}
		}
		return essh.NewSessionExitError(exitCode, "")
	} else {
		l.With("exitCode", exitCode).
			Info("session ended")
		return essh.NewSessionExitError(exitCode, "")
	}
}

func (this *service) executeSession(sshSess essh.Session, conn *connection, taskType environment.TaskType) (exitCode int, rErr error) {
	fail := func(err error) (int, error) {
		return -1, err
	}
	failf := func(t errors.Type, msg string, args ...any) (int, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	auth, _ := sshSess.Context().Value(authorizationCtxKey).(authorization.Authorization)
	if auth == nil {
		return failf(errors.System, "no authorization resolved, but it should")
	}
	sess := auth.FindSession()
	if sess == nil {
		return failf(errors.System, "authorization resolved, but does not have a valid session")
	}
	operationId, err := uuid.NewRandom()
	if err != nil {
		return failf(errors.System, "cannot generate audit operation ID: %w", err)
	}
	requestedTask := auditSessionTask(taskType, sshSess.RawCommand() != "")
	sshSess, forcedCommand := applyAuthorizedKeyPolicy(auth, sshSess)
	if forcedCommand {
		taskType = environment.TaskTypeShell
	}
	_, _, hasPty := sshSess.Pty()
	startedAt := time.Now()
	startedEvent := this.authorizationAuditEvent(sshSess.Context(), auth, "session.task.started", audit.EventDomainSession)
	startedEvent.OperationId = operationId.String()
	startedEvent.SessionTask = requestedTask
	startedEvent.Pty = common.P(hasPty)
	startedEvent.AgentForwarding = common.P(bssh.AgentRequested(sshSess))
	startedEvent.ForcedCommand = common.P(forcedCommand)
	if err := this.recordFlowAudit(sshSess.Context(), auth.Flow(), startedEvent); err != nil {
		return fail(err)
	}
	defer func() {
		event := this.authorizationAuditEvent(sshSess.Context(), auth, "session.task.completed", audit.EventDomainSession)
		event.OperationId = operationId.String()
		event.SessionTask = requestedTask
		event.DurationMillis = common.P(time.Since(startedAt).Milliseconds())
		if exitCode >= 0 {
			event.ExitCode = common.P(exitCode)
		}
		switch {
		case rErr == nil && exitCode < 0 && errors.Is(sshSess.Context().Err(), context.DeadlineExceeded), errors.Is(rErr, context.DeadlineExceeded):
			event.Outcome = audit.EventOutcomeCanceled
			event.Reason = "deadline-exceeded"
		case rErr == nil && exitCode < 0 && errors.Is(sshSess.Context().Err(), context.Canceled), errors.Is(rErr, context.Canceled):
			event.Outcome = audit.EventOutcomeCanceled
			event.Reason = "context-canceled"
		case rErr != nil:
			event.Outcome = audit.EventOutcomeFailure
			event.ErrorCategory = auditErrorCategory(rErr)
		case exitCode < 0:
			event.Outcome = audit.EventOutcomeFailure
			event.Reason = "invalid-exit-code"
		default:
			event.Outcome = audit.EventOutcomeSuccess
		}
		if recordErr := this.recordFlowAudit(sshSess.Context(), auth.Flow(), event); recordErr != nil {
			rErr = goerrors.Join(rErr, recordErr)
		}
	}()
	_, _, oldState, err := this.resolveAuthorizationAndSession(sshSess.Context())
	if err != nil {
		return fail(err)
	}

	if err := this.showRememberMe(sshSess, auth, sess, oldState); err != nil {
		return fail(err)
	}

	req := environmentRequest{
		environmentContext{
			service:          this,
			connection:       conn,
			authorization:    auth,
			executionContext: sshSess.Context(),
		},
		sshSess,
	}

	env, err := this.environments.Ensure(&req)
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, env)

	if len(sshSess.RawCommand()) == 0 && taskType == environment.TaskTypeShell {
		banner, err := env.Banner(&req)
		if err != nil {
			return failf(errors.System, "cannot render banner: %w", err)
		}
		if banner != nil {
			defer common.IgnoreCloseError(banner)
			if _, err := io.Copy(sshSess, banner); err != nil {
				return failf(errors.System, "cannot print banner: %w", err)
			}
		}
	}

	t := environmentTask{
		environmentContext: req.environmentContext,
		sshSession:         sshSess,
		taskType:           taskType,
	}
	if exitCode, err := env.Run(&t); err != nil {
		return failf(errors.System, "run of environment failed: %w", err)
	} else {
		return exitCode, nil
	}
}

func auditSessionTask(taskType environment.TaskType, command bool) audit.SessionTask {
	if taskType == environment.TaskTypeSftp {
		return audit.SessionTaskSftp
	}
	if command {
		return audit.SessionTaskExec
	}
	return audit.SessionTaskShell
}
