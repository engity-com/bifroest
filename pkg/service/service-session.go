package service

import (
	"context"
	goerrors "errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	essh "github.com/engity-com/ssh-server-go"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	bssh "github.com/engity-com/bifroest/pkg/ssh"
	"github.com/engity-com/bifroest/pkg/terminal"
)

func (this *service) handleNewSshSession(srv *essh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx essh.Context) error {
	request := &sshSessionRequest{}
	plainContext, cancel := context.WithCancel(context.WithValue(ctx, sshSessionRequestContextKey{}, request))
	sessionContext := &sshSessionContext{Context: ctx, plainContext: plainContext}
	defer cancel()
	return essh.DefaultSessionHandler(srv, conn, &sessionNewChannel{
		NewChannel: newChan,
		ctx:        plainContext,
		cancel:     cancel,
	}, sessionContext)
}

type sshSessionRequestKind uint32

const (
	sshSessionRequestUnknown sshSessionRequestKind = iota
	sshSessionRequestShell
	sshSessionRequestExec
)

type sshSessionRequestContextKey struct{}

type sshSessionRequest struct {
	kind atomic.Uint32
}

func (this *sshSessionRequest) record(requestType string) {
	var kind sshSessionRequestKind
	switch requestType {
	case "shell":
		kind = sshSessionRequestShell
	case "exec":
		kind = sshSessionRequestExec
	default:
		return
	}
	this.kind.CompareAndSwap(uint32(sshSessionRequestUnknown), uint32(kind))
}

func (this *service) onSessionRequest(sshSession essh.Session, requestType string) (bool, error) {
	if requestType == "subsystem" {
		name := sshSession.Subsystem()
		if name == "" || len(name) > audit.MaxSessionSubsystemBytes || !utf8.ValidString(name) || strings.IndexByte(name, 0) >= 0 {
			return false, nil
		}
		if _, _, hasPty := sshSession.Pty(); hasPty {
			return false, nil
		}
	}
	if request, ok := sshSession.Context().Value(sshSessionRequestContextKey{}).(*sshSessionRequest); ok {
		request.record(requestType)
	}
	return true, nil
}

func sessionRequestedExec(sshSession essh.Session) bool {
	if request, ok := sshSession.Context().Value(sshSessionRequestContextKey{}).(*sshSessionRequest); ok {
		switch sshSessionRequestKind(request.kind.Load()) {
		case sshSessionRequestShell:
			return false
		case sshSessionRequestExec:
			return true
		}
	}
	return sshSession.RawCommand() != ""
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
	return this.uncheckedExecuteSshSession(sess, environment.TaskTypeShell, nil)
}

func (this *service) handleSshSubsystemSession(sess essh.Session, reply essh.SubsystemReply) error {
	taskType := environment.TaskTypeSubsystem
	if sess.Subsystem() == "sftp" {
		taskType = environment.TaskTypeSftp
	}
	var replyMu sync.Mutex
	answered := false
	respond := func(accepted bool) error {
		replyMu.Lock()
		defer replyMu.Unlock()
		if answered {
			return essh.ErrSubsystemResponseAlreadySent
		}
		answered = true
		return reply(accepted)
	}
	err := this.uncheckedExecuteSshSession(sess, taskType, respond)
	replyMu.Lock()
	defer replyMu.Unlock()
	if !answered {
		answered = true
		if replyErr := reply(false); replyErr != nil {
			return goerrors.Join(err, replyErr)
		}
	}
	return err
}

func (this *service) uncheckedExecuteSshSession(sshSess essh.Session, taskType environment.TaskType, respond func(bool) error) error {
	conn := this.connection(sshSess.Context())
	l := conn.logger

	l.With("type", taskType).
		With("env", sshSess.Environ()).
		With("command", sshSess.RawCommand()).
		Info("new remote session")

	if exitCode, err := this.executeSession(sshSess, conn, taskType, respond); err != nil {
		recordingFailure := isSessionRecordingFailure(err)
		if !recordingFailure && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			l.Info("session ended unexpectedly; maybe timeout")
			if exitCode < 0 {
				exitCode = 61
			}
			return essh.NewSessionExitError(exitCode, "")
		}
		le := l.WithError(err)
		if !recordingFailure && errors.IsType(err, errors.User) {
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

type sessionTaskAuditLifecycle struct {
	service     *service
	ctx         context.Context
	connection  bconn.Connection
	auth        authorization.Authorization
	operationId string
	task        audit.SessionTask
	subsystem   string
	startedAt   time.Time
}

type invalidSessionExitStatusError struct {
	cause error
}

func (this *invalidSessionExitStatusError) Error() string { return this.cause.Error() }
func (this *invalidSessionExitStatusError) Unwrap() error { return this.cause }

func isInvalidSessionExitStatus(err error) bool {
	var target *invalidSessionExitStatusError
	return goerrors.As(err, &target)
}

func (this *sessionTaskAuditLifecycle) start(hasPty, agentForwarding, forcedCommand bool) error {
	this.startedAt = time.Now()
	event := authorizationAuditEventFor(this.connection, this.auth, audit.EventNameSessionTaskStarted, audit.EventDomainSession)
	event.OperationId = this.operationId
	event.SessionTask = this.task
	event.SessionSubsystem = this.subsystem
	event.Pty = common.P(hasPty)
	event.AgentForwarding = common.P(agentForwarding)
	event.ForcedCommand = common.P(forcedCommand)
	return this.service.recordFlowAudit(this.ctx, this.auth.Flow(), event)
}

func (this *sessionTaskAuditLifecycle) complete(exitCode int, taskErr error) error {
	event := authorizationAuditEventFor(this.connection, this.auth, audit.EventNameSessionTaskCompleted, audit.EventDomainSession)
	event.OperationId = this.operationId
	event.SessionTask = this.task
	event.SessionSubsystem = this.subsystem
	event.DurationMillis = common.P(time.Since(this.startedAt).Milliseconds())
	if exitCode >= 0 {
		event.ExitCode = common.P(exitCode)
	}
	switch {
	case isSessionRecordingFailure(taskErr):
		event.Outcome = audit.EventOutcomeFailure
		event.ErrorCategory = auditErrorCategory(taskErr)
	case taskErr == nil && exitCode < 0 && errors.Is(this.ctx.Err(), context.DeadlineExceeded), errors.Is(taskErr, context.DeadlineExceeded):
		event.Outcome = audit.EventOutcomeCanceled
		event.Reason = audit.EventReasonDeadlineExceeded
	case taskErr == nil && exitCode < 0 && errors.Is(this.ctx.Err(), context.Canceled), errors.Is(taskErr, context.Canceled):
		event.Outcome = audit.EventOutcomeCanceled
		event.Reason = audit.EventReasonContextCanceled
	case goerrors.Is(taskErr, environment.ErrSubsystemNotAllowed):
		event.Outcome = audit.EventOutcomeDenied
		event.Reason = audit.EventReasonEnvironmentPolicy
	case taskErr != nil:
		event.Outcome = audit.EventOutcomeFailure
		event.ErrorCategory = auditErrorCategory(taskErr)
	case exitCode < 0:
		event.Outcome = audit.EventOutcomeFailure
		event.Reason = audit.EventReasonInvalidExitCode
	default:
		event.Outcome = audit.EventOutcomeSuccess
	}
	return this.service.recordFlowAudit(this.ctx, this.auth.Flow(), event)
}

func (this *service) executeSession(sshSess essh.Session, conn *connection, taskType environment.TaskType, respond func(bool) error) (exitCode int, rErr error) {
	auth, _ := sshSess.Context().Value(authorizationCtxKey).(authorization.Authorization)
	requestedSubsystem := taskType != environment.TaskTypeShell
	requestedExec := sessionRequestedExec(sshSess)
	requestedTask := auditSessionTask(taskType, requestedExec)
	subsystem := ""
	if requestedSubsystem {
		subsystem = sshSess.Subsystem()
	}
	sshSess, forcedCommand := applyAuthorizedKeyPolicy(auth, sshSess)
	executesCommand := requestedExec || forcedCommand
	if forcedCommand {
		taskType = environment.TaskTypeShell
	}
	pty, windows, hasPty := sshSess.Pty()
	ptySnapshot := recordedSessionPty{pty: pty, windows: windows, hasPty: hasPty}
	source := &sshExecutionSource{service: this, session: sshSess, pty: ptySnapshot, respond: respond, forced: forcedCommand, requestedSubsystem: requestedSubsystem}
	defer source.stop()
	key, _ := sshSess.Context().Value(handshakeKeyCtxKey).(essh.PublicKey)
	return this.execute(&executionRequest{
		base:       environmentContext{service: this, connection: conn, authorization: auth, executionContext: sshSess.Context()},
		connection: conn, source: source, taskType: taskType, requestedTask: requestedTask, subsystem: subsystem,
		command: executesCommand, forced: forcedCommand, agentForwarding: bssh.AgentRequested(sshSess), verifiedKey: key,
		pty: terminalRecordingPty{pty: bssh.TerminalPty(pty), hasPty: hasPty},
	})
}

type sshExecutionSource struct {
	service                    *service
	session                    essh.Session
	unrecorded                 essh.Session
	pty                        recordedSessionPty
	stream                     *bssh.Terminal
	respond                    func(bool) error
	forced, requestedSubsystem bool
}

func (this *sshExecutionSource) Terminal() terminal.Stream {
	if this.stream == nil {
		this.stream = bssh.NewTerminal(this.session.Context(), this.session)
	}
	return this.stream
}
func (this *sshExecutionSource) Close() error { return this.session.Close() }
func (this *sshExecutionSource) stop() {
	if this.stream != nil {
		this.stream.Stop()
	}
}
func (this *sshExecutionSource) Capture(sink recordingSink, elapsed func() time.Duration, onFailure func(error)) (*terminalCapture, error) {
	capture, err := newRecordedSessionWithPty(this.session, this.pty, sink, elapsed, onFailure)
	if err != nil {
		return nil, err
	}
	this.unrecorded = this.session
	this.session = capture
	return capture.terminalCapture, nil
}
func (this *sshExecutionSource) DiscardCapture() {
	if this.unrecorded != nil {
		this.session = this.unrecorded
		this.unrecorded = nil
	}
}
func (this *sshExecutionSource) Request(base environmentContext) environment.Request {
	return &environmentRequest{base, this.Terminal()}
}
func (this *sshExecutionSource) Prepared(oldState session.State) error {
	if this.respond != nil && this.forced {
		if err := this.respond(true); err != nil {
			return err
		}
	}
	auth, _ := this.session.Context().Value(authorizationCtxKey).(authorization.Authorization)
	if !this.requestedSubsystem && !this.service.isManagementFlow(auth.Flow()) {
		return this.service.showRememberMe(this.session, auth, auth.FindSession(), oldState)
	}
	return nil
}
func (this *sshExecutionSource) Run(env environment.Environment, base environmentContext, taskType environment.TaskType) (int, error) {
	t := &environmentTask{environmentContext: base, sshSession: this.session, taskType: taskType}
	if this.respond != nil && !this.forced {
		if runner, ok := env.(environment.SubsystemRunner); ok {
			return runner.RunSubsystem(t, this.respond)
		}
		if taskType == environment.TaskTypeSftp {
			if err := this.respond(true); err != nil {
				return -1, err
			}
			return env.Run(t)
		}
		return -1, errors.User.Newf("environment does not support subsystem %q", this.session.Subsystem())
	}
	return env.Run(t)
}

func auditSessionTask(taskType environment.TaskType, command bool) audit.SessionTask {
	if taskType == environment.TaskTypeSftp {
		return audit.SessionTaskSftp
	}
	if taskType == environment.TaskTypeSubsystem {
		return audit.SessionTaskSubsystem
	}
	if command {
		return audit.SessionTaskExec
	}
	return audit.SessionTaskShell
}
