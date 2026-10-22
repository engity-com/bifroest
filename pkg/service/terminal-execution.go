package service

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	bssh "github.com/engity-com/bifroest/pkg/ssh"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/terminal"
)

// executeTerminal is a trusted adapter entry point. There is no HTTP handler or
// authentication shortcut here; a live registered connection is mandatory.
func (this *service) executeTerminal(conn *terminalConnection, stream terminal.Stream, command bool) (int, error) {
	if conn == nil || conn.service != this || conn.IsClosed() || isNilDependency(stream) || isNilDependency(stream.Context()) {
		return -1, errors.Permission.Newf("terminal execution requires a live registered connection")
	}
	if !conn.used.CompareAndSwap(false, true) {
		return -1, errors.Permission.Newf("terminal connection already has an execution")
	}
	if err := conn.activity(); err != nil {
		_ = conn.Close()
		return -1, err
	}
	base := environmentContext{service: this, connection: conn, authorization: conn.authorization, executionContext: conn.Lifetime()}
	if err := this.validateTerminalAuthorization(&base); err != nil {
		_ = conn.Close()
		return -1, err
	}
	if this.isManagementFlow(conn.authorization.Flow()) {
		return -1, errors.Permission.Newf("management requires its structured protocol, not terminal execution")
	}
	stopSource := context.AfterFunc(stream.Context(), func() { _ = conn.Close() })
	defer stopSource()
	stopConnection := context.AfterFunc(conn.Lifetime(), func() { _ = stream.Close() })
	defer stopConnection()
	command = command || stream.RawCommand() != ""
	stream, forced := applyTerminalPolicy(conn.authorization, stream, conn.Lifetime())
	pty, windows, hasPty := stream.Pty()
	snapshot := terminalRecordingPty{pty: terminal.ClonePty(pty), windows: windows, hasPty: hasPty}
	if hasPty {
		event := authorizationAuditEventFor(conn, conn.authorization, audit.EventNameSessionPtyDecided, audit.EventDomainSession)
		event.Outcome = audit.EventOutcomeDenied
		var denied error
		if policy := authorization.AuthorizedKeyPolicyOf(conn.authorization); policy != nil && !policy.PtyAllowed {
			denied = errors.Permission.Newf("PTY is forbidden by authorization policy")
			event.Reason = audit.EventReasonAuthorizedKeyPolicy
		} else if _, err := executionRecordingTerminal(snapshot); err != nil {
			denied = err
			event.Reason = audit.EventReasonInvalidRequest
		} else if err := validateTerminalWindow(pty.Window); err != nil {
			denied = err
			event.Reason = audit.EventReasonInvalidRequest
		} else if accepted, err := this.environments.DoesSupportPty(&base, bssh.SshPty(pty)); err != nil {
			denied = err
			event.Outcome = audit.EventOutcomeFailure
			event.Reason = audit.EventReasonEnvironmentPolicy
			event.ErrorCategory = auditErrorCategory(err)
		} else if !accepted {
			denied = errors.Permission.Newf("PTY is forbidden by the environment")
			event.Reason = audit.EventReasonEnvironmentPolicy
		}
		if denied == nil {
			event.Outcome = audit.EventOutcomeSuccess
		}
		if err := this.recordFlowAudit(base.Context(), conn.authorization.Flow(), event); err != nil {
			return -1, err
		}
		if denied != nil {
			return -1, denied
		}
	}
	active := newActivityTerminal(conn, stream, snapshot)
	defer active.stop()
	pty, windows, hasPty = active.Pty()
	snapshot = terminalRecordingPty{pty: pty, windows: windows, hasPty: hasPty}
	source := &terminalExecutionSource{stream: active, snapshot: snapshot}
	return this.execute(&executionRequest{base: base, connection: conn, source: source, taskType: environment.TaskTypeShell, requestedTask: auditSessionTask(environment.TaskTypeShell, command), command: command || forced, forced: forced, pty: snapshot})
}

func validateTerminalWindow(window terminal.Window) error {
	if window.Width < 0 || window.Height < 0 || window.Width > math.MaxUint16 || window.Height > math.MaxUint16 || window.WidthPixels < 0 || window.HeightPixels < 0 || uint64(window.WidthPixels) > math.MaxUint32 || uint64(window.HeightPixels) > math.MaxUint32 {
		return errors.Permission.Newf("invalid terminal window dimensions")
	}
	return nil
}
func normalizedTerminalSignal(value terminal.Signal) (terminal.Signal, bool) {
	text := string(value)
	if text == "" || len(text) > 32 || text[0] < 'A' || text[0] > 'Z' || strings.IndexFunc(text, func(r rune) bool { return (r < 'A' || r > 'Z') && (r < '0' || r > '9') }) >= 0 {
		return "", false
	}
	var signal sys.Signal
	if signal.Set(text) != nil || signal.IsZero() {
		return "", false
	}
	return terminal.Signal(strings.TrimPrefix(signal.String(), "SIG")), true
}

type terminalExecutionSource struct {
	stream     terminal.Stream
	unrecorded terminal.Stream
	snapshot   terminalRecordingPty
}

func (this *terminalExecutionSource) Terminal() terminal.Stream { return this.stream }
func (this *terminalExecutionSource) Close() error              { return this.stream.Close() }
func (this *terminalExecutionSource) Capture(sink recordingSink, elapsed func() time.Duration, onFailure func(error)) (*terminalCapture, error) {
	capture, err := newRecordedTerminalWithPty(this.stream, this.snapshot, sink, elapsed, onFailure)
	if err != nil {
		return nil, err
	}
	this.unrecorded = this.stream
	this.stream = capture
	return capture.terminalCapture, nil
}
func (this *terminalExecutionSource) DiscardCapture() {
	if this.unrecorded != nil {
		this.stream = this.unrecorded
		this.unrecorded = nil
	}
}
func (this *terminalExecutionSource) Request(base environmentContext) environment.Request {
	return &terminalEnvironmentRequest{base}
}
func (*terminalExecutionSource) Prepared(session.State) error { return nil }
func (this *terminalExecutionSource) Run(env environment.Environment, base environmentContext, taskType environment.TaskType) (int, error) {
	runner, ok := env.(environment.TerminalRunner)
	if !ok {
		return -1, errors.User.Newf("environment does not support neutral terminal execution")
	}
	return runner.RunTerminal(&terminalEnvironmentTask{environmentContext: base, stream: this.stream, taskType: taskType})
}

type terminalEnvironmentRequest struct{ environmentContext }

func (*terminalEnvironmentRequest) StartPreparation(string, string, environment.PreparationProgressAttributes) (environment.PreparationProgress, error) {
	return nil, nil
}

type terminalEnvironmentTask struct {
	environmentContext
	stream   terminal.Stream
	taskType environment.TaskType
}

func (this *terminalEnvironmentTask) Terminal() terminal.Stream      { return this.stream }
func (this *terminalEnvironmentTask) TaskType() environment.TaskType { return this.taskType }
func (this *terminalEnvironmentTask) GetField(name string) (any, bool, error) {
	if name == "taskType" {
		return this.taskType, true, nil
	}
	return this.environmentContext.GetField(name)
}

type authorizedTerminal struct {
	terminal.Stream
	ctx               context.Context
	command, original string
	forced            bool
	client            []string
	keyEnvironment    sys.EnvVars
}

func applyTerminalPolicy(auth authorization.Authorization, stream terminal.Stream, ctx context.Context) (terminal.Stream, bool) {
	result := &authorizedTerminal{Stream: stream, ctx: ctx, command: stream.RawCommand(), client: append([]string(nil), stream.Environ()...)}
	if policy := authorization.AuthorizedKeyPolicyOf(auth); policy != nil {
		result.keyEnvironment = policy.Environment.Clone()
		if policy.ForcedCommand != nil {
			result.original = result.command
			result.command = *policy.ForcedCommand
			result.forced = true
		}
	}
	return result, result.forced
}
func (this *authorizedTerminal) Context() context.Context { return this.ctx }
func (this *authorizedTerminal) RawCommand() string       { return this.command }
func (this *authorizedTerminal) ClientEnvironment() []string {
	return append([]string(nil), this.client...)
}
func (this *authorizedTerminal) AuthorizedKeyEnvironment() sys.EnvVars {
	return this.keyEnvironment.Clone()
}
func (this *authorizedTerminal) OriginalCommand() (string, bool) { return this.original, this.forced }
func (this *authorizedTerminal) Environ() []string {
	values := sys.EnvVars{}
	values.Add(this.client...)
	values.AddAllOf(this.keyEnvironment)
	if this.forced {
		values.Set("SSH_ORIGINAL_COMMAND", this.original)
	}
	return values.Strings()
}
