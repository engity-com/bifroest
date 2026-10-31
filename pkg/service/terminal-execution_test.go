package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/terminal"
)

type executionTestStream struct {
	*recordingTerminalTestStream
	command string
}

func (this *executionTestStream) RawCommand() string { return this.command }

type executionTestTransport struct {
	stream *executionTestStream
	id     bconn.Id
}

func (this *executionTestTransport) Id() bconn.Id   { return this.id }
func (*executionTestTransport) Remote() bnet.Remote { return associationAdapterRemote("alice") }
func (*executionTestTransport) Logger() log.Logger {
	return log.GetLogger("neutral-service-execution-test")
}
func (this *executionTestTransport) Lifetime() context.Context { return this.stream.Context() }
func (this *executionTestTransport) Close() error              { return this.stream.Close() }

type executionTestEnvironment struct {
	environment.Environment
	run func(environment.TerminalTask) (int, error)
}

func (this *executionTestEnvironment) RunTerminal(task environment.TerminalTask) (int, error) {
	return this.run(task)
}

type executionTestRepository struct {
	environment.CloseableRepository
	run             func(environment.TerminalTask) (int, error)
	withoutTerminal bool
	shutdown        func() error
	onAccept        func(environment.Context) (bool, error)
}

func (this *executionTestRepository) WillBeAccepted(ctx environment.Context) (bool, error) {
	if this.onAccept != nil {
		return this.onAccept(ctx)
	}
	return this.CloseableRepository.WillBeAccepted(ctx)
}

func (this *executionTestRepository) Ensure(req environment.Request) (environment.Environment, error) {
	env, err := this.CloseableRepository.Ensure(req)
	if err != nil {
		return nil, err
	}
	if _, management := env.(environment.ManagementReader); management {
		return env, nil // Keep the real structured capability in mixed-workspace fixtures.
	}
	if this.withoutTerminal {
		return &struct{ environment.Environment }{env}, nil
	}
	return &executionTestEnvironment{Environment: env, run: this.run}, nil
}
func (this *executionTestRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, ok := environment.SessionTargetResolverFor(this.CloseableRepository, ctx.Authorization().Flow())
	if !ok {
		return "", fmt.Errorf("missing test target resolver")
	}
	return resolver.ResolveSessionTarget(ctx)
}

func executionTestFixture(t *testing.T, run func(environment.TerminalTask) (int, error), configure ...func(*configuration.Configuration)) (*service, *recordingAuditRecorder, string) {
	t.Helper()
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, root)
	enableSessionRecordingForLifecycleTest(&conf, root)
	conf.Flows[0].Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}}}
	for _, fn := range configure {
		fn(&conf)
	}
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	repo := &executionTestRepository{CloseableRepository: svc.environments, run: run}
	svc.environments = repo
	repo.shutdown = sync.OnceValue(svc.Close)
	t.Cleanup(func() { require.NoError(t, repo.shutdown()) })
	recorder := &recordingAuditRecorder{}
	svc.flowAuditRecorders[conf.Flows[0].Name] = recorder
	return svc, recorder, root
}

func newExecutionTestLogin(t *testing.T, svc *service, command string) (*executionTestTransport, authorization.Authorization) {
	t.Helper()
	stream := &executionTestStream{recordingTerminalTestStream: newRecordingTerminalTestStream(t), command: command}
	transport := &executionTestTransport{stream: stream, id: bconn.MustNewId()}
	auth, err := svc.authorizer.AuthorizePassword(&passwordAuthorizeRequest{authorizeRequest: authorizeRequest{service: svc, connection: transport}, password: "correct"})
	require.NoError(t, err)
	require.True(t, auth.IsAuthorized())
	require.NotNil(t, auth.FindSession())
	return transport, auth
}

func registerExecutionTestConnection(t *testing.T, svc *service, transport *executionTestTransport, auth authorization.Authorization) *terminalConnection {
	t.Helper()
	conn, err := svc.registerTerminalConnection(transport, auth)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
		select {
		case <-conn.done:
		case <-time.After(2 * time.Second):
			t.Error("connection validity worker did not stop")
		}
	})
	return conn
}

func TestNeutralServiceExecutionSealsRecordingAndCorrelatesAudit(t *testing.T) {
	var actualTask environment.TerminalTask
	svc, recorder, root := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		actualTask = task
		if _, legacy := task.(environment.Task); legacy {
			return -1, fmt.Errorf("neutral driver supplied an SSH task")
		}
		if _, err := io.WriteString(task.Terminal(), "stdout"); err != nil {
			return -1, err
		}
		if _, err := io.WriteString(task.Terminal().Stderr(), "stderr"); err != nil {
			return -1, err
		}
		return 7, nil
	})
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	code, err := svc.executeTerminal(conn, transport.stream, true)
	require.NoError(t, err)
	require.Equal(t, 7, code)
	require.Equal(t, "stdout", transport.stream.stdout.String())
	require.Equal(t, "stderr", transport.stream.stderr.String())
	require.False(t, conn.IsClosed(), "successful execution leaves status delivery to its transport owner")
	value, err := template.MustNewString("{{.authentication.principal}}/{{.remote.user}}/{{.session.id}}").Render(actualTask)
	require.NoError(t, err)
	require.Equal(t, "alice/alice/"+auth.FindSession().Id().String(), value)
	verification := verifyOnlySessionRecording(t, svc, root)
	require.Equal(t, recording.CastStatusCompleted, verification.Cast.Result.Status)
	require.Equal(t, uint32(7), *verification.Cast.ExitStatus)
	require.Equal(t, transport.id, verification.Cast.Metadata.ConnectionId)
	require.Equal(t, auth.FindSession().Id(), verification.Cast.Metadata.SessionId)
	events := recorder.eventsSnapshot()
	start := auditEventsNamed(events, audit.EventNameSessionRecordingStarted)
	end := auditEventsNamed(events, audit.EventNameSessionRecordingCompleted)
	require.Len(t, start, 1)
	require.Len(t, end, 1)
	requireSessionRecordingAuditCorrelation(t, verification, start[0], end[0])
	require.Less(t, auditEventIndex(t, events, audit.EventNameSessionTaskStarted), auditEventIndex(t, events, audit.EventNameSessionRecordingStarted))
	require.Less(t, auditEventIndex(t, events, audit.EventNameSessionRecordingCompleted), auditEventIndex(t, events, audit.EventNameSessionTaskCompleted))
	_, err = svc.executeTerminal(conn, transport.stream, true)
	require.ErrorContains(t, err, "already has an execution")
	info, err := auth.FindSession().Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateAuthorized, info.State())
}

func TestNeutralServiceNewConnectionCreatesNewExecutionAndRecording(t *testing.T) {
	var calls atomic.Int32
	svc, _, _ := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		calls.Add(1)
		_, err := io.WriteString(task.Terminal(), "fresh")
		return 0, err
	})
	first, auth := newExecutionTestLogin(t, svc, "run")
	one := registerExecutionTestConnection(t, svc, first, auth)
	_, err := svc.executeTerminal(one, first.stream, true)
	require.NoError(t, err)
	second, secondAuth := newExecutionTestLogin(t, svc, "run")
	require.Equal(t, auth.FindSession().Id(), secondAuth.FindSession().Id())
	two := registerExecutionTestConnection(t, svc, second, secondAuth)
	_, err = svc.executeTerminal(two, second.stream, true)
	require.NoError(t, err)
	require.EqualValues(t, 2, calls.Load())
	ids, err := svc.recordingRepositories[svc.Configuration.Auditlogs[0].Name].native.ListSealed(t.Context())
	require.NoError(t, err)
	require.Len(t, ids, 2)
	require.NoError(t, one.Close())
	require.False(t, two.IsClosed())
	require.NoError(t, svc.sessionConnections.revoke(auth.Flow(), auth.FindSession().Id()))
	require.True(t, two.IsClosed())
	third, thirdAuth := newExecutionTestLogin(t, svc, "run")
	late, err := svc.registerTerminalConnection(third, thirdAuth)
	require.Nil(t, late)
	require.ErrorContains(t, err, "revoked")
}

func TestNeutralServicePtyResizeUsesTheSameRecordingLifecycle(t *testing.T) {
	svc, _, root := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		_, changes, ok := task.Terminal().Pty()
		if !ok {
			return -1, fmt.Errorf("missing PTY")
		}
		for {
			select {
			case change := <-changes:
				if change.Width == 100 {
					_, err := io.WriteString(task.Terminal(), "terminal\n")
					return 0, err
				}
			case <-task.Context().Done():
				return -1, task.Context().Err()
			}
		}
	})
	transport, auth := newExecutionTestLogin(t, svc, "run")
	transport.stream.hasPty = true
	transport.stream.pty = terminal.Pty{Term: "xterm", Window: terminal.Window{Width: 80, Height: 24}}
	transport.stream.windows <- terminal.Window{Width: 90, Height: 30}
	transport.stream.windows <- terminal.Window{Width: 100, Height: 40}
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	_, err := svc.executeTerminal(conn, transport.stream, true)
	require.NoError(t, err)
	verification := verifyOnlySessionRecording(t, svc, root)
	require.True(t, verification.Cast.Metadata.Pty)
	require.EqualValues(t, 2, verification.Cast.ResizeEvents)
	require.Contains(t, exportOnlySessionRecording(t, svc, root), `terminal\r\n`)
}

type executionPolicyAuthorization struct {
	authorization.Authorization
	policy *authorization.AuthorizedKeyPolicy
}

func (this executionPolicyAuthorization) AuthorizedKeyPolicy() *authorization.AuthorizedKeyPolicy {
	return this.policy
}
func (this executionPolicyAuthorization) Authentication() (authentication.Identity, error) {
	return authorization.AuthenticationOf(this.Authorization)
}

func TestNeutralServicePreservesForcedCommandAndPtyRestrictions(t *testing.T) {
	var seenCommand, original string
	svc, _, root := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		seenCommand = task.Terminal().RawCommand()
		provider := task.Terminal().(sessionOriginalCommand)
		original, _ = provider.OriginalCommand()
		layers := task.Terminal().(layeredSessionEnvironment)
		if layers.AuthorizedKeyEnvironment()["FROM_KEY"] != "trusted" {
			return -1, fmt.Errorf("key environment lost")
		}
		return 0, nil
	})
	transport, auth := newExecutionTestLogin(t, svc, "requested")
	forced := "forced"
	policy := executionPolicyAuthorization{Authorization: auth, policy: &authorization.AuthorizedKeyPolicy{ForcedCommand: &forced, Environment: sys.EnvVars{"FROM_KEY": "trusted"}}}
	conn := registerExecutionTestConnection(t, svc, transport, policy)
	_, err := svc.executeTerminal(conn, transport.stream, true)
	require.NoError(t, err)
	require.Equal(t, "forced", seenCommand)
	require.Equal(t, "requested", original)
	require.Equal(t, audit.SessionTaskExec, verifyOnlySessionRecording(t, svc, root).Cast.Metadata.Task)
	blocked, newAuth := newExecutionTestLogin(t, svc, "requested")
	blocked.stream.hasPty = true
	denied := executionPolicyAuthorization{Authorization: newAuth, policy: &authorization.AuthorizedKeyPolicy{PtyAllowed: false}}
	blockedConn := registerExecutionTestConnection(t, svc, blocked, denied)
	_, err = svc.executeTerminal(blockedConn, blocked.stream, true)
	require.ErrorContains(t, err, "PTY is forbidden")
}

func TestNeutralServiceStrictAuditFailureClosesNonSshConnection(t *testing.T) {
	var runs atomic.Int32
	svc, recorder, root := executionTestFixture(t, func(environment.TerminalTask) (int, error) { runs.Add(1); return 0, nil })
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionRecordingStarted, errors.New("audit unavailable"))
	_, err := svc.executeTerminal(conn, transport.stream, true)
	require.Error(t, err)
	require.True(t, conn.IsClosed())
	require.Zero(t, runs.Load())
	require.Equal(t, recording.CastStatusFailed, verifyOnlySessionRecording(t, svc, root).Cast.Result.Status)
}

func TestNeutralServiceBestEffortAuditFailureDoesNotStopOutput(t *testing.T) {
	svc, recorder, _ := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		_, err := io.WriteString(task.Terminal(), "still delivered")
		return 0, err
	}, func(conf *configuration.Configuration) {
		conf.Auditlogs[0].FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
	})
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	flow := auth.Flow()
	auditlog := svc.flowAuditlogs[flow]
	svc.flowAuditRecorders[flow] = &failurePolicyAuditRecorder{service: svc, auditlog: auditlog, delegate: recorder}
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionRecordingStarted, errors.New("audit unavailable"))
	code, err := svc.executeTerminal(conn, transport.stream, true)
	require.NoError(t, err)
	require.Zero(t, code)
	require.Equal(t, "still delivered", transport.stream.stdout.String())
	require.False(t, conn.IsClosed())
}

func TestNeutralServiceRejectsUnsupportedEnvironmentWithoutSshFallback(t *testing.T) {
	svc, _, _ := executionTestFixture(t, func(environment.TerminalTask) (int, error) { t.Fatal("unexpected run"); return 0, nil })
	svc.environments.(*executionTestRepository).withoutTerminal = true
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	_, err := svc.executeTerminal(conn, transport.stream, true)
	require.ErrorContains(t, err, "does not support neutral terminal")
}

func TestNeutralServiceShutdownDrainsExecutionBeforeClosingRecordingRepository(t *testing.T) {
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	svc, _, root := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		close(started)
		<-task.Context().Done()
		close(canceled)
		<-release
		return -1, task.Context().Err()
	})
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	runDone := make(chan error, 1)
	go func() { _, err := svc.executeTerminal(conn, transport.stream, true); runDone <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("execution did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- svc.environments.(*executionTestRepository).shutdown() }()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel neutral execution")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("closed resources before execution cleanup: %v", err)
	default:
	}
	unblock()
	select {
	case err := <-runDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("execution did not end")
	}
	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not drain")
	}
	require.Equal(t, recording.CastStatusIncomplete, verifyOnlySessionRecording(t, svc, root).Cast.Result.Status)
}

func TestNeutralServiceShutdownCancelsAndDrainsPendingAdmission(t *testing.T) {
	svc, _, _ := executionTestFixture(t, func(environment.TerminalTask) (int, error) { return 0, nil })
	transport, auth := newExecutionTestLogin(t, svc, "run")
	repo := svc.environments.(*executionTestRepository)
	entered := make(chan struct{})
	repo.onAccept = func(ctx environment.Context) (bool, error) {
		close(entered)
		<-ctx.Context().Done()
		return false, ctx.Context().Err()
	}
	admitted := make(chan error, 1)
	go func() { _, err := svc.registerTerminalConnection(transport, auth); admitted <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("admission did not start")
	}
	require.NoError(t, repo.shutdown())
	select {
	case err := <-admitted:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not drain admission")
	}
}

func TestNeutralServiceStrictSealFailureClosesConnection(t *testing.T) {
	cause := errors.New("seal unavailable")
	svc, recorder, _ := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		capture := task.Terminal().(*recordedTerminal)
		coordinator := capture.sink.(*sessionRecordingCoordinator)
		coordinator.mu.Lock()
		coordinator.active.seal = func(time.Duration, recording.CastResult, *uint32) (sessionRecordingSealSummary, error) {
			return sessionRecordingSealSummary{}, cause
		}
		coordinator.mu.Unlock()
		_, err := io.WriteString(task.Terminal(), "recorded before seal failure")
		return 0, err
	})
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	code, err := svc.executeTerminal(conn, transport.stream, true)
	require.ErrorIs(t, err, cause)
	require.Equal(t, -1, code)
	require.True(t, conn.IsClosed())
	failures := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionRecordingFailed)
	require.Len(t, failures, 1)
	require.Equal(t, audit.EventReasonRecordingSeal, failures[0].Reason)
}

func TestNeutralServiceStrictCaptureFailurePreventsOutputDelivery(t *testing.T) {
	cause := errors.New("capture unavailable")
	svc, recorder, root := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		task.Terminal().(*recordedTerminal).sink = &captureTestSink{outputErr: cause}
		_, err := io.WriteString(task.Terminal(), "must not be delivered")
		return -1, err
	})
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	_, err := svc.executeTerminal(conn, transport.stream, true)
	require.ErrorIs(t, err, cause)
	require.True(t, conn.IsClosed())
	require.Empty(t, transport.stream.stdout.String())
	require.Equal(t, recording.CastStatusFailed, verifyOnlySessionRecording(t, svc, root).Cast.Result.Status)
	failures := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionRecordingFailed)
	require.Len(t, failures, 1)
	require.Equal(t, audit.EventReasonRecordingCapture, failures[0].Reason)
}

func TestNeutralTerminalControlValidation(t *testing.T) {
	for _, invalid := range []terminal.Window{{Width: -1}, {Height: 65536}, {WidthPixels: -1}} {
		require.Error(t, validateTerminalWindow(invalid))
	}
	require.NoError(t, validateTerminalWindow(terminal.Window{Width: 65535, Height: 65535}))
	for _, invalid := range []terminal.Signal{"", "0", "15", "0x9", "term", "TERM\n", "NOTASIGNAL"} {
		_, valid := normalizedTerminalSignal(invalid)
		require.False(t, valid)
	}
	for _, valid := range []terminal.Signal{"TERM", "SIGTERM"} {
		actual, ok := normalizedTerminalSignal(valid)
		require.True(t, ok)
		require.Equal(t, terminal.Signal("TERM"), actual)
	}
}

func TestNeutralServiceInvalidResizeIsRejectedEvenWithoutRecording(t *testing.T) {
	svc, _, _ := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		<-task.Context().Done()
		return -1, task.Context().Err()
	}, func(conf *configuration.Configuration) {
		conf.Auditlogs[0].Recording.Enabled = false
		conf.Auditlogs[0].FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
	})
	transport, auth := newExecutionTestLogin(t, svc, "run")
	transport.stream.hasPty = true
	transport.stream.pty = terminal.Pty{Term: "xterm", Window: terminal.Window{Width: 80, Height: 24}}
	transport.stream.windows <- terminal.Window{Width: -1, Height: 24}
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	_, err := svc.executeTerminal(conn, transport.stream, true)
	require.Error(t, err)
	require.Eventually(t, conn.IsClosed, time.Second, time.Millisecond)
	require.False(t, svc.auditlogDisabled(svc.Configuration.Auditlogs[0].Name), "bad client input is not a storage failure")
}

func TestNeutralServiceInvalidExitCannotProduceCompletedRecording(t *testing.T) {
	svc, _, root := executionTestFixture(t, func(environment.TerminalTask) (int, error) { return -3, nil })
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	_, err := svc.executeTerminal(conn, transport.stream, true)
	require.True(t, isInvalidSessionExitStatus(err))
	verification := verifyOnlySessionRecording(t, svc, root)
	require.Equal(t, recording.CastStatusIncomplete, verification.Cast.Result.Status)
	require.Nil(t, verification.Cast.ExitStatus)
}

func TestNeutralServiceSourceDisconnectCancelsExecutionAndSealsIncomplete(t *testing.T) {
	started := make(chan struct{})
	svc, _, root := executionTestFixture(t, func(task environment.TerminalTask) (int, error) {
		close(started)
		<-task.Context().Done()
		return -1, task.Context().Err()
	})
	transport, auth := newExecutionTestLogin(t, svc, "run")
	conn := registerExecutionTestConnection(t, svc, transport, auth)
	done := make(chan error, 1)
	go func() { _, err := svc.executeTerminal(conn, transport.stream, true); done <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("execution did not start")
	}
	transport.stream.cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("source disconnect did not cancel execution")
	}
	require.True(t, conn.IsClosed())
	require.Equal(t, recording.CastStatusIncomplete, verifyOnlySessionRecording(t, svc, root).Cast.Result.Status)
}
