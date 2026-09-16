package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	goerrors "errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
)

func TestDomainAuditRecordsRuntimeTransitionsWithoutSensitiveValues(t *testing.T) {
	const requestedCommand = "audit-secret-requested-command"
	releaseSftp := make(chan struct{})
	repository := &authorizedKeysTestEnvironment{
		portForwardingAllowed:        true,
		reversePortForwardingAllowed: commonBool(true),
		run: func(task environment.Task) (int, error) {
			if task.TaskType() == environment.TaskTypeSftp {
				<-releaseSftp
			}
			return 0, nil
		},
	}
	server := newAuthorizedKeysTestServer(t, "", repository)
	recorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = recorder

	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.Setenv("AUDIT_TEST", "audit-secret-environment-value"))
	require.NoError(t, sshSession.RequestPty("audit-secret-terminal", 80, 25, nil))
	require.NoError(t, agent.RequestAgentForwarding(sshSession))
	require.NoError(t, sshSession.Run(requestedCommand))

	sftpSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sftpSession.RequestSubsystem("sftp"))
	close(releaseSftp)
	_ = sftpSession.Close()

	forwarded, err := client.Dial("tcp", "127.0.0.1:22")
	require.NoError(t, err)
	require.NoError(t, forwarded.Close())

	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	require.NoError(t, client.Close())

	require.Eventually(t, func() bool {
		return recorder.hasEvent(audit.EventNameConnectionClosed) && recorder.hasEvent(audit.EventNamePortForwardingDirectCompleted)
	}, time.Second, 10*time.Millisecond)
	events := recorder.eventsSnapshot()

	requireAuditEvent(t, events, audit.EventNameAuthenticationFlowEvaluated, audit.EventOutcomeSuccess)
	requireAuditEvent(t, events, audit.EventNameAuthenticationCompleted, audit.EventOutcomeSuccess)
	requireAuditEvent(t, events, audit.EventNameSessionPtyDecided, audit.EventOutcomeSuccess)
	requireAuditEvent(t, events, audit.EventNameSessionAgentForwardingDecided, audit.EventOutcomeSuccess)
	requireAuditEvent(t, events, audit.EventNamePortForwardingDirectDecided, audit.EventOutcomeSuccess)
	directStarted := requireAuditEvent(t, events, audit.EventNamePortForwardingDirectStarted, "")
	directCompleted := requireAuditEvent(t, events, audit.EventNamePortForwardingDirectCompleted, audit.EventOutcomeSuccess)
	require.Equal(t, directStarted.OperationId, directCompleted.OperationId)
	require.Empty(t, auditEventsNamed(events, audit.EventNamePortForwardingDirectOpenFailed))
	requireAuditEvent(t, events, audit.EventNamePortForwardingReverseDecided, audit.EventOutcomeSuccess)
	requireAuditEvent(t, events, audit.EventNameConnectionClosed, "")

	startedTasks := auditEventsNamed(events, audit.EventNameSessionTaskStarted)
	completedTasks := auditEventsNamed(events, audit.EventNameSessionTaskCompleted)
	require.Len(t, startedTasks, 2)
	require.Len(t, completedTasks, 2)
	require.ElementsMatch(t, []audit.SessionTask{audit.SessionTaskExec, audit.SessionTaskSftp}, []audit.SessionTask{startedTasks[0].SessionTask, startedTasks[1].SessionTask})
	for _, started := range startedTasks {
		require.NotEmpty(t, started.OperationId)
		require.Equal(t, flow.String(), started.Flow)
		require.NotEmpty(t, started.ConnectionId)
		require.NotEmpty(t, started.SessionId)
		matched := false
		for _, completed := range completedTasks {
			if completed.OperationId == started.OperationId {
				matched = true
				require.Equal(t, started.SessionTask, completed.SessionTask)
				require.Equal(t, audit.EventOutcomeSuccess, completed.Outcome)
			}
		}
		require.True(t, matched)
	}

	payload, err := json.Marshal(events)
	require.NoError(t, err)
	require.NotContains(t, string(payload), requestedCommand)
	require.NotContains(t, string(payload), "audit-secret-terminal")
	require.NotContains(t, string(payload), "audit-secret-environment-value")
}

func TestDomainAuditDoesNotRecordForcedCommand(t *testing.T) {
	const (
		forcedCommand    = "audit-secret-forced-command"
		requestedCommand = "audit-secret-original-command"
	)
	server := newAuthorizedKeysTestServer(t, `command="`+forcedCommand+`"`, &authorizedKeysTestEnvironment{})
	recorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = recorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.Run(requestedCommand))

	started := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted)
	require.Len(t, started, 1)
	require.NotNil(t, started[0].ForcedCommand)
	require.True(t, *started[0].ForcedCommand)
	payload, err := json.Marshal(recorder.eventsSnapshot())
	require.NoError(t, err)
	require.NotContains(t, string(payload), forcedCommand)
	require.NotContains(t, string(payload), requestedCommand)
}

func TestDomainAuditFailureClosesOnlyCausingConnection(t *testing.T) {
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{})
	recordErr := goerrors.New("record failed")
	recorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = recorder
	healthyClient := server.mustDial(t)
	eventsBeforeFailure := len(recorder.eventsSnapshot())
	recorder.setError(recordErr)

	client, err := server.dial()
	require.Error(t, err)
	require.Nil(t, client)
	require.Eventually(t, func() bool { return server.service.activeConnections.Load() == 1 }, time.Second, 10*time.Millisecond)
	require.Len(t, recorder.eventsSnapshot(), eventsBeforeFailure+1)

	recorder.setError(nil)
	sshSession, err := healthyClient.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.Run("still-alive"))
	require.NoError(t, healthyClient.Close())
}

func TestDomainAuditRecordsEachEvaluatedFlowAndNotSkippedFlows(t *testing.T) {
	_, rejectedPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rejectedSigner, err := gossh.NewSignerFromKey(rejectedPrivateKey)
	require.NoError(t, err)
	rejectedKey := bfcrypto.AuthorizedKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(rejectedSigner.PublicKey()))))

	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		accepted := conf.Flows[0]
		rejected := accepted
		rejected.Name = "rejected"
		rejectedAuthorization := *(rejected.Authorization.V.(*configuration.AuthorizationSimple))
		rejectedAuthorization.Entries = append(configuration.AuthorizationSimpleEntries(nil), rejectedAuthorization.Entries...)
		rejectedAuthorization.Entries[0].AuthorizedKeys = rejectedKey
		rejected.Authorization.V = &rejectedAuthorization
		skipped := rejected
		skipped.Name = "skipped"
		skipped.Requirement.IncludedRequestingName = common.MustNewRegexp("^another-user$")
		conf.Flows = configuration.Flows{skipped, rejected, accepted}
	})
	recorder := &recordingAuditRecorder{}
	for _, flow := range server.service.Configuration.Flows {
		server.service.flowAuditRecorders[flow.Name] = recorder
	}
	client := server.mustDial(t)
	require.NoError(t, client.Close())

	evaluated := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluated)
	require.Len(t, evaluated, 2)
	require.Equal(t, "rejected", evaluated[0].Flow)
	require.Equal(t, audit.EventOutcomeDenied, evaluated[0].Outcome)
	require.Equal(t, "restricted-key", evaluated[1].Flow)
	require.Equal(t, audit.EventOutcomeSuccess, evaluated[1].Outcome)
}

func TestDomainAuditRecordsPublicKeySuccessOnlyAfterCertificateVerification(t *testing.T) {
	authority := newIncomingCertificateTestSigner(t)
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		simple := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		simple.TrustedUserCAs = bfcrypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey()))))
		simple.Entries[0].AuthorizedKeys = ""
	})
	recorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = recorder
	certificateSigner := newIncomingCertificateSigner(t, authority, server.signer, server.username, nil)
	blockingSigner := &blockingIncomingCertificateSigner{
		Signer:      certificateSigner,
		signStarted: make(chan struct{}),
		releaseSign: make(chan struct{}),
	}
	dialDone := make(chan error, 1)
	go func() {
		client, err := dialAuthorizedKeysTestServer(server, blockingSigner)
		if client != nil {
			_ = client.Close()
		}
		dialDone <- err
	}()

	select {
	case <-blockingSigner.signStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not reach certificate signing")
	}
	beforeVerification := recorder.eventsSnapshot()
	require.Len(t, auditEventsNamed(beforeVerification, audit.EventNameAuthenticationFlowEvaluated), 1)
	require.Empty(t, auditEventsNamed(beforeVerification, audit.EventNameAuthenticationCompleted))
	close(blockingSigner.releaseSign)
	require.NoError(t, <-dialDone)

	evaluated := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationFlowEvaluated)
	require.Len(t, evaluated, 2)
	require.Equal(t, audit.AuthenticationPhaseCandidate, evaluated[0].AuthenticationPhase)
	require.Equal(t, audit.AuthenticationPhaseVerified, evaluated[1].AuthenticationPhase)
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted), 1)
}

func TestDomainAuditClassifiesSessionFailureWithoutErrorText(t *testing.T) {
	const secretError = "audit-secret-environment-error"
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{
		run: func(environment.Task) (int, error) {
			return -1, goerrors.New(secretError)
		},
	})
	recorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = recorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.Error(t, sshSession.Run("false"))

	completed := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted)
	require.Len(t, completed, 1)
	require.Equal(t, audit.EventOutcomeFailure, completed[0].Outcome)
	require.Equal(t, audit.ErrorCategorySystem, completed[0].ErrorCategory)
	payload, err := json.Marshal(completed)
	require.NoError(t, err)
	require.NotContains(t, string(payload), secretError)
}

func TestDomainAuditClassifiesSessionCanceledWithoutEnvironmentError(t *testing.T) {
	runStarted := make(chan struct{})
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{
		run: func(task environment.Task) (int, error) {
			close(runStarted)
			<-task.Context().Done()
			return -1, nil
		},
	})
	recorder := &recordingAuditRecorder{}
	flow := server.service.Configuration.Flows[0].Name
	server.service.flowAuditRecorders[flow] = recorder
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	runDone := make(chan error, 1)
	go func() { runDone <- sshSession.Run("wait") }()

	select {
	case <-runStarted:
	case <-time.After(time.Second):
		t.Fatal("environment run did not start")
	}
	require.NoError(t, sshSession.Close())
	require.Error(t, <-runDone)
	require.Eventually(t, func() bool {
		completed := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted)
		return len(completed) == 1 && completed[0].Outcome == audit.EventOutcomeCanceled
	}, time.Second, 10*time.Millisecond)
}

type recordingAuditRecorder struct {
	mutex          sync.Mutex
	events         []audit.Event
	recordErr      error
	failName       audit.EventName
	failBefore     bool
	rejectCanceled bool
}

func (this *recordingAuditRecorder) Record(ctx context.Context, event audit.Event) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.rejectCanceled && ctx.Err() != nil {
		return ctx.Err()
	}
	shouldFail := this.recordErr != nil && (this.failName == "" || this.failName == event.Name)
	if shouldFail && this.failBefore {
		return this.recordErr
	}
	this.events = append(this.events, event)
	if !shouldFail {
		return nil
	}
	return this.recordErr
}

func (*recordingAuditRecorder) Close() error { return nil }

func (this *recordingAuditRecorder) setError(err error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.recordErr = err
	this.failName = ""
	this.failBefore = false
}

func (this *recordingAuditRecorder) setErrorForName(name audit.EventName, err error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.recordErr = err
	this.failName = name
	this.failBefore = false
}

func (this *recordingAuditRecorder) setErrorBeforeRecordForName(name audit.EventName, err error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.recordErr = err
	this.failName = name
	this.failBefore = true
}

func (this *recordingAuditRecorder) setRejectCanceled(value bool) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.rejectCanceled = value
}

func (this *recordingAuditRecorder) eventsSnapshot() []audit.Event {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return append([]audit.Event(nil), this.events...)
}

func (this *recordingAuditRecorder) hasEvent(name audit.EventName) bool {
	for _, event := range this.eventsSnapshot() {
		if event.Name == name {
			return true
		}
	}
	return false
}

func auditEventsNamed(events []audit.Event, name audit.EventName) []audit.Event {
	var result []audit.Event
	for _, event := range events {
		if event.Name == name {
			result = append(result, event)
		}
	}
	return result
}

func requireAuditEvent(t *testing.T, events []audit.Event, name audit.EventName, outcome audit.EventOutcome) audit.Event {
	t.Helper()
	for _, event := range events {
		if event.Name == name && event.Outcome == outcome {
			return event
		}
	}
	t.Fatalf("no audit event %q with outcome %q in %#v", name, outcome, events)
	return audit.Event{}
}

func commonBool(value bool) *bool { return &value }

var _ audit.Recorder = (*recordingAuditRecorder)(nil)
