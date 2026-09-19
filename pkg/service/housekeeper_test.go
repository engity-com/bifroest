package service

import (
	"context"
	goerrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestHouseKeeperFinalRetentionDeleteWaitsForSuccessfulAuthorizationDispose(t *testing.T) {
	recorder := &recordingAuditRecorder{}
	repository := &houseKeeperTestSessionRepository{}
	sess := &houseKeeperTestSession{
		flow:       "current",
		id:         session.MustNewId(),
		state:      session.StateDisposed,
		validUntil: time.Now().Add(time.Hour),
	}
	hk := newHouseKeeperForTest(repository, &houseKeeperTestAuthorizer{restoreErr: goerrors.New("permanent restore failure")})
	hk.service.flowAuditRecorders[sess.flow] = recorder
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
	hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)

	canContinue, err := hk.inspectSession(context.Background(), sess)
	require.NoError(t, err)
	require.True(t, canContinue)
	require.Zero(t, repository.deleteCalls)

	events := recorder.eventsSnapshot()
	require.Len(t, events, 2)
	require.Equal(t, audit.EventNameHousekeepingSessionDisposeStarted, events[0].Name)
	require.Equal(t, audit.EventNameHousekeepingSessionDisposeCompleted, events[1].Name)
	require.Equal(t, audit.EventOutcomeFailure, events[1].Outcome)
	require.Equal(t, events[0].OperationId, events[1].OperationId)
}

func TestHouseKeeperClearsPermanentlyUnusableAuthorizationBeforeRetentionDelete(t *testing.T) {
	recorder := &recordingAuditRecorder{}
	repository := &houseKeeperTestSessionRepository{}
	sess := &houseKeeperTestSession{
		flow:               "current",
		id:                 session.MustNewId(),
		validUntil:         time.Now().Add(-2 * time.Hour),
		authorizationToken: []byte("broken"),
	}
	authorizer := &houseKeeperTestAuthorizer{restoreErr: authorization.ErrUnusableAuthorizationToken}
	hk := newHouseKeeperForTest(repository, authorizer)
	hk.service.flowAuditRecorders[sess.flow] = recorder
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
	hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)

	canContinue, err := hk.inspectSession(context.Background(), sess)
	require.NoError(t, err)
	require.True(t, canContinue)
	require.Equal(t, 1, sess.setAuthorizationTokenCalls)
	require.Empty(t, sess.authorizationToken)
	require.Equal(t, 1, repository.deleteCalls)
	require.NotNil(t, authorizer.lastRestoreOpts)
	require.False(t, authorizer.lastRestoreOpts.IsAutoCleanUpAllowed())

	events := recorder.eventsSnapshot()
	require.Len(t, events, 4)
	require.Equal(t, audit.EventNameHousekeepingSessionDisposeStarted, events[0].Name)
	require.Equal(t, audit.EventOutcomeSuccess, events[1].Outcome)
	require.Equal(t, audit.EventNameHousekeepingSessionDeleteStarted, events[2].Name)
	require.Equal(t, audit.EventOutcomeSuccess, events[3].Outcome)
}

func TestHouseKeeperKeepsSessionWhenUnusableAuthorizationTokenCannotBeCleared(t *testing.T) {
	recorder := &recordingAuditRecorder{}
	repository := &houseKeeperTestSessionRepository{}
	sess := &houseKeeperTestSession{
		flow:                       "current",
		id:                         session.MustNewId(),
		validUntil:                 time.Now().Add(-2 * time.Hour),
		authorizationToken:         []byte("broken"),
		setAuthorizationTokenError: goerrors.New("storage unavailable"),
	}
	hk := newHouseKeeperForTest(repository, &houseKeeperTestAuthorizer{restoreErr: authorization.ErrUnusableAuthorizationToken})
	hk.service.flowAuditRecorders[sess.flow] = recorder
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
	hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)

	canContinue, err := hk.inspectSession(context.Background(), sess)
	require.NoError(t, err)
	require.True(t, canContinue)
	require.Equal(t, 1, sess.setAuthorizationTokenCalls)
	require.Equal(t, []byte("broken"), sess.authorizationToken)
	require.Zero(t, repository.deleteCalls)
	require.Equal(t, audit.EventOutcomeFailure, recorder.eventsSnapshot()[1].Outcome)
}

func TestHouseKeeperKeepsTransientAuthorizationFailuresRetryable(t *testing.T) {
	for name, restoreErr := range map[string]error{
		"network": errors.Network.Newf("temporarily unavailable"),
		"system":  errors.System.Newf("local storage unavailable"),
		"unknown": goerrors.New("unclassified failure"),
	} {
		t.Run(name, func(t *testing.T) {
			repository := &houseKeeperTestSessionRepository{}
			sess := &houseKeeperTestSession{flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(-2 * time.Hour)}
			hk := newHouseKeeperForTest(repository, &houseKeeperTestAuthorizer{restoreErr: restoreErr})
			hk.service.flowAuditRecorders[sess.flow] = audit.NewNoopRecorder()
			hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
			hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)

			_, err := hk.inspectSession(context.Background(), sess)
			require.NoError(t, err)
			require.Zero(t, sess.setAuthorizationTokenCalls)
			require.Zero(t, repository.deleteCalls)
		})
	}
}

func TestHouseKeeperInitialDisposeFailureDoesNotDeleteBeforeRetention(t *testing.T) {
	recorder := &recordingAuditRecorder{}
	repository := &houseKeeperTestSessionRepository{}
	sess := &houseKeeperTestSession{
		flow:       "current",
		id:         session.MustNewId(),
		validUntil: time.Now().Add(-time.Minute),
	}
	hk := newHouseKeeperForTest(repository, &houseKeeperTestAuthorizer{restoreErr: goerrors.New("permanent restore failure")})
	hk.service.flowAuditRecorders[sess.flow] = recorder
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
	hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)

	canContinue, err := hk.inspectSession(context.Background(), sess)
	require.NoError(t, err)
	require.True(t, canContinue)
	require.Zero(t, repository.deleteCalls)
	events := recorder.eventsSnapshot()
	require.Len(t, events, 2)
	require.Equal(t, audit.EventNameHousekeepingSessionDisposeStarted, events[0].Name)
	require.Equal(t, audit.EventOutcomeFailure, events[1].Outcome)
}

func TestHouseKeeperPreservesRemovedFlowSessionsWithoutAudit(t *testing.T) {
	for name, state := range map[string]session.State{
		"retention elapsed": session.StateAuthorized,
		"already disposed":  session.StateDisposed,
	} {
		t.Run(name, func(t *testing.T) {
			repository := &houseKeeperTestSessionRepository{}
			authorizer := &houseKeeperTestAuthorizer{restoreErr: goerrors.New("must not be called")}
			sess := &houseKeeperTestSession{
				flow:               "removed",
				id:                 session.MustNewId(),
				state:              state,
				validUntil:         time.Now().Add(-2 * time.Hour),
				authorizationToken: []byte(`{"user":{"name":"local-user"}}`),
				environmentToken:   []byte(`{"containerId":"recover-me"}`),
			}
			hk := newHouseKeeperForTest(repository, authorizer)
			hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: configuration.DefaultAuditlogName, Enabled: false}}
			hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)

			canContinue, err := hk.inspectSession(context.Background(), sess)
			require.NoError(t, err)
			require.True(t, canContinue)
			require.Zero(t, sess.disposeCalls)
			require.Zero(t, sess.authorizationTokenCalls)
			require.Zero(t, sess.setAuthorizationTokenCalls)
			require.Zero(t, sess.environmentTokenCalls)
			require.Zero(t, sess.setEnvironmentTokenCalls)
			require.Zero(t, repository.deleteCalls)
			require.Zero(t, authorizer.restoreCalls)
			require.Zero(t, hk.service.environments.(*houseKeeperTestEnvironmentRepository).findCalls)
		})
	}
}

func TestHouseKeeperFansOutRemovedFlowCleanupSkipToEveryEnabledAuditlog(t *testing.T) {
	first := &recordingAuditRecorder{}
	second := &recordingAuditRecorder{}
	repository := &houseKeeperTestSessionRepository{}
	sess := &houseKeeperTestSession{
		flow:               "removed",
		id:                 session.MustNewId(),
		state:              session.StateDisposed,
		validUntil:         time.Now().Add(-2 * time.Hour),
		authorizationToken: []byte(`{"user":{"name":"local-user"}}`),
		environmentToken:   []byte(`{"containerId":"recover-me"}`),
	}
	authorizer := &houseKeeperTestAuthorizer{restoreErr: goerrors.New("must not be called")}
	hk := newHouseKeeperForTest(repository, authorizer)
	hk.service.auditRecorders["first"] = first
	hk.service.auditRecorders["second"] = second
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{
		{Name: "first", Enabled: true},
		{Name: "disabled", Enabled: false},
		{Name: "second", Enabled: true},
	}
	hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)

	_, err := hk.inspectSession(context.Background(), sess)
	require.NoError(t, err)
	require.Zero(t, sess.disposeCalls)
	require.Zero(t, sess.authorizationTokenCalls)
	require.Zero(t, sess.setAuthorizationTokenCalls)
	require.Zero(t, sess.environmentTokenCalls)
	require.Zero(t, sess.setEnvironmentTokenCalls)
	require.Zero(t, repository.deleteCalls)
	require.Zero(t, authorizer.restoreCalls)
	require.Zero(t, hk.service.environments.(*houseKeeperTestEnvironmentRepository).findCalls)

	for _, recorder := range []*recordingAuditRecorder{first, second} {
		events := recorder.eventsSnapshot()
		require.Len(t, events, 1)
		require.Equal(t, audit.EventNameHousekeepingOrphanedSessionCleanupSkipped, events[0].Name)
		require.Equal(t, "removed", events[0].Flow)
		require.Equal(t, sess.id.String(), events[0].SessionId)
		require.Equal(t, audit.EventReasonMissingFlow, events[0].Reason)
		require.Equal(t, audit.EventOutcomeDenied, events[0].Outcome)
		require.Empty(t, events[0].OperationId)
	}
}

func TestHouseKeeperPreservesRemovedFlowWhenSkipAuditFails(t *testing.T) {
	working := &recordingAuditRecorder{}
	failing := &recordingAuditRecorder{recordErr: goerrors.New("journal unavailable")}
	sess := &houseKeeperTestSession{
		flow:               "removed",
		id:                 session.MustNewId(),
		validUntil:         time.Now().Add(-2 * time.Hour),
		authorizationToken: []byte("former-flow-token"),
	}
	valid := &houseKeeperTestSession{flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(-time.Minute)}
	repository := &houseKeeperTestSessionRepository{
		findAll: func(ctx context.Context, consumer session.Consumer, _ *session.FindOpts) error {
			if canContinue, err := consumer(ctx, sess); err != nil || !canContinue {
				return err
			}
			_, err := consumer(ctx, valid)
			return err
		},
	}
	hk := newHouseKeeperForTest(repository, &houseKeeperTestAuthorizer{restoreErr: authorization.ErrNoSuchAuthorization})
	hk.service.auditRecorders["working"] = working
	hk.service.auditRecorders["failing"] = failing
	hk.service.flowAuditRecorders["current"] = audit.NewNoopRecorder()
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "working", Enabled: true}, {Name: "failing", Enabled: true}}
	hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)

	require.NoError(t, hk.run(hk.logger(), context.Background()))
	require.Zero(t, sess.disposeCalls)
	require.Zero(t, sess.setAuthorizationTokenCalls)
	require.Zero(t, repository.deleteCalls)
	require.Equal(t, 1, valid.disposeCalls)
	require.Len(t, working.eventsSnapshot(), 1)
	require.Len(t, failing.eventsSnapshot(), 1)
	require.Equal(t, audit.EventNameHousekeepingOrphanedSessionCleanupSkipped, working.eventsSnapshot()[0].Name)
}

func TestHouseKeeperContinuesAfterCorruptSessionDiagnostic(t *testing.T) {
	valid := &houseKeeperTestSession{flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(-time.Minute)}
	repository := &houseKeeperTestSessionRepository{}
	repository.findAll = func(ctx context.Context, consumer session.Consumer, opts *session.FindOpts) error {
		diagnostic := session.FindDiagnostic{Flow: "current", Id: session.MustNewId(), Path: "/sessions/corrupt", Err: goerrors.New("invalid session JSON")}
		require.NoError(t, opts.ReportDiagnostic(ctx, diagnostic))
		_, err := consumer(ctx, valid)
		return err
	}
	hk := newHouseKeeperForTest(repository, &houseKeeperTestAuthorizer{restoreErr: authorization.ErrNoSuchAuthorization})
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
	hk.service.flowAuditRecorders["current"] = audit.NewNoopRecorder()
	hk.service.Configuration.HouseKeeping.KeepExpiredFor.SetNative(time.Hour)
	environments := hk.service.environments.(*houseKeeperTestEnvironmentRepository)

	require.NoError(t, hk.run(hk.logger(), context.Background()))
	require.Equal(t, 1, valid.disposeCalls)
	require.Equal(t, 1, environments.cleanupCalls)
	require.NotNil(t, repository.findAllOpts.DiagnosticConsumer)
	require.NotNil(t, repository.findAllOpts.AutoCleanUpAllowed)
	require.False(t, *repository.findAllOpts.AutoCleanUpAllowed)
}

func TestHouseKeeperPreservesEnvironmentResourcesOfRemovedFlow(t *testing.T) {
	orphaned := &houseKeeperTestSession{
		flow:               "removed",
		id:                 session.MustNewId(),
		state:              session.StateDisposed,
		authorizationToken: []byte(`{"user":{"name":"local-user"}}`),
		environmentToken:   []byte(`{"containerId":"recover-me"}`),
	}
	repository := &houseKeeperTestSessionRepository{
		findAll: func(ctx context.Context, consumer session.Consumer, _ *session.FindOpts) error {
			_, err := consumer(ctx, orphaned)
			return err
		},
	}
	hk := newHouseKeeperForTest(repository, nil)
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: configuration.DefaultAuditlogName, Enabled: false}}
	environments := hk.service.environments.(*houseKeeperTestEnvironmentRepository)
	environments.cleanupCheckFlow = "removed"

	require.NoError(t, hk.run(hk.logger(), context.Background()))
	require.True(t, environments.cleanupFlowExists)
	require.Zero(t, orphaned.disposeCalls)
	require.Zero(t, repository.deleteCalls)
}

func TestHouseKeeperDisablesSessionAutoRepairWhenAuditlogEnabled(t *testing.T) {
	repository := &houseKeeperTestSessionRepository{findByErr: session.ErrNoSuchSession}
	hk := newHouseKeeperForTest(repository, nil)
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: "security", Enabled: true}}
	hk.service.Configuration.HouseKeeping.AutoRepair = true

	require.NoError(t, hk.inspectSessions(nil, context.Background()))
	require.NotNil(t, repository.findAllOpts.AutoCleanUpAllowed)
	require.False(t, *repository.findAllOpts.AutoCleanUpAllowed)

	exists, err := hk.doesSessionExist(nil)(context.Background(), "flow", session.MustNewId())
	require.NoError(t, err)
	require.False(t, exists)
	require.NotNil(t, repository.findByOpts.AutoCleanUpAllowed)
	require.False(t, *repository.findByOpts.AutoCleanUpAllowed)
}

func TestHouseKeeperHonorsDisabledAutoRepairWhenAuditlogsAreDisabled(t *testing.T) {
	repository := &houseKeeperTestSessionRepository{findByErr: session.ErrNoSuchSession}
	hk := newHouseKeeperForTest(repository, nil)
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: configuration.DefaultAuditlogName, Enabled: false}}
	hk.service.Configuration.HouseKeeping.AutoRepair = false

	require.NoError(t, hk.inspectSessions(nil, context.Background()))
	require.NotNil(t, repository.findAllOpts.AutoCleanUpAllowed)
	require.False(t, *repository.findAllOpts.AutoCleanUpAllowed)

	exists, err := hk.doesSessionExist(nil)(context.Background(), "flow", session.MustNewId())
	require.NoError(t, err)
	require.False(t, exists)
	require.NotNil(t, repository.findByOpts.AutoCleanUpAllowed)
	require.False(t, *repository.findByOpts.AutoCleanUpAllowed)
}

func TestHouseKeeperRestrictsSessionAutoRepairToKnownFlows(t *testing.T) {
	repository := &houseKeeperTestSessionRepository{}
	hk := newHouseKeeperForTest(repository, nil)
	hk.service.Configuration.Auditlogs = configuration.Auditlogs{{Name: configuration.DefaultAuditlogName, Enabled: false}}
	hk.service.Configuration.HouseKeeping.AutoRepair = true

	require.NoError(t, hk.inspectSessions(nil, context.Background()))
	require.True(t, repository.findAllOpts.IsAutoCleanUpAllowedFor(context.Background(), "current", session.MustNewId()))
	require.False(t, repository.findAllOpts.IsAutoCleanUpAllowedFor(context.Background(), "removed", session.MustNewId()))
}

func TestHouseKeeperDoesNotDeleteRecordingWhenStartAuditFails(t *testing.T) {
	hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, nil)
	recorder := &recordingAuditRecorder{}
	recorder.setErrorBeforeRecordForName(audit.EventNameHousekeepingRecordingDeleteStarted, goerrors.New("journal unavailable"))
	hk.service.auditRecorders["security"] = recorder
	recordingId, err := recording.NewId()
	require.NoError(t, err)
	performed := false

	changed, actionErr, auditErr := hk.auditRecordingDeletion(t.Context(), "security", sessionRecordingRetentionCandidate{recordingId: recordingId}, func() (bool, error) {
		performed = true
		return true, nil
	})
	require.False(t, changed)
	require.NoError(t, actionErr)
	require.ErrorContains(t, auditErr, "journal unavailable")
	require.False(t, performed)
	require.Empty(t, recorder.eventsSnapshot())
}

func newHouseKeeperForTest(repository *houseKeeperTestSessionRepository, authorizer *houseKeeperTestAuthorizer) *houseKeeper {
	svc := &service{
		Service:            &Service{},
		sessions:           repository,
		authorizer:         authorizer,
		environments:       &houseKeeperTestEnvironmentRepository{},
		flowAuditRecorders: make(map[configuration.FlowName]audit.Recorder),
		auditRecorders:     make(map[configuration.AuditlogName]audit.Recorder),
		knownFlows:         map[configuration.FlowName]struct{}{"current": {}},
	}
	return &houseKeeper{service: svc}
}

type houseKeeperTestSessionRepository struct {
	session.CloseableRepository
	deleteCalls int
	findAllOpts *session.FindOpts
	findByOpts  *session.FindOpts
	findByErr   error
	findAll     func(context.Context, session.Consumer, *session.FindOpts) error
}

func (this *houseKeeperTestSessionRepository) FindAll(ctx context.Context, consumer session.Consumer, opts *session.FindOpts) error {
	this.findAllOpts = opts
	if this.findAll != nil {
		return this.findAll(ctx, consumer, opts)
	}
	return nil
}

func (this *houseKeeperTestSessionRepository) FindBy(_ context.Context, _ configuration.FlowName, _ session.Id, opts *session.FindOpts) (session.Session, error) {
	this.findByOpts = opts
	return nil, this.findByErr
}

func (this *houseKeeperTestSessionRepository) Delete(context.Context, session.Session) error {
	this.deleteCalls++
	return nil
}

type houseKeeperTestSession struct {
	session.Session
	flow                       configuration.FlowName
	id                         session.Id
	validUntil                 time.Time
	state                      session.State
	disposeCalls               int
	authorizationToken         []byte
	authorizationTokenCalls    int
	setAuthorizationTokenCalls int
	setAuthorizationTokenError error
	environmentToken           []byte
	environmentTokenCalls      int
	setEnvironmentTokenCalls   int
}

func (this *houseKeeperTestSession) Flow() configuration.FlowName { return this.flow }
func (this *houseKeeperTestSession) Id() session.Id               { return this.id }
func (this *houseKeeperTestSession) String() string {
	return this.flow.String() + "/" + this.id.String()
}
func (this *houseKeeperTestSession) Info(context.Context) (session.Info, error) {
	state := this.state
	if state == session.StateUnchanged {
		state = session.StateAuthorized
	}
	return houseKeeperTestSessionInfo{validUntil: this.validUntil, state: state}, nil
}
func (this *houseKeeperTestSession) Dispose(context.Context) (bool, error) {
	this.disposeCalls++
	return true, nil
}
func (this *houseKeeperTestSession) AuthorizationToken(context.Context) ([]byte, error) {
	this.authorizationTokenCalls++
	return append([]byte(nil), this.authorizationToken...), nil
}
func (this *houseKeeperTestSession) SetAuthorizationToken(_ context.Context, value []byte) error {
	this.setAuthorizationTokenCalls++
	if this.setAuthorizationTokenError != nil {
		return this.setAuthorizationTokenError
	}
	this.authorizationToken = append(this.authorizationToken[:0], value...)
	return nil
}
func (this *houseKeeperTestSession) EnvironmentToken(context.Context) ([]byte, error) {
	this.environmentTokenCalls++
	return append([]byte(nil), this.environmentToken...), nil
}
func (this *houseKeeperTestSession) SetEnvironmentToken(_ context.Context, value []byte) error {
	this.setEnvironmentTokenCalls++
	this.environmentToken = append(this.environmentToken[:0], value...)
	return nil
}

type houseKeeperTestSessionInfo struct {
	session.Info
	validUntil time.Time
	state      session.State
}

func (this houseKeeperTestSessionInfo) State() session.State { return this.state }
func (this houseKeeperTestSessionInfo) ValidUntil(context.Context) (time.Time, error) {
	return this.validUntil, nil
}

type houseKeeperTestAuthorizer struct {
	authorization.CloseableAuthorizer
	restoreErr      error
	restoreCalls    int
	lastRestoreOpts *authorization.RestoreOpts
}

func (this *houseKeeperTestAuthorizer) RestoreFromSession(_ context.Context, _ session.Session, opts *authorization.RestoreOpts) (authorization.Authorization, error) {
	this.restoreCalls++
	this.lastRestoreOpts = opts
	return nil, this.restoreErr
}

type houseKeeperTestEnvironmentRepository struct {
	environment.CloseableRepository
	findCalls         int
	cleanupCalls      int
	cleanupCheckFlow  configuration.FlowName
	cleanupFlowExists bool
}

func (this *houseKeeperTestEnvironmentRepository) FindBySession(context.Context, session.Session, *environment.FindOpts) (environment.Environment, error) {
	this.findCalls++
	return nil, environment.ErrNoSuchEnvironment
}

func (this *houseKeeperTestEnvironmentRepository) Cleanup(_ context.Context, opts *environment.CleanupOpts) error {
	this.cleanupCalls++
	if !this.cleanupCheckFlow.IsZero() {
		exists, err := opts.HasFlowOfName(this.cleanupCheckFlow)
		if err != nil {
			return err
		}
		this.cleanupFlowExists = exists
	}
	return nil
}
