package service

import (
	"context"
	goerrors "errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type maintenanceTestRepository struct {
	session.CloseableRepository
	expired session.Id
}

func (this *maintenanceTestRepository) FindBy(ctx context.Context, flow configuration.FlowName, id session.Id, opts *session.FindOpts) (session.Session, error) {
	found, err := this.CloseableRepository.FindBy(ctx, flow, id, opts)
	return this.wrap(found), err
}

func (this *maintenanceTestRepository) FindAll(ctx context.Context, consume session.Consumer, opts *session.FindOpts) error {
	return this.CloseableRepository.FindAll(ctx, func(ctx context.Context, sess session.Session) (bool, error) {
		return consume(ctx, this.wrap(sess))
	}, opts)
}

func (this *maintenanceTestRepository) Delete(ctx context.Context, sess session.Session) error {
	if wrapped, ok := sess.(maintenanceTestExpiredSession); ok {
		sess = wrapped.Session
	}
	return this.CloseableRepository.Delete(ctx, sess)
}

func (this *maintenanceTestRepository) wrap(sess session.Session) session.Session {
	if sess == nil || sess.Id() != this.expired {
		return sess
	}
	return maintenanceTestExpiredSession{sess}
}

type maintenanceTestExpiredSession struct{ session.Session }
type maintenanceTestExpiredInfo struct{ session.Info }

func (this maintenanceTestExpiredSession) Info(ctx context.Context) (session.Info, error) {
	info, err := this.Session.Info(ctx)
	return maintenanceTestExpiredInfo{info}, err
}
func (maintenanceTestExpiredInfo) ValidUntil(context.Context) (time.Time, error) {
	return time.Unix(1, 0), nil
}

type maintenanceTestEnvironmentRepository struct {
	environment.CloseableRepository
	disposals atomic.Int32
	cleanups  atomic.Int32
	closes    atomic.Int32
	fail      atomic.Bool
}

func (*maintenanceTestEnvironmentRepository) SessionEnvironmentMatches(context.Context, session.Session) (bool, error) {
	return true, nil
}
func (this *maintenanceTestEnvironmentRepository) FindBySession(_ context.Context, sess session.Session, _ *environment.FindOpts) (environment.Environment, error) {
	return &maintenanceTestEnvironment{repository: this, sess: sess}, nil
}
func (this *maintenanceTestEnvironmentRepository) Cleanup(ctx context.Context, opts *environment.CleanupOpts) error {
	this.cleanups.Add(1)
	return this.CloseableRepository.Cleanup(ctx, opts)
}
func (this *maintenanceTestEnvironmentRepository) Close() error {
	this.closes.Add(1)
	return this.CloseableRepository.Close()
}

type maintenanceTestEnvironment struct {
	environment.Environment
	repository *maintenanceTestEnvironmentRepository
	sess       session.Session
}

func (this *maintenanceTestEnvironment) Dispose(ctx context.Context) (bool, error) {
	this.repository.disposals.Add(1)
	if this.repository.fail.Load() {
		return false, goerrors.New("backend cleanup unavailable")
	}
	return true, this.sess.SetEnvironmentToken(ctx, nil)
}
func (*maintenanceTestEnvironment) Close() error { return nil }

type maintenanceTestAuthorizer struct {
	authorization.CloseableAuthorizer
	restores atomic.Int32
}

func (this *maintenanceTestAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, opts *authorization.RestoreOpts) (authorization.Authorization, error) {
	this.restores.Add(1)
	return this.CloseableAuthorizer.RestoreFromSession(ctx, sess, opts)
}

type maintenanceTestAuditGate struct {
	audit.Recorder
	name    audit.EventName
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (this *maintenanceTestAuditGate) Record(ctx context.Context, event audit.Event) error {
	if event.Name == this.name {
		this.once.Do(func() { close(this.entered) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-this.release:
		}
	}
	return this.Recorder.Record(ctx, event)
}

func TestRuntimeMaintenanceUsesSessionOwnerAndPinsDeletionAudit(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	// Drive complete passes explicitly; activation still wakes the single
	// process loop in the separate notification integration test.
	require.NoError(t, svc.houseKeeper.Close())
	oldAuth := runtimeAdmissionTestPassword(t, svc, "correct")
	require.True(t, oldAuth.IsAuthorized())
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(17)
	candidate, err := svc.prepareGeneration(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(candidate.generation) {
			<-candidate.generationClosed
		}
	})
	_, err = svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	newAuth := runtimeAdmissionTestPassword(t, candidate, "correct")
	require.True(t, newAuth.IsAuthorized())
	require.NotEqual(t, oldAuth.FindSession().Id(), newAuth.FindSession().Id())
	store := &maintenanceTestRepository{CloseableRepository: svc.sessions, expired: oldAuth.FindSession().Id()}
	svc.sessions, candidate.sessions = store, store
	oldEnvironment := &maintenanceTestEnvironmentRepository{CloseableRepository: svc.environments}
	newEnvironment := &maintenanceTestEnvironmentRepository{CloseableRepository: candidate.environments}
	svc.environments, candidate.environments = oldEnvironment, newEnvironment
	oldAuthorizer := &maintenanceTestAuthorizer{CloseableAuthorizer: svc.authorizer}
	newAuthorizer := &maintenanceTestAuthorizer{CloseableAuthorizer: candidate.authorizer}
	svc.authorizer, candidate.authorizer = oldAuthorizer, newAuthorizer
	require.NoError(t, oldAuth.FindSession().SetEnvironmentToken(t.Context(), []byte(`{"pending":true}`)))
	oldEnvironment.fail.Store(true)
	_, err = svc.houseKeeper.checkedRun(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, oldEnvironment.disposals.Load())
	require.Zero(t, newEnvironment.disposals.Load())
	require.Zero(t, oldEnvironment.closes.Load())
	require.Same(t, svc.generation, svc.runtime.sessionOwner(oldAuth.FindSession()))
	require.Zero(t, oldEnvironment.cleanups.Load(), "persistent runtime forbids unscoped orphan scans")
	require.Zero(t, newEnvironment.cleanups.Load())
	oldEnvironment.fail.Store(false)
	gate := &maintenanceTestAuditGate{
		Recorder: svc.flowAuditRecorders[oldAuth.Flow()], name: audit.EventNameHousekeepingSessionDeleteCompleted,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	svc.flowAuditRecorders[oldAuth.Flow()] = gate
	done := make(chan error, 1)
	go func() { _, err := svc.houseKeeper.checkedRun(t.Context()); done <- err }()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("housekeeping did not reach deletion completion")
	}
	require.Nil(t, svc.runtime.sessionOwner(oldAuth.FindSession()))
	require.Zero(t, oldEnvironment.closes.Load(), "the final audit completion still owns provider resources")
	unblock()
	require.NoError(t, <-done)
	runtimeResourcesWaitClosed(t, svc)
	require.EqualValues(t, 1, oldEnvironment.closes.Load())
	require.Zero(t, newEnvironment.closes.Load())
	require.EqualValues(t, 1, oldAuthorizer.restores.Load())
	require.Zero(t, newAuthorizer.restores.Load())
	require.Same(t, candidate.generation, svc.runtime.sessionOwner(newAuth.FindSession()))
}

func TestRuntimeMaintenanceActivationDisposesRemovedFlowWithoutNewLoop(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	auth := runtimeAdmissionTestPassword(t, svc, "correct")
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Name = "replacement"
	candidate, err := svc.prepareGeneration(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(candidate.generation) {
			<-candidate.generationClosed
		}
	})
	loop := svc.houseKeeper.done
	_, err = svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	require.Equal(t, loop, svc.houseKeeper.done)
	require.Nil(t, candidate.houseKeeper.done)
	require.Eventually(t, func() bool {
		current, err := svc.sessions.FindBy(t.Context(), auth.Flow(), auth.FindSession().Id(), nil)
		if err != nil {
			return false
		}
		info, err := current.Info(t.Context())
		return err == nil && info.State() == session.StateDisposed
	}, 5*time.Second, 5*time.Millisecond)
	require.True(t, svc.sessionConnections.isRevoked(auth.FindSession()))
}

func TestRuntimeMaintenanceSessionActionsSerializeAndCancelWaiters(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	auth := runtimeAdmissionTestPassword(t, svc, "correct")
	owner, _, release, err := svc.retainSessionAction(t.Context(), auth.FindSession())
	require.NoError(t, err)
	defer release()
	require.Same(t, svc, owner)
	ctx, cancel := context.WithCancel(t.Context())
	waiting := make(chan error, 1)
	go func() {
		_, _, release, err := svc.retainSessionAction(ctx, auth.FindSession())
		if release != nil {
			release()
		}
		waiting <- err
	}()
	cancel()
	require.ErrorIs(t, <-waiting, context.Canceled)
	release()
	svc.resources.actionsMutex.Lock()
	require.Empty(t, svc.resources.actions)
	svc.resources.actionsMutex.Unlock()
}

func TestRuntimeMaintenanceManagementDisposesTargetWithItsOwnProvidersAndAuditlog(t *testing.T) {
	svc := runtimeResourcesFixture(t, func(conf *configuration.Configuration) {
		next := conf.Auditlogs[0]
		next.Name = "next"
		root := t.TempDir()
		next.IdentityFile, next.Directory = filepath.Join(root, "identity"), filepath.Join(root, "journal")
		next.Recording.Enabled = false
		conf.Auditlogs = append(conf.Auditlogs, next)
		admin := conf.Flows[0]
		admin.Name, admin.Auditlog = "administration", next.Name
		var management configuration.EnvironmentManagement
		require.NoError(t, management.SetDefaults())
		admin.Environment = configuration.Environment{V: &management}
		conf.Flows = append(conf.Flows, admin)
	})
	require.NoError(t, svc.houseKeeper.Close())
	target := runtimeAdmissionTestPassword(t, svc, "correct").FindSession()
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).Banner = template.MustNewString("changed")
	conf.Flows[0].Auditlog = "next"
	candidate, err := svc.prepareGeneration(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(candidate.generation) {
			<-candidate.generationClosed
		}
	})
	oldEnvironment := &maintenanceTestEnvironmentRepository{CloseableRepository: svc.environments}
	newEnvironment := &maintenanceTestEnvironmentRepository{CloseableRepository: candidate.environments}
	svc.environments, candidate.environments = oldEnvironment, newEnvironment
	oldAudit, newAudit := &recordingAuditRecorder{}, &recordingAuditRecorder{}
	svc.flowAuditRecorders[target.Flow()] = oldAudit
	candidate.flowAuditRecorders[target.Flow()] = newAudit
	candidate.flowAuditRecorders["administration"] = newAudit
	_, err = svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	control := managementSessionControl{service: candidate, task: managementControlTestTask{
		caller: &houseKeeperTestSession{flow: "administration", id: session.MustNewId()},
		conn:   managementControlTestConnection{},
	}}
	result, err := control.Dispose(t.Context(), target.Id())
	require.NoError(t, err)
	require.Equal(t, "dispose", result.Action)
	require.EqualValues(t, 1, oldEnvironment.disposals.Load())
	require.Zero(t, newEnvironment.disposals.Load())
	for _, recorder := range []*recordingAuditRecorder{oldAudit, newAudit} {
		events := recorder.eventsSnapshot()
		require.Len(t, events, 2)
		require.Equal(t, audit.EventNameSessionDisposeStarted, events[0].Name)
		require.Equal(t, audit.EventNameSessionDisposeCompleted, events[1].Name)
	}
}

func TestRuntimeMaintenancePreservesUnownedSessionsAfterReload(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	require.NoError(t, svc.houseKeeper.Close())
	candidate := runtimeResourcesCandidate(t, svc)
	_, err := svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	// A record restored externally after startup must not be implicitly
	// assigned to the newest configuration, even if its flow name still exists.
	unowned, err := svc.sessions.Create(t.Context(), candidate.Configuration.Flows[0].Name, associationAdapterRemote("alice"), []byte("preserve"))
	require.NoError(t, err)
	original := svc.sessions
	svc.sessions = &maintenanceTestRepository{CloseableRepository: original, expired: unowned.Id()}
	_, err = svc.houseKeeper.checkedRun(t.Context())
	require.NoError(t, err)
	require.Nil(t, svc.runtime.sessionOwner(unowned))
	require.False(t, candidate.loginSessionCompatible(unowned))
	require.False(t, svc.houseKeeper.sessionAutoRepairAllowed())
	preserved, err := original.FindBy(t.Context(), unowned.Flow(), unowned.Id(), nil)
	require.NoError(t, err)
	token, err := preserved.AuthorizationToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, []byte("preserve"), token)
}
