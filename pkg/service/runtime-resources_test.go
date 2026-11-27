package service

import (
	"context"
	goerrors "errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func runtimeResourcesFixture(t *testing.T, configure ...func(*configuration.Configuration)) *service {
	t.Helper()
	return runtimeResourcesFixtureContext(t, context.Background(), configure...)
}

func runtimeResourcesFixtureContext(t *testing.T, ctx context.Context, configure ...func(*configuration.Configuration)) *service {
	t.Helper()
	conf := sessionRecordingTestConfiguration(t, t.TempDir())
	conf.HouseKeeping.InitialDelay = common.DurationOf(time.Hour)
	conf.Flows[0].Authorization.V = &configuration.AuthorizationSimple{
		Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}},
	}
	enableSessionRecording(&conf.Auditlogs[0])
	for _, fn := range configure {
		fn(&conf)
	}
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepareContext(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return svc
}

func runtimeResourcesCandidate(t *testing.T, svc *service) *service {
	t.Helper()
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Title = "candidate"
	candidate, err := svc.prepareGeneration(t.Context(), conf)
	require.NoError(t, err)
	// Activated generations are cleaned by the process owner, not Close.
	t.Cleanup(func() {
		if svc.runtime.discard(candidate.generation) {
			<-candidate.generationClosed
		}
	})
	return candidate
}

func runtimeResourcesWaitClosed(t *testing.T, svc *service) {
	t.Helper()
	select {
	case <-svc.generationClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("generation resources did not close")
	}
}

func TestRuntimeResourcesCandidateBorrowsWritersAndDoesNotStartWorkers(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	candidate := runtimeResourcesCandidate(t, svc)
	require.Same(t, svc.sessions, candidate.sessions)
	require.Same(t, svc.imp, candidate.imp)
	require.Same(t, svc.alternatives, candidate.alternatives)
	name := svc.Configuration.Auditlogs[0].Name
	require.Same(t, svc.auditRecorders[name], candidate.auditRecorders[name])
	require.Same(t, svc.recordingRepositories[name], candidate.recordingRepositories[name])
	require.NotSame(t, svc.authorizer, candidate.authorizer)
	require.NotSame(t, svc.environments, candidate.environments)
	require.NotSame(t, svc.managementApplication, candidate.managementApplication)
	require.Nil(t, candidate.houseKeeper.done)
	require.Nil(t, candidate.oidcRefresh.ctx)
	require.Nil(t, candidate.https)
	require.Nil(t, candidate.web)
	require.Nil(t, candidate.sshTunnel)
	require.Empty(t, candidate.auditRecorderOrder, "only the process owner closes shared writers")
	require.Empty(t, candidate.recordingRepositoryOrder)
	firstMAC, err := svc.managementAuditCursorMAC([]byte("cursor"))
	require.NoError(t, err)
	secondMAC, err := candidate.managementAuditCursorMAC([]byte("cursor"))
	require.NoError(t, err)
	require.Equal(t, firstMAC, secondMAC, "management cursor integrity belongs to the shared process")
	require.NoError(t, candidate.Close())
	require.NoError(t, candidate.Close())
	require.True(t, svc.runtime.allowFlow(svc.generation, svc.Configuration.Flows[0].Name))
	require.True(t, runtimeAdmissionTestPassword(t, svc, "correct").IsAuthorized())
	require.NoError(t, svc.recordingRepositories[name].receipts.ValidateDeliveryTargets(t.Context(), svc.recordingRepositories[name], nil))
}

func TestRuntimeResourcesRetiredProvidersWaitForEveryLease(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	auth := runtimeAdmissionTestPassword(t, svc, "correct")
	require.True(t, auth.IsAuthorized())
	_, releaseHandler := runtimeGenerationTestAdmit(t, svc.runtime, svc.generation, auth.FindSession())
	releaseExecution, err := svc.retainRuntime()
	require.NoError(t, err)
	defer releaseExecution()
	candidate := runtimeResourcesCandidate(t, svc)
	_, err = svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	select {
	case <-svc.generationClosed:
		t.Fatal("providers closed while a persisted session still owns them")
	default:
	}
	require.NoError(t, svc.sessions.Delete(t.Context(), auth.FindSession()))
	svc.runtime.finalSessionDeleted(auth.Flow(), auth.FindSession().Id())
	releaseHandler()
	select {
	case <-svc.generationClosed:
		t.Fatal("providers closed before the execution lease ended")
	default:
	}
	releaseExecution()
	runtimeResourcesWaitClosed(t, svc)
	require.True(t, runtimeAdmissionTestPassword(t, candidate, "correct").IsAuthorized())
	require.ErrorContains(t, candidate.Close(), "activated")
	require.NoError(t, svc.Close())
	runtimeResourcesWaitClosed(t, candidate)
}

func TestRuntimeResourcesFailedEnvironmentPreparationPreservesCurrent(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Environment.V = &configuration.EnvironmentSsh{
		Address:        template.MustNewString("target.example.org:22"),
		User:           template.MustNewString("alice"),
		KnownHostsFile: crypto.KnownHostsFile(filepath.Join(t.TempDir(), "missing-known-hosts")),
	}
	// Get complete SSH defaults through the normal loader.
	require.NoError(t, conf.Flows[0].Environment.V.SetDefaults())
	conf.Flows[0].Environment.V.(*configuration.EnvironmentSsh).KnownHostsFile = crypto.KnownHostsFile(filepath.Join(t.TempDir(), "missing-known-hosts"))
	candidate, err := svc.prepareGeneration(t.Context(), conf)
	require.Error(t, err)
	require.Nil(t, candidate)
	require.Same(t, svc.generation, svc.runtime.current)
	require.True(t, runtimeAdmissionTestPassword(t, svc, "correct").IsAuthorized())
	svc.resources.mutex.Lock()
	require.Len(t, svc.resources.views, 1)
	svc.resources.mutex.Unlock()
	svc.resources.keysMutex.Lock()
	require.Empty(t, svc.resources.sshKeys)
	svc.resources.keysMutex.Unlock()
}

func TestRuntimeResourcesRejectsSharedConfigurationChanges(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	conf := svc.generation.snapshot.Configuration()
	conf.Session.V.(*configuration.SessionFs).Storage = filepath.Join(t.TempDir(), "new-storage")
	candidate, err := svc.prepareGeneration(t.Context(), conf)
	require.ErrorContains(t, err, "requires restart: session")
	require.Nil(t, candidate)
	require.Same(t, svc.generation, svc.runtime.current)
	require.True(t, runtimeAdmissionTestPassword(t, svc, "correct").IsAuthorized())
}

type runtimeResourcesSessionCloser struct {
	session.CloseableRepository
	closes atomic.Int32
	err    error
}

func (this *runtimeResourcesSessionCloser) Close() error {
	this.closes.Add(1)
	if this.CloseableRepository == nil {
		return this.err
	}
	return goerrors.Join(this.err, this.CloseableRepository.Close())
}

type runtimeResourcesAuthorizerCloser struct {
	authorization.CloseableAuthorizer
	closes atomic.Int32
}

func (this *runtimeResourcesAuthorizerCloser) Close() error {
	this.closes.Add(1)
	return this.CloseableAuthorizer.Close()
}

func TestRuntimeResourcesShutdownClosesSharedHandlesAndProvidersOnce(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	sessions := &runtimeResourcesSessionCloser{CloseableRepository: svc.sessions}
	svc.sessions = sessions
	authorizer := &runtimeResourcesAuthorizerCloser{CloseableAuthorizer: svc.authorizer}
	svc.authorizer = authorizer
	candidate := runtimeResourcesCandidate(t, svc)
	require.NoError(t, candidate.Close())
	require.Zero(t, sessions.closes.Load())
	require.Zero(t, authorizer.closes.Load())
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() { require.NoError(t, svc.Close()) })
	}
	workers.Wait()
	require.EqualValues(t, 1, sessions.closes.Load())
	require.EqualValues(t, 1, authorizer.closes.Load())
	require.NoError(t, candidate.Close())
	_, err := svc.prepareGeneration(t.Context(), svc.Configuration)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRuntimeResourcesShutdownCancelsAndWaitsForPreparation(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	lifetime, _, finish, err := svc.resources.beginPreparation(t.Context())
	require.NoError(t, err)
	finishOnce := sync.OnceFunc(func() { finish(false) })
	defer finishOnce()
	closed := make(chan error, 1)
	go func() { closed <- svc.Close() }()
	select {
	case <-lifetime.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not cancel pending preparation")
	}
	select {
	case err := <-closed:
		t.Fatalf("shared resources closed during preparation: %v", err)
	default:
	}
	finishOnce()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish after preparation released its dependencies")
	}
}

func TestRuntimeResourcesCloseErrorIsStableAndHandlesCloseOnce(t *testing.T) {
	snapshot := runtimeGenerationTestSnapshot(t, runtimeGenerationTestSource)
	registry := newRuntimeGenerations(snapshot)
	failure := goerrors.New("session close failed")
	sessions := &runtimeResourcesSessionCloser{err: failure}
	svc := &service{
		Service: &Service{Configuration: snapshot.Configuration()}, runtime: registry,
		generation: registry.initial, generationClosed: make(chan struct{}), sessions: sessions,
	}
	svc.resources = newRuntimeResources(svc)
	svc.resources.track(svc)
	require.ErrorIs(t, svc.Close(), failure)
	require.ErrorIs(t, svc.Close(), failure)
	require.EqualValues(t, 1, sessions.closes.Load())
}

func TestRuntimeResourcesProviderContextOutlivesReloadRequest(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	lifetime, stop, finish, err := svc.resources.beginPreparation(ctx)
	require.NoError(t, err)
	defer stop()
	finish(true)
	cancel()
	require.NoError(t, lifetime.Err())
}

func TestRuntimeResourcesPreparationRacesShutdown(t *testing.T) {
	for range 20 {
		svc := runtimeResourcesFixture(t)
		conf := svc.generation.snapshot.Configuration()
		conf.Flows[0].Title = "racing candidate"
		type result struct {
			candidate *service
			err       error
		}
		prepared := make(chan result, 1)
		closed := make(chan error, 1)
		go func() {
			candidate, err := svc.prepareGeneration(t.Context(), conf)
			prepared <- result{candidate, err}
		}()
		go func() { closed <- svc.Close() }()
		select {
		case result := <-prepared:
			if result.err != nil {
				require.ErrorIs(t, result.err, context.Canceled)
				require.Nil(t, result.candidate)
			} else {
				require.NoError(t, result.candidate.Close())
			}
		case <-time.After(5 * time.Second):
			t.Fatal("preparation did not finish during shutdown")
		}
		select {
		case err := <-closed:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown did not finish after candidate preparation")
		}
		svc.resources.mutex.Lock()
		require.Empty(t, svc.resources.views)
		svc.resources.mutex.Unlock()
	}
}

func TestRuntimeResourcesGenerationsShareSessionAssociationLock(t *testing.T) {
	svc := runtimeResourcesFixture(t, func(conf *configuration.Configuration) {
		var ssh configuration.EnvironmentSsh
		require.NoError(t, ssh.SetDefaults())
		ssh.Address, ssh.User = template.MustNewString("target.example.org:22"), template.MustNewString("alice")
		ssh.AcceptAllHostKeys = true
		conf.Flows[0].Environment.V = &ssh
	})
	// Simulate an admitted old handshake before preparing the new definition.
	release, err := svc.retainRuntime()
	require.NoError(t, err)
	defer release()
	candidate := runtimeResourcesCandidate(t, svc)
	_, err = svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	requests := []*passwordAuthorizeRequest{
		{authorizeRequest: authorizeRequest{service: svc, connection: runtimeAdmissionTestTransport(t)}, password: "correct"},
		{authorizeRequest: authorizeRequest{service: candidate, connection: runtimeAdmissionTestTransport(t)}, password: "correct"},
	}
	type result struct {
		auth authorization.Authorization
		err  error
	}
	results := make(chan result, len(requests))
	for _, request := range requests {
		go func() {
			auth, err := request.service.authorizer.AuthorizePassword(request)
			results <- result{auth, err}
		}()
	}
	first, second := <-results, <-results
	require.NoError(t, first.err)
	require.NoError(t, second.err)
	require.True(t, first.auth.IsAuthorized())
	require.True(t, second.auth.IsAuthorized())
	require.Equal(t, first.auth.FindSession().Id(), second.auth.FindSession().Id())
	var count int
	require.NoError(t, svc.sessions.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) {
		count++
		return true, nil
	}, nil))
	require.Equal(t, 1, count, "independent per-generation store locks must not create duplicate associated sessions")
}

func TestRuntimeResourcesSSHKeyCannotReuseSharedAuditOrTLSKeys(t *testing.T) {
	for _, kind := range []string{"signing", "tls"} {
		t.Run(kind, func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			var path string
			if kind == "signing" {
				// Different path, same key material: path-overlap checks alone
				// cannot catch this reuse.
				encoded, err := os.ReadFile(svc.Configuration.Auditlogs[0].IdentityFile)
				require.NoError(t, err)
				path = filepath.Join(t.TempDir(), "copied-signing-key")
				require.NoError(t, os.WriteFile(path, encoded, 0600))
			} else {
				path = filepath.Join(t.TempDir(), "tls-key")
				key, err := crypto.EnsureKeyFile(path, &crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}, nil)
				require.NoError(t, err)
				require.NoError(t, svc.validateHTTPSKey(key.PublicKey().ToSdk()))
			}
			conf := svc.generation.snapshot.Configuration()
			var ssh configuration.EnvironmentSsh
			require.NoError(t, ssh.SetDefaults())
			ssh.Address, ssh.User = template.MustNewString("target.example.org:22"), template.MustNewString("alice")
			ssh.AcceptAllHostKeys = true
			ssh.IdentityFiles = template.Strings{template.MustNewString(path)}
			conf.Flows[0].Environment.V = &ssh
			candidate, err := svc.prepareGeneration(t.Context(), conf)
			require.ErrorContains(t, err, "must be distinct")
			require.Nil(t, candidate)
			require.Same(t, svc.generation, svc.runtime.current)
		})
	}
}

func TestRuntimeResourcesTLSKeyCannotReusePreparedSSHKey(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	path := filepath.Join(t.TempDir(), "ssh-environment-key")
	key, err := crypto.EnsureKeyFile(path, &crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}, nil)
	require.NoError(t, err)
	conf := svc.generation.snapshot.Configuration()
	var ssh configuration.EnvironmentSsh
	require.NoError(t, ssh.SetDefaults())
	ssh.Address, ssh.User = template.MustNewString("target.example.org:22"), template.MustNewString("alice")
	ssh.AcceptAllHostKeys = true
	ssh.IdentityFiles = template.Strings{template.MustNewString(path)}
	conf.Flows[0].Environment.V = &ssh
	candidate, err := svc.prepareGeneration(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, candidate.Close()) })
	require.ErrorContains(t, svc.validateHTTPSKey(key.PublicKey().ToSdk()), "prepared and retained")
	require.NoError(t, candidate.Close())
	require.NoError(t, svc.validateHTTPSKey(key.PublicKey().ToSdk()))
}
