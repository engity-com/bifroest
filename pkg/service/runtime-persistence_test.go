package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func runtimePersistenceRestart(t *testing.T, svc *service, conf configuration.Configuration) *service {
	t.Helper()
	return runtimePersistenceRestartContext(t, t.Context(), svc, conf)
}

func runtimePersistenceRestartContext(t *testing.T, ctx context.Context, svc *service, conf configuration.Configuration) *service {
	t.Helper()
	require.NoError(t, svc.Close())
	restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepareContext(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	return restarted
}

func TestRuntimePersistenceOidcComparesResolvedAuthorityOnReloadAndRestart(t *testing.T) {
	for _, phase := range []string{"reload", "restart"} {
		for _, change := range []string{"none", "secret", "token_endpoint", "jwks_uri"} {
			t.Run(phase+"/"+change, func(t *testing.T) {
				ctx, settings := runtimeOidcSettings(t)
				t.Setenv("BIFROEST_RUNTIME_OIDC_SECRET", "original-secret")
				settings.ClientSecret = template.MustNewString(`{{ env "BIFROEST_RUNTIME_OIDC_SECRET" }}`)
				originalClient := ctx.Value(oauth2.HTTPClient).(*http.Client)
				var changed atomic.Bool
				client := &http.Client{Transport: runtimeOidcRoundTripper(func(r *http.Request) (*http.Response, error) {
					response, err := originalClient.Transport.RoundTrip(r)
					if err != nil || !changed.Load() || r.URL.Path != "/.well-known/openid-configuration" || change == "none" || change == "secret" {
						return response, err
					}
					defer response.Body.Close()
					var metadata map[string]any
					if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
						return nil, err
					}
					metadata[change] = settings.Issuer.String() + "/changed"
					raw, err := json.Marshal(metadata)
					if err != nil {
						return nil, err
					}
					response.Body = io.NopCloser(strings.NewReader(string(raw)))
					response.ContentLength = int64(len(raw))
					return response, nil
				})}
				ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
				svc := runtimeResourcesFixtureContext(t, ctx, func(conf *configuration.Configuration) {
					conf.Flows[0].Authorization.V = settings
				})
				sess := runtimeOidcSession(t, svc)
				conf := svc.generation.snapshot.Configuration()
				changed.Store(true)
				if change == "secret" {
					t.Setenv("BIFROEST_RUNTIME_OIDC_SECRET", "changed-secret")
				}
				var next *service
				if phase == "restart" {
					next = runtimePersistenceRestartContext(t, ctx, svc, conf)
				} else {
					var err error
					next, err = svc.prepareGeneration(ctx, conf)
					require.NoError(t, err)
					t.Cleanup(func() {
						if svc.runtime.discard(next.generation) {
							<-next.generationClosed
						}
					})
					_, err = svc.runtime.activate(t.Context(), next.generation)
					require.NoError(t, err)
				}
				require.Equal(t, change == "none", next.loginSessionCompatible(sess))
				if phase == "reload" {
					flow := sess.Flow()
					if change == "none" {
						require.Same(t, svc.generation.flows[flow].actions, next.generation.flows[flow].actions)
					} else {
						require.NotSame(t, svc.generation.flows[flow].actions, next.generation.flows[flow].actions, "resolved authority changes must invalidate new browser actions too")
					}
				}
				if change == "none" && phase == "restart" {
					require.Same(t, next.generation, next.runtime.sessionOwner(sess))
				}
			})
		}
	}
}

func runtimePersistenceOwner(t *testing.T, svc *service, sess session.Session) *session.RuntimeOwnership {
	t.Helper()
	provider, ok := sess.(session.RuntimeOwnershipSession)
	require.True(t, ok)
	owner, err := provider.RuntimeOwnership(t.Context())
	require.NoError(t, err)
	require.NotNil(t, owner)
	require.True(t, owner.Matches(svc.generation.ownership.Flows[sess.Flow()]))
	return owner
}

func TestRuntimePersistenceRestartReusesOnlyExactOwnedSessionAfterFreshCredentials(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	conf := svc.generation.snapshot.Configuration()
	first := runtimeAdmissionTestPassword(t, svc, "correct").FindSession()
	require.NotNil(t, first)
	owner := runtimePersistenceOwner(t, svc, first)
	restarted := runtimePersistenceRestart(t, svc, conf)
	require.False(t, runtimeAdmissionTestPassword(t, restarted, "wrong").IsAuthorized())
	fresh := runtimeAdmissionTestPassword(t, restarted, "correct").FindSession()
	require.Equal(t, first.Id(), fresh.Id())
	require.Equal(t, owner, runtimePersistenceOwner(t, restarted, fresh))
	require.Same(t, restarted.generation, restarted.runtime.sessionOwner(fresh))
}

func TestRuntimePersistenceLegacySessionIsNotImportedOrCleanedByNewProvider(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	conf := svc.generation.snapshot.Configuration()
	flow := conf.Flows[0].Name
	legacy, err := svc.sessions.Create(t.Context(), flow, associationAdapterRemote("alice"), []byte("legacy-credential"))
	require.NoError(t, err)
	require.NoError(t, legacy.SetEnvironmentToken(t.Context(), []byte("unrecognized-existing-backend")))
	restarted := runtimePersistenceRestart(t, svc, conf)
	require.Nil(t, restarted.runtime.sessionOwner(legacy))
	require.False(t, restarted.loginSessionCompatible(legacy))
	require.NoError(t, restarted.houseKeeper.Close())
	environments := &maintenanceTestEnvironmentRepository{CloseableRepository: restarted.environments}
	restarted.environments = environments
	require.NoError(t, restarted.houseKeeper.run(restarted.logger(), t.Context()))
	require.Zero(t, environments.disposals.Load())
	require.Zero(t, environments.cleanups.Load(), "unscoped orphan scans cannot prove ownership of external resources")
	preserved, err := restarted.sessions.FindBy(t.Context(), flow, legacy.Id(), nil)
	require.NoError(t, err)
	token, err := preserved.EnvironmentToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, []byte("unrecognized-existing-backend"), token)
	owner, err := preserved.(session.RuntimeOwnershipSession).RuntimeOwnership(t.Context())
	require.NoError(t, err)
	require.Nil(t, owner)
	fresh := runtimeAdmissionTestPassword(t, restarted, "correct").FindSession()
	require.NotEqual(t, legacy.Id(), fresh.Id())
	runtimePersistenceOwner(t, restarted, fresh)
}

func TestRuntimePersistenceEnvironmentRevertCannotReviveEarlierSessionAfterRestart(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	first := runtimeAdmissionTestPassword(t, svc, "correct").FindSession()
	originalOwner := runtimePersistenceOwner(t, svc, first)
	changed := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(17)
	})
	runtimeSshActivate(t, svc, changed)
	reverted := runtimeSshCandidate(t, changed, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment = svc.generation.snapshot.Configuration().Flows[0].Environment
	})
	runtimeSshActivate(t, svc, reverted)
	current := runtimeAdmissionTestPassword(t, reverted, "correct").FindSession()
	require.NotEqual(t, first.Id(), current.Id())
	require.NotEqual(t, originalOwner.Environment, runtimePersistenceOwner(t, reverted, current).Environment)
	restarted := runtimePersistenceRestart(t, svc, reverted.generation.snapshot.Configuration())
	require.Nil(t, restarted.runtime.sessionOwner(first))
	require.Equal(t, current.Id(), runtimeAdmissionTestPassword(t, restarted, "correct").FindSession().Id())
}

func TestRuntimePersistenceChangedAuthorizationDoesNotReinterpretOldOwnerAfterRestart(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	first := runtimeAdmissionTestPassword(t, svc, "correct").FindSession()
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
	restarted := runtimePersistenceRestart(t, svc, conf)
	require.Nil(t, restarted.runtime.sessionOwner(first))
	require.False(t, runtimeAdmissionTestPassword(t, restarted, "correct").IsAuthorized())
	fresh := runtimeAdmissionTestPassword(t, restarted, "changed").FindSession()
	require.NotEqual(t, first.Id(), fresh.Id())
}

func TestRuntimePersistenceIndividualRevocationSurvivesWithoutDisposal(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	require.NoError(t, svc.houseKeeper.Close())
	conf := svc.generation.snapshot.Configuration()
	first := runtimeAdmissionTestPassword(t, svc, "correct").FindSession()
	require.NoError(t, svc.sessionConnections.revoke(first.Flow(), first.Id()))
	revoked, err := first.(session.RuntimeOwnershipSession).RuntimeRevoked(t.Context())
	require.NoError(t, err)
	require.True(t, revoked)
	valid, err := session.IsStillValid(t.Context(), first)
	require.NoError(t, err)
	require.True(t, valid, "this test must exercise a durable tombstone, not disposed session metadata")
	restarted := runtimePersistenceRestart(t, svc, conf)
	require.True(t, restarted.runtime.sessionRevoked(first))
	require.NotEqual(t, first.Id(), runtimeAdmissionTestPassword(t, restarted, "correct").FindSession().Id())
}

type runtimePersistenceTestRepository struct {
	session.RuntimeRepository
	commit func(context.Context, session.RuntimeRevision, session.RuntimeState) session.RuntimeCommit
}

func (this *runtimePersistenceTestRepository) CommitRuntimeState(ctx context.Context, expected session.RuntimeRevision, next session.RuntimeState) session.RuntimeCommit {
	return this.commit(ctx, expected, next)
}

func TestRuntimePersistencePreCommitFailureKeepsRegistryListenersAndDurableState(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, nil)
	scope, physical := run.scope(t, "SSH", svc.Configuration.Ssh.Addresses[0].String(), 0)
	repository := svc.runtime.persistence.repository
	before, err := repository.RuntimeState(t.Context())
	require.NoError(t, err)
	injected := errors.New("injected persistence failure")
	svc.runtime.persistence.repository = &runtimePersistenceTestRepository{RuntimeRepository: repository, commit: func(context.Context, session.RuntimeRevision, session.RuntimeState) session.RuntimeCommit {
		return session.RuntimeCommit{Err: injected}
	}}
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Ssh.Addresses = append(conf.Ssh.Addresses, conf.Ssh.Addresses[0])
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
	})
	activation, err := svc.activateGeneration(t.Context(), next)
	require.ErrorIs(t, err, injected)
	require.Nil(t, activation)
	require.Same(t, svc.generation, svc.runtime.current)
	require.False(t, next.generation.activated)
	retained, original := run.scope(t, "SSH", svc.Configuration.Ssh.Addresses[0].String(), 0)
	require.Same(t, scope, retained)
	require.Same(t, physical, original)
	after, err := repository.RuntimeState(t.Context())
	require.NoError(t, err)
	require.Equal(t, before, after)
	runtimeSshRun(t, runtimeSshDial(t, svc, physical.Addr().String(), "correct"), 0)
}

func TestRuntimePersistencePublishedWriteIsAcceptedDespiteCancellationAndSyncError(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, nil)
	_, physical := run.scope(t, "SSH", svc.Configuration.Ssh.Addresses[0].String(), 0)
	repository := svc.runtime.persistence.repository
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	injected := errors.New("injected post-publication sync error")
	svc.runtime.persistence.repository = &runtimePersistenceTestRepository{RuntimeRepository: repository, commit: func(ctx context.Context, expected session.RuntimeRevision, next session.RuntimeState) session.RuntimeCommit {
		// These operations would deadlock if persistence held registry, topology
		// or admission locks. Old admission must remain available during I/O.
		_, release, err := svc.runtime.selectCurrent()
		require.NoError(t, err)
		release()
		run.inputs.mutex.Lock()
		require.True(t, run.inputs.ready)
		run.inputs.mutex.Unlock()
		client := runtimeSshDial(t, svc, physical.Addr().String(), "correct")
		require.NoError(t, client.Close())
		result := repository.CommitRuntimeState(ctx, expected, next)
		require.True(t, result.Published)
		require.NoError(t, result.Err)
		cancel()
		result.Err = injected
		return result
	}}
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
	})
	activation, err := svc.activateGeneration(ctx, next)
	require.NoError(t, err)
	require.ErrorIs(t, activation.cleanupErr, injected)
	require.Same(t, next.generation, svc.runtime.current)
	state, err := repository.RuntimeState(t.Context())
	require.NoError(t, err)
	require.Equal(t, next.generation.ownership, state)
	runtimeSshRun(t, runtimeSshDial(t, svc, physical.Addr().String(), "changed"), 0)
}

func TestRuntimePersistenceUncertainWriteStopsAdmissionInsteadOfGuessing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result session.RuntimeCommit
	}{
		{"uncertain", session.RuntimeCommit{Uncertain: true, Err: errors.New("injected uncertain write")}},
		{"contradictory", session.RuntimeCommit{Published: true, Uncertain: true}},
		{"missing-result", session.RuntimeCommit{}},
		{"conflict", session.RuntimeCommit{Err: session.ErrRuntimeStateConflict}},
		{"damaged", session.RuntimeCommit{Err: session.ErrInvalidRuntimeState}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			repository := svc.runtime.persistence.repository
			svc.runtime.persistence.repository = &runtimePersistenceTestRepository{RuntimeRepository: repository, commit: func(context.Context, session.RuntimeRevision, session.RuntimeState) session.RuntimeCommit {
				return tc.result
			}}
			next := runtimeResourcesCandidate(t, svc)
			activation, err := svc.runtime.activate(t.Context(), next.generation)
			require.ErrorIs(t, err, errUncertainRuntimeCommit)
			require.Nil(t, activation)
			selection, _, err := svc.runtime.selectCurrent()
			require.ErrorIs(t, err, context.Canceled)
			require.Nil(t, selection)
			require.False(t, next.generation.activated)
		})
	}
}

func TestRuntimePersistenceActualCASConflictStopsAdmissionAndPreservesWinner(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	next := runtimeResourcesCandidate(t, svc)
	repository := svc.runtime.persistence.repository
	digests, err := svc.generation.snapshot.RuntimeDigests(svc.runtime.persistence.key)
	require.NoError(t, err)
	winner, err := session.AdvanceRuntimeState(svc.generation.ownership, digests)
	require.NoError(t, err)
	require.NoError(t, repository.CommitRuntimeState(t.Context(), svc.generation.ownership.Revision, *winner).Err)
	_, err = svc.runtime.activate(t.Context(), next.generation)
	require.ErrorIs(t, err, session.ErrRuntimeStateConflict)
	require.ErrorIs(t, err, errUncertainRuntimeCommit)
	require.False(t, next.generation.activated)
	require.True(t, svc.runtime.stopped)
	retained, err := repository.RuntimeState(t.Context())
	require.NoError(t, err)
	require.Equal(t, winner, retained)
}

func TestRuntimePersistenceStartupRejectsUnfinishedOrDamagedStateWithoutRepair(t *testing.T) {
	for _, mode := range []string{"pending", "damaged"} {
		t.Run(mode, func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			require.NotNil(t, runtimeAdmissionTestPassword(t, svc, "correct").FindSession())
			conf := svc.generation.snapshot.Configuration()
			storage, err := filepath.EvalSymlinks(conf.Session.V.(*configuration.SessionFs).Storage)
			require.NoError(t, err)
			path := filepath.Join(filepath.Dir(storage), "."+filepath.Base(storage)+session.FsFileRuntimeState)
			if mode == "pending" {
				path = filepath.Join(filepath.Dir(storage), "."+filepath.Base(storage)+session.FsFileRuntimePending)
			}
			require.NoError(t, svc.Close())
			raw := []byte("private-unfinished-authority")
			require.NoError(t, os.WriteFile(path, raw, 0600))
			restarted, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepareContext(t.Context())
			require.ErrorIs(t, err, session.ErrInvalidRuntimeState)
			require.Nil(t, restarted)
			require.NotContains(t, err.Error(), string(raw))
			retained, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, raw, retained)
		})
	}
}

type runtimePersistenceTestRevoker func(context.Context, configuration.FlowName, session.Id) error

func (this runtimePersistenceTestRevoker) RevokeRuntimeSession(ctx context.Context, flow configuration.FlowName, id session.Id) error {
	return this(ctx, flow, id)
}

func TestRuntimePersistenceRevocationWriteFailureStopsAdmission(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	sess := runtimeAdmissionTestPassword(t, svc, "correct").FindSession()
	injected := errors.New("injected tombstone write failure")
	svc.runtime.persistence.revoker = runtimePersistenceTestRevoker(func(context.Context, configuration.FlowName, session.Id) error {
		return injected
	})
	require.ErrorIs(t, svc.sessionConnections.revoke(sess.Flow(), sess.Id()), injected)
	require.True(t, svc.runtime.sessionRevoked(sess))
	_, _, err := svc.runtime.selectCurrent()
	require.ErrorIs(t, err, context.Canceled)
}

func TestRuntimePersistenceShutdownJoinsAnAlreadyPublishedCommit(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	repository := svc.runtime.persistence.repository
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	svc.runtime.persistence.repository = &runtimePersistenceTestRepository{RuntimeRepository: repository, commit: func(ctx context.Context, expected session.RuntimeRevision, next session.RuntimeState) session.RuntimeCommit {
		result := repository.CommitRuntimeState(ctx, expected, next)
		close(entered)
		<-release
		return result
	}}
	next := runtimeResourcesCandidate(t, svc)
	activated := make(chan error, 1)
	go func() { _, err := svc.runtime.activate(t.Context(), next.generation); activated <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("durable commit did not publish")
	}
	closed := make(chan error, 1)
	go func() { closed <- svc.Close() }()
	select {
	case <-svc.resources.ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not cancel preparation")
	}
	select {
	case err := <-closed:
		t.Fatalf("shutdown abandoned an in-flight committed activation: %v", err)
	default:
	}
	unblock()
	require.NoError(t, <-activated)
	require.NoError(t, <-closed)
	require.True(t, next.generation.activated)
	state, err := repository.RuntimeState(t.Context())
	require.NoError(t, err)
	require.Equal(t, next.generation.ownership, state)
}
