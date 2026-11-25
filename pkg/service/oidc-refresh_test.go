package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	goerrors "errors"
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type oidcRefreshTestRepository struct {
	*houseKeeperTestSessionRepository
	findBy func(context.Context, configuration.FlowName, session.Id, *session.FindOpts) (session.Session, error)
}

type oidcRefreshSynchronizedSession struct {
	*houseKeeperTestSession
	mutex sync.Mutex
}

func (this *oidcRefreshSynchronizedSession) AuthorizationToken(ctx context.Context) ([]byte, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.houseKeeperTestSession.AuthorizationToken(ctx)
}

func (this *oidcRefreshSynchronizedSession) SetAuthorizationToken(ctx context.Context, token []byte) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.houseKeeperTestSession.SetAuthorizationToken(ctx, token)
}

func (this *oidcRefreshTestRepository) FindBy(ctx context.Context, flow configuration.FlowName, id session.Id, opts *session.FindOpts) (session.Session, error) {
	return this.findBy(ctx, flow, id, opts)
}

func oidcRefreshTestConfig(t *testing.T, tokenHandler ...http.HandlerFunc) (context.Context, *configuration.AuthorizationOidcDeviceAuth) {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" && len(tokenHandler) != 0 {
			tokenHandler[0](w, r)
			return
		}
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
			"device_authorization_endpoint": server.URL + "/device",
			"token_endpoint":                server.URL + "/token", "jwks_uri": server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(server.Close)
	return context.WithValue(context.Background(), oauth2.HTTPClient, server.Client()), &configuration.AuthorizationOidcDeviceAuth{
		Issuer: template.MustNewUrl(server.URL), ClientId: template.MustNewString("client"),
		ClientSecret: template.MustNewString("secret"), Scopes: template.MustNewStrings("openid"),
		ForceDisposeSessionOn: "lostAccess",
		RefreshToken:          configuration.AuthorizationOidcRefreshToken{Mode: "proactive"},
	}
}

func oidcRefreshWatchdogFixture(t *testing.T, ctx context.Context, conf *configuration.AuthorizationOidcDeviceAuth, findBy func(context.Context, configuration.FlowName, session.Id, *session.FindOpts) (session.Session, error), token []byte) (*oidcRefreshManager, *service, *houseKeeperTestSession, *connection, *recordingAuditRecorder) {
	t.Helper()
	if conf.RefreshToken.MaxUnverifiedFor.Native() == 0 {
		conf.RefreshToken.MaxUnverifiedFor = common.DurationOf(time.Second)
	}
	authorizer, err := authorization.NewOidcDeviceAuth(ctx, "current", conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, authorizer.Close()) })
	sess := &houseKeeperTestSession{flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(time.Hour), authorizationToken: token}
	repository := &oidcRefreshTestRepository{houseKeeperTestSessionRepository: &houseKeeperTestSessionRepository{}}
	if findBy == nil {
		synchronized := &oidcRefreshSynchronizedSession{houseKeeperTestSession: sess}
		findBy = func(context.Context, configuration.FlowName, session.Id, *session.FindOpts) (session.Session, error) {
			return synchronized, nil
		}
	}
	repository.findBy = findBy
	hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, &houseKeeperTestAuthorizer{restoreErr: authorization.ErrNoSuchAuthorization})
	svc := hk.service
	svc.sessions = repository
	svc.houseKeeper.service = svc
	svc.Configuration.Flows = configuration.Flows{{Name: sess.flow, Authorization: configuration.Authorization{V: conf}}}
	recorder := &recordingAuditRecorder{}
	svc.flowAuditRecorders[sess.flow] = recorder
	manager := &svc.oidcRefresh
	manager.service = svc
	manager.authorizers = map[configuration.FlowName]*authorization.OidcDeviceAuthAuthorizer{sess.flow: authorizer}
	manager.workers = make(map[sessionConnectionKey]context.CancelFunc)
	manager.limit = make(chan struct{}, 1)
	manager.ctx, manager.cancel = context.WithCancel(ctx)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	conn := newTrackedSessionConnection(t, svc)
	svc.sessionConnections.track(conn, sess)
	return manager, svc, sess, conn, recorder
}

func oidcRefreshWatchdogToken(t *testing.T, lastVerified time.Time) []byte {
	t.Helper()
	token, err := json.Marshal(map[string]any{
		"access_token": "access", "token_type": "Bearer", "refresh_token": "refresh",
		"subject": "user", "issuer": "issuer", "lastVerifiedAt": lastVerified.UTC(),
		"receivedAt": time.Now().UTC(), "expiry": time.Now().Add(300 * time.Millisecond).UTC(),
	})
	require.NoError(t, err)
	return token
}

func TestOidcRefreshWatchdogAcceptsReconnectVerification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, conf := oidcRefreshTimingConfig(t)
		manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, time.Now()))
		key := sessionConnectionKey{flow: sess.flow, id: sess.id}
		deadlines := make(chan time.Time, 1)
		manager.deadlines = map[sessionConnectionKey]chan time.Time{key: deadlines}
		parentCtx, cancel := context.WithCancel(manager.ctx)
		workerCtx, stopWorker := context.WithCancel(parentCtx)
		defer stopWorker()
		stop := make(chan struct{})
		finished := make(chan struct{})
		t.Cleanup(func() { cancel(); close(stop); <-finished })
		go func() {
			defer close(finished)
			manager.watchDeadline(parentCtx, workerCtx, stopWorker, stop, key, deadlines)
		}()
		old := time.Now().Add(2 * time.Second)
		manager.verificationUpdated(sess, old)
		synctest.Sleep(100 * time.Millisecond)
		fresh := time.Now().Add(5 * time.Second)
		manager.verificationUpdated(sess, fresh)
		// A worker may report an older token after a reconnect persisted the newer one.
		manager.verificationUpdated(sess, time.Now().Add(500*time.Millisecond))
		synctest.Sleep(time.Until(old))
		require.False(t, conn.closed.Load(), "a newly verified grant must supersede the previous deadline")
		require.Equal(t, fresh, oidcRefreshTimingDeadlines(manager)[key])
		synctest.Sleep(time.Until(fresh) - time.Nanosecond)
		require.False(t, conn.closed.Load())
		require.Empty(t, recorder.eventsSnapshot())
		synctest.Sleep(time.Nanosecond)
		<-finished
		require.ErrorIs(t, workerCtx.Err(), context.Canceled)
		oidcRefreshTimingAssertDisposed(t, manager, sess, conn, recorder)
	})
}

func TestOidcRefreshWatchdogChecksQueuedDeadlineAfterTimer(t *testing.T) {
	for _, mode := range []string{"latest accepted update", "queued notification"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, conf := oidcRefreshTimingConfig(t)
				manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, time.Now()))
				key := sessionConnectionKey{flow: sess.flow, id: sess.id}
				updates := make(chan time.Time, 1)
				manager.deadlines = map[sessionConnectionKey]chan time.Time{key: updates}
				parent, cancel := context.WithCancel(manager.ctx)
				worker, stopWorker := context.WithCancel(parent)
				defer stopWorker()
				gate := &oidcRefreshTimingTimerGate{Context: worker, entered: make(chan struct{}), resume: make(chan struct{}, 1)}
				stop := make(chan struct{})
				finished := make(chan struct{})
				t.Cleanup(func() { cancel(); close(gate.resume); close(stop); <-finished })
				go func() {
					defer close(finished)
					manager.watchDeadline(parent, gate, stopWorker, stop, key, updates)
				}()
				old := time.Now().Add(150 * time.Millisecond)
				manager.verificationUpdated(sess, old)
				synctest.Sleep(time.Until(old) - time.Nanosecond)
				select {
				case <-gate.entered:
					t.Fatal("watchdog timer fired before its deadline")
				default:
				}
				synctest.Sleep(time.Nanosecond)
				<-gate.entered // The old timer branch has definitely been selected.
				fresh := time.Now().Add(time.Second)
				if mode == "latest accepted update" {
					manager.verificationUpdated(sess, fresh)
				} else {
					updates <- fresh // Exercise the queued-channel fallback, not lastDeadlines.
				}
				require.Len(t, updates, 1)
				gate.resume <- struct{}{}
				synctest.Wait()
				require.False(t, conn.closed.Load(), "queued persisted verification must win over an expired timer")
				require.NoError(t, worker.Err())
				synctest.Sleep(time.Until(fresh) - time.Nanosecond)
				require.False(t, conn.closed.Load())
				require.Empty(t, recorder.eventsSnapshot())
				synctest.Sleep(time.Nanosecond)
				<-finished
				oidcRefreshTimingAssertDisposed(t, manager, sess, conn, recorder)
			})
		})
	}
}

type oidcRefreshReadOnlySession struct {
	*houseKeeperTestSession
	token []byte
}

func (this *oidcRefreshReadOnlySession) AuthorizationToken(context.Context) ([]byte, error) {
	return append([]byte(nil), this.token...), nil
}

func TestOidcRefreshStartupDeadlineDoesNotWaitForCollidingProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		release := make(chan struct{})
		defer close(release)
		var once sync.Once
		ctx, conf := oidcRefreshTimingConfig(t, func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(requested) })
			select {
			case <-r.Context().Done():
			case <-release:
			}
		})
		conf.RefreshToken.MaxUnverifiedFor = common.DurationOf(4 * time.Second)
		authorizer, err := authorization.NewOidcDeviceAuth(ctx, "current", conf)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, authorizer.Close()) })
		sessions := make(map[session.Id]*oidcRefreshReadOnlySession)
		flow := configuration.FlowName("current")
		start := time.Now()
		var nextID uint64
		makeSession := func(expiry time.Time) *oidcRefreshReadOnlySession {
			nextID++
			var id session.Id
			binary.BigEndian.PutUint64(id[8:], nextID)
			sess := &oidcRefreshReadOnlySession{houseKeeperTestSession: &houseKeeperTestSession{
				flow: flow, id: id, validUntil: start.Add(time.Hour),
			}}
			token, marshalErr := json.Marshal(map[string]any{
				"access_token": "access", "token_type": "Bearer", "refresh_token": "refresh",
				"subject": "user", "issuer": "issuer", "lastVerifiedAt": start.UTC(),
				"receivedAt": start.UTC(), "expiry": expiry.UTC(),
			})
			require.NoError(t, marshalErr)
			sess.token = token
			return sess
		}
		first := makeSession(start.Add(200 * time.Millisecond))
		sessions[first.id] = first
		shard := func(sess *oidcRefreshReadOnlySession) uint32 {
			h := fnv.New32a()
			_, _ = h.Write([]byte(sess.String()))
			return h.Sum32() % 64
		}
		var peers []*oidcRefreshReadOnlySession
		for len(peers) < 99 {
			candidate := makeSession(start.Add(time.Hour))
			if len(peers) == 0 && shard(candidate) != shard(first) {
				continue
			}
			peers = append(peers, candidate)
			sessions[candidate.id] = candidate
		}
		require.Equal(t, shard(first), shard(peers[0]), "the fixture must contain an actual refresh-lock collision")
		repository := &oidcRefreshTestRepository{houseKeeperTestSessionRepository: &houseKeeperTestSessionRepository{}}
		repository.findBy = func(_ context.Context, _ configuration.FlowName, id session.Id, _ *session.FindOpts) (session.Session, error) {
			return sessions[id], nil
		}
		hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, &houseKeeperTestAuthorizer{restoreErr: authorization.ErrNoSuchAuthorization})
		svc := hk.service
		svc.sessions = repository
		svc.houseKeeper.service = svc
		svc.Configuration.Flows = configuration.Flows{{Name: flow, Authorization: configuration.Authorization{V: conf}}}
		manager := &svc.oidcRefresh
		manager.service = svc
		manager.authorizers = map[configuration.FlowName]*authorization.OidcDeviceAuthAuthorizer{flow: authorizer}
		manager.workers = make(map[sessionConnectionKey]context.CancelFunc)
		manager.limit = make(chan struct{}, 8)
		manager.ctx, manager.cancel = context.WithCancel(ctx)
		t.Cleanup(func() { require.NoError(t, manager.Close()) })
		manager.register(first)
		<-requested
		connections := make([]*connection, 0, len(peers))
		for _, peer := range peers {
			conn := newTrackedSessionConnection(t, svc)
			t.Cleanup(func() { require.NoError(t, conn.Close()) })
			svc.sessionConnections.track(conn, peer)
			connections = append(connections, conn)
			manager.register(peer)
		}
		synctest.Wait()
		deadlines := oidcRefreshTimingDeadlines(manager)
		require.Len(t, deadlines, 100, "every persisted deadline must be readable during the blocked provider call")
		for _, deadline := range deadlines {
			require.Equal(t, start.Add(4*time.Second).UTC(), deadline.UTC())
		}
		synctest.Sleep(oidcRefreshUnknownGrace + 200*time.Millisecond)
		for i, conn := range connections {
			require.Falsef(t, conn.closed.Load(), "valid session %d revoked while provider held shard %d", i, shard(first))
		}
		require.NoError(t, manager.Close())
		require.Empty(t, manager.workers)
		require.Empty(t, manager.deadlines)
		require.Empty(t, manager.lastDeadlines)
	})
}

func TestOidcRefreshVerificationNotificationsDoNotBlock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager := &oidcRefreshManager{deadlines: make(map[sessionConnectionKey]chan time.Time)}
		manager.ctx, manager.cancel = context.WithCancel(t.Context())
		defer manager.cancel()
		sess := &houseKeeperTestSession{flow: "current", id: session.MustNewId()}
		key := sessionConnectionKey{flow: sess.flow, id: sess.id}
		updates := make(chan time.Time, 1)
		manager.deadlines[key] = updates
		stop := make(chan struct{})
		finished := make(chan struct{})
		defer func() { close(stop); <-finished }()
		go func() {
			defer close(finished)
			for {
				select {
				case <-stop:
					return
				case <-updates:
				}
			}
		}()
		done := make(chan struct{})
		base := time.Now().Add(time.Hour)
		go func() {
			for i := range 10000 {
				manager.verificationUpdated(sess, base.Add(time.Duration(i)*time.Nanosecond))
			}
			close(done)
		}()
		<-done
		synctest.Wait()
		require.Equal(t, base.Add(9999*time.Nanosecond), oidcRefreshTimingDeadlines(manager)[key])
	})
}

func TestOidcRefreshManagerRevokesOnReconnectLostAccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, conf := oidcRefreshTimingConfig(t)
		manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, time.Now()))
		manager.invalidateSession(sess)
		require.True(t, conn.closed.Load(), "public-key restore must close existing connections without waiting for a worker")
		oidcRefreshTimingAssertDisposed(t, manager, sess, conn, recorder)
	})
}

func TestOidcRefreshInvalidationRetainedUntilFinalDeletion(t *testing.T) {
	key := sessionConnectionKey{flow: "current", id: session.MustNewId()}
	manager := &oidcRefreshManager{invalidating: map[sessionConnectionKey]struct{}{key: {}}}
	require.Contains(t, manager.invalidating, key)
	manager.finalSessionDeleted(key.flow, key.id)
	require.Empty(t, manager.invalidating)
}

func TestOidcRefreshWatchdogBlockedProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan context.Context, 1)
		stopped := make(chan struct{})
		ctx, conf := oidcRefreshTimingConfig(t, func(w http.ResponseWriter, r *http.Request) {
			requested <- r.Context()
			<-r.Context().Done()
			defer close(stopped)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"late-access","refresh_token":"late-refresh","token_type":"Bearer","expires_in":3600}`))
		})
		start := time.Now()
		manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, start))
		manager.register(sess)
		requestCtx := <-requested
		deadline, bounded := requestCtx.Deadline()
		require.True(t, bounded)
		require.Equal(t, start.Add(time.Second).UTC(), deadline.UTC())
		synctest.Sleep(time.Until(deadline) - time.Nanosecond)
		require.False(t, conn.closed.Load())
		require.NoError(t, requestCtx.Err())
		require.Empty(t, recorder.eventsSnapshot())
		synctest.Sleep(time.Nanosecond)
		oidcRefreshTimingAssertDisposed(t, manager, sess, conn, recorder)
		<-stopped
		require.Error(t, requestCtx.Err())
		require.Empty(t, sess.authorizationToken)
		require.Equal(t, 1, sess.setAuthorizationTokenCalls, "only disposal may clear the token; late credentials must never be persisted")
		synctest.Sleep(time.Minute)
		require.Empty(t, sess.authorizationToken)
		require.Equal(t, 1, sess.setAuthorizationTokenCalls)
		require.Len(t, recorder.eventsSnapshot(), 2)
	})
}

func TestOidcRefreshWatchdogWaitingOnSemaphore(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		ctx, conf := oidcRefreshTimingConfig(t, func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		start := time.Now()
		manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, start))
		manager.limit <- struct{}{}
		manager.register(sess)
		synctest.Sleep(time.Second - time.Nanosecond)
		require.False(t, conn.closed.Load())
		require.Empty(t, recorder.eventsSnapshot())
		require.Zero(t, calls)
		synctest.Sleep(time.Nanosecond)
		oidcRefreshTimingAssertDisposed(t, manager, sess, conn, recorder)
		require.Zero(t, calls, "the blocked refresh must not acquire the semaphore after revocation")
		require.Len(t, manager.limit, 1)
		<-manager.limit
	})
}

func TestOidcRefreshWatchdogFailedCheckDoesNotExtendDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{}, 1)
		var attempts []time.Time
		ctx, conf := oidcRefreshTimingConfig(t, func(w http.ResponseWriter, _ *http.Request) {
			attempts = append(attempts, time.Now())
			requested <- struct{}{}
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		start := time.Now()
		manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, start))
		manager.register(sess)
		<-requested
		synctest.Wait()
		require.Equal(t, []time.Time{start.Add(210 * time.Millisecond)}, attempts)
		key := sessionConnectionKey{flow: sess.flow, id: sess.id}
		deadline := start.Add(time.Second)
		require.Equal(t, deadline.UTC(), oidcRefreshTimingDeadlines(manager)[key].UTC(), "an unsuccessful check must retain the persisted deadline")
		synctest.Sleep(time.Until(deadline) - time.Nanosecond)
		require.False(t, conn.closed.Load())
		require.Empty(t, recorder.eventsSnapshot())
		synctest.Sleep(time.Nanosecond)
		oidcRefreshTimingAssertDisposed(t, manager, sess, conn, recorder)
		require.Len(t, attempts, 1)
		require.Equal(t, 1, sess.setAuthorizationTokenCalls, "a failed check must not renew verification")
	})
}

func TestOidcRefreshWatchdogRepositoryFailures(t *testing.T) {
	for _, mode := range []string{"unknown at startup", "default without flow configuration", "transient startup", "last known deadline", "token read error"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, conf := oidcRefreshTimingConfig(t)
				wait := oidcRefreshUnknownGrace
				if mode == "last known deadline" {
					conf.RefreshToken.MaxUnverifiedFor = common.DurationOf(2 * time.Second)
					wait = 2 * time.Second
				}
				var unavailable atomic.Bool
				var findCalls atomic.Int32
				unavailable.Store(mode == "unknown at startup" || mode == "default without flow configuration")
				var sess *houseKeeperTestSession
				findBy := func(_ context.Context, _ configuration.FlowName, _ session.Id, _ *session.FindOpts) (session.Session, error) {
					if mode == "transient startup" && findCalls.Add(1) == 1 {
						return nil, goerrors.New("repository temporarily unavailable")
					}
					if mode == "last known deadline" && findCalls.Add(1) > 1 {
						unavailable.Store(true)
					}
					if unavailable.Load() {
						return nil, goerrors.New("repository unavailable")
					}
					return sess, nil
				}
				var conn *connection
				var manager *oidcRefreshManager
				var recorder *recordingAuditRecorder
				start := time.Now()
				token := oidcRefreshWatchdogToken(t, start)
				var svc *service
				manager, svc, sess, conn, recorder = oidcRefreshWatchdogFixture(t, ctx, conf, findBy, token)
				if mode == "default without flow configuration" {
					svc.Configuration.Flows = nil
				}
				if mode == "token read error" {
					sess.authorizationTokenError = goerrors.New("token storage unavailable")
				}
				manager.register(sess)
				synctest.Wait()
				if mode == "last known deadline" {
					synctest.Sleep(oidcRefreshUnknownGrace + 100*time.Millisecond)
					require.False(t, conn.closed.Load(), "a transient read error must not replace the persisted deadline with startup grace")
					require.Equal(t, start.Add(wait).UTC(), oidcRefreshTimingDeadlines(manager)[sessionConnectionKey{flow: sess.flow, id: sess.id}].UTC())
				}
				synctest.Sleep(time.Until(start.Add(wait)) - time.Nanosecond)
				require.False(t, conn.closed.Load())
				require.Empty(t, recorder.eventsSnapshot())
				synctest.Sleep(time.Nanosecond)
				require.True(t, conn.closed.Load())
				// Disposal looks up the session even when the watchdog had no snapshot.
				if mode == "token read error" || mode == "transient startup" {
					require.Len(t, recorder.eventsSnapshot(), 2)
					require.Equal(t, 1, sess.disposeCalls)
				} else {
					require.Empty(t, recorder.eventsSnapshot(), "an unavailable repository cannot fabricate a completed disposal")
				}
				require.NoError(t, manager.Close())
				require.Empty(t, manager.workers)
				require.Equal(t, wait, time.Since(start))
				late := newTrackedSessionConnection(t, svc)
				svc.sessionConnections.track(late, sess)
				require.True(t, late.closed.Load(), "repository failure must not clear the revocation tombstone")
			})
		})
	}
}

func TestOidcRefreshWatchdogNeverModeAndShutdown(t *testing.T) {
	for _, mode := range []string{"never", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, conf := oidcRefreshTimingConfig(t)
				if mode == "never" {
					conf.ForceDisposeSessionOn = "never"
				}
				started := make(chan struct{})
				stopped := make(chan struct{})
				findBy := func(ctx context.Context, _ configuration.FlowName, _ session.Id, _ *session.FindOpts) (session.Session, error) {
					defer close(stopped)
					close(started)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, findBy, nil)
				manager.register(sess)
				<-started
				if mode == "shutdown" {
					require.NoError(t, manager.Close())
					<-stopped
				}
				synctest.Sleep(oidcRefreshUnknownGrace + 100*time.Millisecond)
				require.False(t, conn.closed.Load())
				require.Empty(t, recorder.eventsSnapshot())
				if mode == "never" {
					manager.mutex.Lock()
					workers := len(manager.workers)
					manager.mutex.Unlock()
					require.Equal(t, 1, workers, "never mode must keep the worker alive without a revoking watchdog")
				}
				require.NoError(t, manager.Close())
				<-stopped
				require.Empty(t, manager.workers)
				require.NoError(t, conn.Close())
			})
		})
	}
}

func TestOidcRefreshManagerStartupRegistersPersistedSessionsOnce(t *testing.T) {
	ctx, conf := oidcRefreshTestConfig(t)
	flow := configuration.FlowName("oidc")
	flows := configuration.Flows{{Name: flow, Authorization: configuration.Authorization{V: conf}}}
	facade, err := authorization.NewAuthorizerFacade(ctx, &flows)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, facade.Close()) })
	sess := &houseKeeperTestSession{flow: flow, id: session.MustNewId(), validUntil: time.Now().Add(time.Hour)}
	started := make(chan sessionConnectionKey, 4)
	repository := &oidcRefreshTestRepository{houseKeeperTestSessionRepository: &houseKeeperTestSessionRepository{
		findAll: func(ctx context.Context, consumer session.Consumer, opts *session.FindOpts) error {
			require.NotNil(t, opts)
			require.NotNil(t, opts.DiagnosticConsumer)
			for _, candidate := range []session.Session{
				sess, &houseKeeperTestSession{flow: flow, id: sess.id},
				&houseKeeperTestSession{flow: "unconfigured", id: session.MustNewId()},
			} {
				_, err := consumer(ctx, candidate)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}}
	repository.findBy = func(ctx context.Context, gotFlow configuration.FlowName, gotId session.Id, opts *session.FindOpts) (session.Session, error) {
		started <- sessionConnectionKey{flow: gotFlow, id: gotId}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	svc := &service{Service: &Service{}, sessions: repository, authorizer: facade}
	svc.Configuration.Flows = flows
	require.NoError(t, svc.oidcRefresh.init(svc))
	t.Cleanup(func() { require.NoError(t, svc.oidcRefresh.Close()) })
	key := sessionConnectionKey{flow: flow, id: sess.id}
	require.Equal(t, key, <-started)
	svc.oidcRefresh.mutex.Lock()
	count, worker := len(svc.oidcRefresh.workers), svc.oidcRefresh.workers[key]
	svc.oidcRefresh.mutex.Unlock()
	require.Equal(t, 1, count)
	require.NotNil(t, worker)
	svc.oidcRefresh.register(sess)
	svc.oidcRefresh.mutex.Lock()
	count = len(svc.oidcRefresh.workers)
	svc.oidcRefresh.mutex.Unlock()
	require.Equal(t, 1, count)
	require.NoError(t, svc.oidcRefresh.Close())
	require.Empty(t, svc.oidcRefresh.workers)
	select {
	case <-started:
		t.Fatal("duplicate session started another worker")
	default:
	}
}

func TestOidcRefreshManagerCloseStopsWorkers(t *testing.T) {
	flow := configuration.FlowName("oidc")
	started := make(chan session.Id, 2)
	repository := &oidcRefreshTestRepository{houseKeeperTestSessionRepository: &houseKeeperTestSessionRepository{}}
	repository.findBy = func(ctx context.Context, _ configuration.FlowName, id session.Id, _ *session.FindOpts) (session.Session, error) {
		started <- id
		<-ctx.Done()
		return nil, ctx.Err()
	}
	svc := &service{Service: &Service{}, sessions: repository}
	manager := &oidcRefreshManager{service: svc, workers: make(map[sessionConnectionKey]context.CancelFunc),
		authorizers: map[configuration.FlowName]*authorization.OidcDeviceAuthAuthorizer{flow: {}},
	}
	manager.ctx, manager.cancel = context.WithCancel(context.Background())
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	first := &houseKeeperTestSession{flow: flow, id: session.MustNewId()}
	second := &houseKeeperTestSession{flow: flow, id: session.MustNewId()}
	manager.register(first)
	manager.register(second)
	seen := map[session.Id]bool{<-started: true, <-started: true}
	require.True(t, seen[first.id])
	require.True(t, seen[second.id])
	require.NoError(t, manager.Close())
	require.ErrorIs(t, manager.ctx.Err(), context.Canceled)
	require.Empty(t, manager.workers)
	manager.register(first)
	require.Empty(t, manager.workers)
}

func TestOidcRefreshManagerLostAccessDisposalAndAuditRetry(t *testing.T) {
	ctx, conf := oidcRefreshTestConfig(t)
	authorizer, err := authorization.NewOidcDeviceAuth(ctx, "current", conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, authorizer.Close()) })

	for _, auditStartFails := range []bool{false, true} {
		name := "audited disposal"
		if auditStartFails {
			name = "audit start failure is retryable"
		}
		t.Run(name, func(t *testing.T) {
			token, err := json.Marshal(map[string]any{
				"access_token": "access", "token_type": "Bearer", "subject": "user",
				"issuer": "issuer", "lastVerifiedAt": time.Now().UTC(),
			})
			require.NoError(t, err)
			sess := &houseKeeperTestSession{
				flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(time.Hour), authorizationToken: token,
			}
			_, lost, err := authorizer.RefreshSession(ctx, sess)
			require.ErrorContains(t, err, "no refresh token")
			require.True(t, lost)

			recorder := &recordingAuditRecorder{}
			hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, &houseKeeperTestAuthorizer{restoreErr: authorization.ErrNoSuchAuthorization})
			svc := hk.service
			svc.houseKeeper.service = svc
			svc.flowAuditRecorders[sess.flow] = recorder
			manager := &oidcRefreshManager{service: svc}
			target := newTrackedSessionConnection(t, svc)
			otherFlow := newTrackedSessionConnection(t, svc)
			otherSession := newTrackedSessionConnection(t, svc)
			svc.sessionConnections.track(target, sess)
			svc.sessionConnections.track(otherFlow, &houseKeeperTestSession{flow: "other", id: sess.id})
			svc.sessionConnections.track(otherSession, &houseKeeperTestSession{flow: sess.flow, id: session.MustNewId()})
			t.Cleanup(func() { require.NoError(t, otherFlow.Close()); require.NoError(t, otherSession.Close()) })

			if auditStartFails {
				auditErr := goerrors.New("audit unavailable")
				recorder.setErrorBeforeRecordForName(audit.EventNameHousekeepingSessionDisposeStarted, auditErr)
				require.ErrorIs(t, manager.dispose(ctx, sess), auditErr)
				require.Zero(t, sess.disposeCalls)
				require.Empty(t, recorder.eventsSnapshot())
				require.True(t, target.closed.Load())
				recorder.setError(nil)
			}
			require.NoError(t, manager.dispose(ctx, sess))
			require.Equal(t, 1, sess.disposeCalls)
			require.True(t, target.closed.Load())
			require.False(t, otherFlow.closed.Load())
			require.False(t, otherSession.closed.Load())
			events := recorder.eventsSnapshot()
			require.Len(t, events, 2)
			require.Equal(t, audit.EventNameHousekeepingSessionDisposeStarted, events[0].Name)
			require.Equal(t, audit.EventNameHousekeepingSessionDisposeCompleted, events[1].Name)
			require.Equal(t, audit.EventReasonOIDCAccessLost, events[0].Reason)
			require.Equal(t, audit.EventReasonOIDCAccessLost, events[1].Reason)
			require.Equal(t, audit.EventOutcomeSuccess, events[1].Outcome)
			require.Equal(t, events[0].OperationId, events[1].OperationId)
			require.NotEmpty(t, events[0].OperationId)
			require.Equal(t, sess.id.String(), events[0].SessionId)
		})
	}
}

func TestOidcRefreshWorkerDisposesPersistedSessionWithoutRefreshToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, conf := oidcRefreshTimingConfig(t)
		// Keep the production verification default so the missing-token worker,
		// not an unknown-state watchdog, makes the disposal decision.
		conf.RefreshToken.MaxUnverifiedFor = common.DurationOf(30 * time.Minute)
		token, err := json.Marshal(map[string]any{
			"access_token": "access", "token_type": "Bearer", "subject": "user",
			"issuer": "issuer", "lastVerifiedAt": time.Now().UTC(),
		})
		require.NoError(t, err)
		manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, token)
		// Detach the original association before selecting deterministic jitter.
		manager.service.sessionConnections.untrack(conn)
		sess.id = session.Id{15: 1}
		manager.service.sessionConnections.track(conn, sess)
		require.Len(t, manager.service.sessionConnections.sessions, 1)
		repository := manager.service.sessions.(*oidcRefreshTestRepository)
		findBy := repository.findBy
		repository.findBy = func(ctx context.Context, flow configuration.FlowName, id session.Id, opts *session.FindOpts) (session.Session, error) {
			if flow != sess.flow || id != sess.id {
				t.Errorf("refresh lookup selected %s/%s, want %s/%s", flow, id, sess.flow, sess.id)
			}
			return findBy(ctx, flow, id, opts)
		}
		h := fnv.New32a()
		_, _ = h.Write([]byte(sess.id.String()))
		delay := time.Duration(h.Sum32()%5000) * time.Millisecond
		require.Positive(t, delay)
		manager.register(sess)
		synctest.Sleep(delay - time.Nanosecond)
		require.False(t, conn.closed.Load())
		require.Empty(t, recorder.eventsSnapshot())
		synctest.Sleep(time.Nanosecond)
		oidcRefreshTimingAssertDisposed(t, manager, sess, conn, recorder)
	})
}
