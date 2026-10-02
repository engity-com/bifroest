package service

import (
	"context"
	"encoding/json"
	goerrors "errors"
	"hash/fnv"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
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
	ctx, conf := oidcRefreshTestConfig(t)
	manager, _, sess, conn, _ := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, time.Now()))
	key := sessionConnectionKey{flow: sess.flow, id: sess.id}
	deadlines := make(chan time.Time, 1)
	manager.deadlines = map[sessionConnectionKey]chan time.Time{key: deadlines}
	parentCtx, cancel := context.WithCancel(manager.ctx)
	defer cancel()
	workerCtx, stopWorker := context.WithCancel(parentCtx)
	defer stopWorker()
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		manager.watchDeadline(parentCtx, workerCtx, stopWorker, stop, key, deadlines)
	}()
	manager.verificationUpdated(sess, time.Now().Add(2*time.Second))
	time.Sleep(100 * time.Millisecond)
	manager.verificationUpdated(sess, time.Now().Add(5*time.Second))
	// A worker may finish reading an older token only after a reconnect has
	// persisted and reported the newer verification deadline.
	manager.verificationUpdated(sess, time.Now().Add(500*time.Millisecond))
	time.Sleep(2100 * time.Millisecond)
	require.False(t, conn.closed.Load(), "a newly verified grant must supersede the previous deadline")
	cancel()
	close(stop)
	<-finished
}

func TestOidcRefreshWatchdogChecksQueuedDeadlineAfterTimer(t *testing.T) {
	ctx, conf := oidcRefreshTestConfig(t)
	manager, _, sess, conn, _ := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, time.Now()))
	key := sessionConnectionKey{flow: sess.flow, id: sess.id}
	updates := make(chan time.Time, 1)
	manager.deadlines = map[sessionConnectionKey]chan time.Time{key: updates}
	manager.lastDeadlines = make(map[sessionConnectionKey]time.Time)
	parent, cancel := context.WithCancel(manager.ctx)
	defer cancel()
	worker, stopWorker := context.WithCancel(parent)
	defer stopWorker()
	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		manager.watchDeadline(parent, worker, stopWorker, stop, key, updates)
	}()
	manager.verificationUpdated(sess, time.Now().Add(150*time.Millisecond))
	time.Sleep(75 * time.Millisecond)
	manager.mutex.Lock()
	time.Sleep(150 * time.Millisecond)
	fresh := time.Now().Add(time.Second)
	manager.lastDeadlines[key] = fresh
	updates <- fresh
	manager.mutex.Unlock()
	require.False(t, conn.closed.Load())
	time.Sleep(100 * time.Millisecond)
	require.False(t, conn.closed.Load(), "queued persisted verification must win over an expired timer")
	cancel()
	close(stop)
	<-finished
}

type oidcRefreshReadOnlySession struct {
	*houseKeeperTestSession
	token []byte
}

func (this *oidcRefreshReadOnlySession) AuthorizationToken(context.Context) ([]byte, error) {
	return append([]byte(nil), this.token...), nil
}

func TestOidcRefreshStartupDeadlineDoesNotWaitForCollidingProvider(t *testing.T) {
	requested := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ctx, conf := oidcRefreshTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
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
	makeSession := func(expiry time.Time) *oidcRefreshReadOnlySession {
		sess := &oidcRefreshReadOnlySession{houseKeeperTestSession: &houseKeeperTestSession{
			flow: flow, id: session.MustNewId(), validUntil: time.Now().Add(time.Hour),
		}}
		token, marshalErr := json.Marshal(map[string]any{
			"access_token": "access", "token_type": "Bearer", "refresh_token": "refresh",
			"subject": "user", "issuer": "issuer", "lastVerifiedAt": time.Now().UTC(),
			"receivedAt": time.Now().UTC(), "expiry": expiry.UTC(),
		})
		require.NoError(t, marshalErr)
		sess.token = token
		return sess
	}
	first := makeSession(time.Now().Add(200 * time.Millisecond))
	sessions[first.id] = first
	shard := func(sess *oidcRefreshReadOnlySession) uint32 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(sess.String()))
		return h.Sum32() % 64
	}
	var peers []*oidcRefreshReadOnlySession
	for len(peers) < 99 {
		candidate := makeSession(time.Now().Add(time.Hour))
		if len(peers) == 0 && shard(candidate) != shard(first) {
			continue
		}
		peers = append(peers, candidate)
		sessions[candidate.id] = candidate
	}
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
	select {
	case <-requested:
	case <-time.After(2 * time.Second):
		t.Fatal("provider call did not start")
	}
	connections := make([]*connection, 0, len(peers))
	for _, peer := range peers {
		conn := newTrackedSessionConnection(t, svc)
		svc.sessionConnections.track(conn, peer)
		connections = append(connections, conn)
		manager.register(peer)
	}
	require.Eventually(t, func() bool {
		manager.mutex.Lock()
		defer manager.mutex.Unlock()
		return len(manager.lastDeadlines) == 100
	}, time.Second, 10*time.Millisecond, "every persisted deadline should be readable during the blocked provider call")
	time.Sleep(oidcRefreshUnknownGrace + 200*time.Millisecond)
	for i, conn := range connections {
		require.Falsef(t, conn.closed.Load(), "valid session %d revoked while provider held shard %d", i, shard(first))
	}
	close(release)
}

func TestOidcRefreshVerificationNotificationsDoNotBlock(t *testing.T) {
	manager := &oidcRefreshManager{deadlines: make(map[sessionConnectionKey]chan time.Time)}
	manager.ctx, manager.cancel = context.WithCancel(context.Background())
	defer manager.cancel()
	sess := &houseKeeperTestSession{flow: "current", id: session.MustNewId()}
	key := sessionConnectionKey{flow: sess.flow, id: sess.id}
	updates := make(chan time.Time, 1)
	manager.deadlines[key] = updates
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-updates:
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		for range 10000 {
			manager.verificationUpdated(sess, time.Now().Add(time.Hour))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deadline notification blocked while the watcher consumed a pending value")
	}
}

func TestOidcRefreshManagerRevokesOnReconnectLostAccess(t *testing.T) {
	ctx, conf := oidcRefreshTestConfig(t)
	manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, time.Now()))
	manager.invalidateSession(sess)
	require.True(t, conn.closed.Load(), "public-key restore must close existing connections without waiting for a worker")
	require.Eventually(t, func() bool { return len(recorder.eventsSnapshot()) == 2 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, manager.Close())
}

func TestOidcRefreshInvalidationRetainedUntilFinalDeletion(t *testing.T) {
	key := sessionConnectionKey{flow: "current", id: session.MustNewId()}
	manager := &oidcRefreshManager{invalidating: map[sessionConnectionKey]struct{}{key: {}}}
	require.Contains(t, manager.invalidating, key)
	manager.finalSessionDeleted(key.flow, key.id)
	require.Empty(t, manager.invalidating)
}

func TestOidcRefreshWatchdogBlockedProvider(t *testing.T) {
	requested := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	ctx, conf := oidcRefreshTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
		close(requested)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, time.Now()))
	manager.register(sess)
	select {
	case <-requested:
	case <-time.After(2 * time.Second):
		t.Fatal("provider was not called")
	}
	require.Eventually(t, func() bool { return conn.closed.Load() }, 3*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return len(recorder.eventsSnapshot()) == 2 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, manager.Close())
	require.Equal(t, 1, sess.disposeCalls)
	require.Len(t, recorder.eventsSnapshot(), 2)
}

func TestOidcRefreshWatchdogWaitingOnSemaphore(t *testing.T) {
	ctx, conf := oidcRefreshTestConfig(t)
	manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, time.Now()))
	manager.limit <- struct{}{}
	manager.register(sess)
	require.Eventually(t, func() bool { return conn.closed.Load() }, 3*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return len(recorder.eventsSnapshot()) == 2 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, manager.Close())
	require.Equal(t, 1, sess.disposeCalls)
	require.Len(t, recorder.eventsSnapshot(), 2)
}

func TestOidcRefreshWatchdogFailedCheckDoesNotExtendDeadline(t *testing.T) {
	requested := make(chan struct{})
	ctx, conf := oidcRefreshTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
		close(requested)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, nil, oidcRefreshWatchdogToken(t, time.Now()))
	manager.register(sess)
	select {
	case <-requested:
	case <-time.After(2 * time.Second):
		t.Fatal("provider was not called")
	}
	require.Eventually(t, func() bool { return conn.closed.Load() }, 3*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return len(recorder.eventsSnapshot()) == 2 }, 2*time.Second, 10*time.Millisecond)
	require.NoError(t, manager.Close())
	require.Equal(t, 1, sess.disposeCalls)
	require.Len(t, recorder.eventsSnapshot(), 2)
}

func TestOidcRefreshWatchdogRepositoryFailures(t *testing.T) {
	for _, mode := range []string{"unknown at startup", "default without flow configuration", "transient startup", "last known deadline", "token read error"} {
		t.Run(mode, func(t *testing.T) {
			ctx, conf := oidcRefreshTestConfig(t)
			if mode == "last known deadline" {
				conf.RefreshToken.MaxUnverifiedFor = common.DurationOf(2 * time.Second)
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
			token := oidcRefreshWatchdogToken(t, time.Now())
			var svc *service
			manager, svc, sess, conn, recorder = oidcRefreshWatchdogFixture(t, ctx, conf, findBy, token)
			if mode == "default without flow configuration" {
				svc.Configuration.Flows = nil
			}
			if mode == "token read error" {
				sess.authorizationTokenError = goerrors.New("token storage unavailable")
			}
			manager.register(sess)
			if mode == "last known deadline" {
				time.Sleep(oidcRefreshUnknownGrace + 100*time.Millisecond)
				require.False(t, conn.closed.Load(), "a transient read error must not replace the persisted deadline with startup grace")
			}
			require.Eventually(t, func() bool { return conn.closed.Load() }, 3*time.Second, 10*time.Millisecond)
			// Disposal is retried by looking up the session, even when the
			// watchdog had no session snapshot when it revoked the connection.
			if mode == "token read error" || mode == "transient startup" {
				require.Eventually(t, func() bool { return len(recorder.eventsSnapshot()) == 2 }, 2*time.Second, 10*time.Millisecond)
			}
			require.NoError(t, manager.Close())
		})
	}
}

func TestOidcRefreshWatchdogNeverModeAndShutdown(t *testing.T) {
	for _, mode := range []string{"never", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, conf := oidcRefreshTestConfig(t)
			if mode == "never" {
				conf.ForceDisposeSessionOn = "never"
			}
			started := make(chan struct{})
			findBy := func(ctx context.Context, _ configuration.FlowName, _ session.Id, _ *session.FindOpts) (session.Session, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			manager, _, sess, conn, recorder := oidcRefreshWatchdogFixture(t, ctx, conf, findBy, nil)
			manager.register(sess)
			<-started
			if mode == "shutdown" {
				require.NoError(t, manager.Close())
			}
			time.Sleep(oidcRefreshUnknownGrace + 100*time.Millisecond)
			require.False(t, conn.closed.Load())
			require.Empty(t, recorder.eventsSnapshot())
			require.NoError(t, manager.Close())
			require.Empty(t, manager.workers)
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
	ctx, conf := oidcRefreshTestConfig(t)
	authorizer, err := authorization.NewOidcDeviceAuth(ctx, "current", conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, authorizer.Close()) })
	token, err := json.Marshal(map[string]any{
		"access_token": "access", "token_type": "Bearer", "subject": "user",
		"issuer": "issuer", "lastVerifiedAt": time.Now().UTC(),
	})
	require.NoError(t, err)
	sess := &houseKeeperTestSession{
		flow: "current", id: session.MustNewId(), validUntil: time.Now().Add(time.Hour), authorizationToken: token,
	}
	repository := &oidcRefreshTestRepository{houseKeeperTestSessionRepository: &houseKeeperTestSessionRepository{}}
	repository.findBy = func(_ context.Context, flow configuration.FlowName, id session.Id, _ *session.FindOpts) (session.Session, error) {
		require.Equal(t, sess.flow, flow)
		require.Equal(t, sess.id, id)
		return sess, nil
	}
	hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, &houseKeeperTestAuthorizer{restoreErr: authorization.ErrNoSuchAuthorization})
	svc := hk.service
	svc.sessions = repository
	svc.houseKeeper.service = svc
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
	manager.register(sess)
	require.Eventually(t, func() bool {
		return conn.closed.Load() && len(recorder.eventsSnapshot()) == 2
	}, 7*time.Second, 10*time.Millisecond)
	require.NoError(t, manager.Close())
	require.Equal(t, 1, sess.disposeCalls)
	events := recorder.eventsSnapshot()
	require.Len(t, events, 2)
	require.Equal(t, audit.EventReasonOIDCAccessLost, events[0].Reason)
}
