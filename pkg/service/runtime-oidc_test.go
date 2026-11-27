package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func runtimeOidcSettings(t *testing.T) (context.Context, *configuration.AuthorizationOidcDeviceAuth) {
	t.Helper()
	ctx, metadata := oidcRefreshTestConfig(t)
	var conf configuration.AuthorizationOidcDeviceAuth
	require.NoError(t, conf.SetDefaults())
	conf.Issuer = metadata.Issuer
	conf.ClientId, conf.ClientSecret = metadata.ClientId, metadata.ClientSecret
	conf.RetrieveIdToken = false
	conf.RefreshToken.MaxUnverifiedFor = common.DurationOf(time.Hour)
	return ctx, &conf
}

func runtimeOidcSession(t *testing.T, svc *service) session.Session {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	token, err := json.Marshal(map[string]any{
		"access_token": "access", "token_type": "Bearer", "refresh_token": "refresh",
		"subject": "alice", "issuer": configuration.OidcSettings(svc.Configuration.Flows[0].Authorization.V).Issuer.String(),
		"lastVerifiedAt": now, "receivedAt": now, "expiry": now.Add(time.Hour),
	})
	require.NoError(t, err)
	sess, err := svc.sessions.Create(svc.runtimeCreationContext(t.Context(), svc.Configuration.Flows[0].Name), svc.Configuration.Flows[0].Name, associationAdapterRemote("alice"), token)
	require.NoError(t, err)
	require.NoError(t, svc.runtime.bindSession(svc.generation, sess, true))
	return sess
}

func runtimeOidcWorkers(manager *oidcRefreshManager) int {
	state := manager.state()
	state.mutex.Lock()
	defer state.mutex.Unlock()
	return len(state.workers)
}

func TestRuntimeOidcRefreshKeepsOwnerAndOriginalVerificationPolicy(t *testing.T) {
	ctx, settings := runtimeOidcSettings(t)
	svc := runtimeResourcesFixtureContext(t, ctx, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V = settings
	})
	sess := runtimeOidcSession(t, svc)
	unchanged := svc.generation.snapshot.Configuration()
	unchanged.Flows[0].Title = "unchanged grant"
	unchanged.Flows[0].Authorization.V.(*configuration.AuthorizationOidcDeviceAuth).Ssh.LoginMessage = template.MustNewString("changed presentation only")
	same, err := svc.prepareGeneration(ctx, unchanged)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(same.generation) {
			<-same.generationClosed
		}
	})
	_, err = svc.runtime.activate(t.Context(), same.generation)
	require.NoError(t, err)
	require.True(t, same.loginSessionCompatible(sess))
	svc.oidcRefresh.register(sess)
	require.Eventually(t, func() bool { return len(oidcRefreshTimingDeadlines(&svc.oidcRefresh)) == 1 }, time.Second, time.Millisecond)
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	conf := svc.generation.snapshot.Configuration()
	nextSettings := conf.Flows[0].Authorization.V.(*configuration.AuthorizationOidcDeviceAuth)
	nextSettings.ClientSecret = template.MustNewString("changed secret")
	nextSettings.RefreshToken.MaxUnverifiedFor = common.DurationOf(2 * time.Minute)
	candidate, err := svc.prepareGeneration(ctx, conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(candidate.generation) {
			<-candidate.generationClosed
		}
	})
	_, err = svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	require.False(t, candidate.loginSessionCompatible(sess), "new credentials must create a new grant instead of rotating the retained one")
	// Both views discover the same session, but there is still one worker.
	candidate.oidcRefresh.register(sess)
	svc.oidcRefresh.register(sess)
	require.Equal(t, 1, runtimeOidcWorkers(&svc.oidcRefresh))
	owner, release, err := candidate.oidcRefresh.owned(key)
	require.NoError(t, err)
	require.Same(t, svc, owner.service)
	require.Same(t, svc.oidcRefresh.authorizers[key.flow], owner.authorizers[key.flow])
	release()
	expected, err := (&svc.oidcRefresh).verificationDeadline(t.Context(), key, sess)
	require.NoError(t, err)
	candidate.oidcRefresh.authorizers[key.flow].OnVerified(sess, time.Now().Add(2*time.Minute))
	require.Equal(t, expected, oidcRefreshTimingDeadlines(&svc.oidcRefresh)[key])
	require.False(t, svc.sessionConnections.isRevoked(sess), "configuration alone does not require fresh authentication")
	candidate.oidcRefresh.authorizers[key.flow].OnLostAccess(sess)
	require.False(t, svc.sessionConnections.isRevoked(sess), "a new configuration's grant failure cannot revoke the old provider's session")
	fresh := runtimeOidcSession(t, candidate)
	candidate.oidcRefresh.register(fresh)
	require.Eventually(t, func() bool { return runtimeOidcWorkers(&svc.oidcRefresh) == 2 }, time.Second, time.Millisecond)
	newKey := sessionConnectionKey{flow: fresh.Flow(), id: fresh.Id()}
	newOwner, release, err := svc.oidcRefresh.owned(newKey)
	require.NoError(t, err)
	require.Same(t, candidate, newOwner.service)
	require.Same(t, candidate.oidcRefresh.authorizers[newKey.flow], newOwner.authorizers[newKey.flow])
	release()
	require.NoError(t, candidate.oidcRefresh.Close())
	require.Equal(t, 2, runtimeOidcWorkers(&svc.oidcRefresh), "a generation view cannot stop process-wide workers")
}

type runtimeOidcRoundTripper func(*http.Request) (*http.Response, error)

func (f runtimeOidcRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRuntimeOidcAuthorizersShareGrantRotationLock(t *testing.T) {
	ctx, settings := runtimeOidcSettings(t)
	svc := runtimeResourcesFixtureContext(t, ctx, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V = settings
	})
	require.NoError(t, svc.houseKeeper.Close())
	sess := runtimeOidcSession(t, svc)
	now := time.Now().UTC()
	raw, err := json.Marshal(map[string]any{
		"access_token": "expired", "refresh_token": "refresh", "token_type": "Bearer",
		"subject": "alice", "issuer": settings.Issuer.String(),
		"receivedAt": now.Add(-time.Hour), "expiry": now.Add(-time.Minute), "lastVerifiedAt": now,
	})
	require.NoError(t, err)
	require.NoError(t, sess.SetAuthorizationToken(t.Context(), raw))
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Title = "new provider, identical grant policy"
	candidate, err := svc.prepareGeneration(ctx, conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, candidate.Close()) })
	entered, unblock := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(unblock) })
	defer release()
	client := &http.Client{Transport: runtimeOidcRoundTripper(func(r *http.Request) (*http.Response, error) {
		close(entered)
		select {
		case <-unblock:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body:    io.NopCloser(strings.NewReader(`{"access_token":"fresh","token_type":"Bearer","refresh_token":"rotated","expires_in":3600}`)),
			Request: r,
		}, nil
	})}
	callCtx := context.WithValue(t.Context(), oauth2.HTTPClient, client)
	done := make(chan error, 1)
	go func() {
		_, _, err := svc.oidcRefresh.authorizers[sess.Flow()].RefreshSession(callCtx, sess)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not reach token exchange")
	}
	blockedCtx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	_, err = candidate.oidcRefresh.authorizers[sess.Flow()].NextRefreshAt(blockedCtx, sess)
	require.ErrorIs(t, err, context.DeadlineExceeded, "a second authorizer must not read/rotate the grant during the first exchange")
	release()
	require.NoError(t, <-done)
	_, err = candidate.oidcRefresh.authorizers[sess.Flow()].NextRefreshAt(t.Context(), sess)
	require.NoError(t, err)
}

func TestRuntimeOidcCanBeAddedAfterInitialProviderHasDrained(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	ctx, settings := runtimeOidcSettings(t)
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Authorization.V = settings
	candidate, err := svc.prepareGeneration(ctx, conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(candidate.generation) {
			<-candidate.generationClosed
		}
	})
	_, err = svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	runtimeResourcesWaitClosed(t, svc)
	sess := runtimeOidcSession(t, candidate)
	candidate.oidcRefresh.register(sess)
	require.Eventually(t, func() bool { return runtimeOidcWorkers(&svc.oidcRefresh) == 1 }, time.Second, time.Millisecond)
	select {
	case <-svc.houseKeeper.done:
		t.Fatal("retiring the initial providers stopped process housekeeping")
	default:
	}
	require.NoError(t, svc.Close())
	require.Zero(t, runtimeOidcWorkers(&svc.oidcRefresh))
}

func TestRuntimeOidcRemovedFlowStopsRefreshAndDisposesWithOldOwner(t *testing.T) {
	ctx, settings := runtimeOidcSettings(t)
	svc := runtimeResourcesFixtureContext(t, ctx, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V = settings
	})
	sess := runtimeOidcSession(t, svc)
	svc.oidcRefresh.register(sess)
	require.Equal(t, 1, runtimeOidcWorkers(&svc.oidcRefresh))
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Name = "replacement"
	candidate, err := svc.prepareGeneration(ctx, conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(candidate.generation) {
			<-candidate.generationClosed
		}
	})
	_, err = svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		current, err := svc.sessions.FindBy(t.Context(), sess.Flow(), sess.Id(), nil)
		if err != nil {
			return false
		}
		token, err := current.AuthorizationToken(t.Context())
		return err == nil && len(token) == 0 && runtimeOidcWorkers(&svc.oidcRefresh) == 0
	}, 5*time.Second, time.Millisecond)
	candidate.oidcRefresh.register(sess)
	require.Zero(t, runtimeOidcWorkers(&svc.oidcRefresh))
	require.True(t, svc.sessionConnections.isRevoked(sess))
}

func TestRuntimeOidcConcurrentRegistrationAndShutdown(t *testing.T) {
	ctx, settings := runtimeOidcSettings(t)
	svc := runtimeResourcesFixtureContext(t, ctx, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V = settings
	})
	sess := runtimeOidcSession(t, svc)
	var registered atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			svc.oidcRefresh.register(sess)
			registered.Add(1)
		}
	}()
	require.NoError(t, svc.Close())
	<-done
	require.EqualValues(t, 100, registered.Load())
	require.Zero(t, runtimeOidcWorkers(&svc.oidcRefresh))
}
