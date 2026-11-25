package service

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

type oidcRefreshTimingTransport func(*http.Request) (*http.Response, error)

func (f oidcRefreshTimingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// Socket I/O is not durably blocked in synctest. Only the timing tests use this
// in-process provider; oidcRefreshTestConfig retains the real TLS integration.
func oidcRefreshTimingConfig(t *testing.T, tokenHandler ...http.HandlerFunc) (context.Context, *configuration.AuthorizationOidcDeviceAuth) {
	t.Helper()
	const issuer = "https://issuer.example"
	client := &http.Client{Transport: oidcRefreshTimingTransport(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			defer req.Body.Close()
		}
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		w := httptest.NewRecorder()
		if req.URL.Path == "/token" && len(tokenHandler) != 0 {
			// A controlled handler may return late credentials despite cancellation.
			// The real authorizer/worker must still reject that response.
			tokenHandler[0](w, req)
		} else if req.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"device_authorization_endpoint": issuer + "/device",
				"token_endpoint":                issuer + "/token", "jwks_uri": issuer + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		} else {
			http.NotFound(w, req)
		}
		return w.Result(), nil
	})}
	return context.WithValue(t.Context(), oauth2.HTTPClient, client), &configuration.AuthorizationOidcDeviceAuth{
		Issuer: template.MustNewUrl(issuer), ClientId: template.MustNewString("client"),
		ClientSecret: template.MustNewString("secret"), Scopes: template.MustNewStrings("openid"),
		ForceDisposeSessionOn: "lostAccess",
		RefreshToken:          configuration.AuthorizationOidcRefreshToken{Mode: "proactive"},
	}
}

// watchDeadline calls workerCtx.Err only after receiving its timer. Gate that
// boundary, not a mutex or scheduler delay, to queue verification AFTER the old
// timer fires and BEFORE the watcher makes its revocation decision.
type oidcRefreshTimingTimerGate struct {
	context.Context
	once    sync.Once
	entered chan struct{}
	resume  chan struct{}
}

func (g *oidcRefreshTimingTimerGate) Err() error {
	g.once.Do(func() {
		close(g.entered)
		<-g.resume
	})
	return g.Context.Err()
}

func oidcRefreshTimingDeadlines(manager *oidcRefreshManager) map[sessionConnectionKey]time.Time {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	return maps.Clone(manager.lastDeadlines)
}

func oidcRefreshTimingAssertDisposed(t *testing.T, manager *oidcRefreshManager, sess *houseKeeperTestSession, conn *connection, recorder *recordingAuditRecorder) {
	t.Helper()
	synctest.Wait()
	require.True(t, conn.closed.Load())
	require.NoError(t, manager.Close())
	require.Empty(t, manager.workers)
	require.Equal(t, 1, sess.disposeCalls)
	events := recorder.eventsSnapshot()
	require.Len(t, events, 2)
	require.Equal(t, audit.EventNameHousekeepingSessionDisposeStarted, events[0].Name)
	require.Equal(t, audit.EventNameHousekeepingSessionDisposeCompleted, events[1].Name)
	require.Equal(t, audit.EventReasonOIDCAccessLost, events[0].Reason)
	require.Equal(t, audit.EventReasonOIDCAccessLost, events[1].Reason)
	require.Equal(t, audit.EventOutcomeSuccess, events[1].Outcome)
	late := newTrackedSessionConnection(t, manager.service)
	manager.service.sessionConnections.track(late, sess)
	require.True(t, late.closed.Load(), "late connection registration must not revive the revoked session")
}

// Retain a real discovery + authenticated token POST + rotation integration.
// Watchdog scheduling is tested separately with the isolated clock above.
func TestOidcRefreshProviderTLSRoundTrip(t *testing.T) {
	type request struct {
		method, path, refresh, username, password string
		basic                                     bool
		parseErr                                  error
	}
	requests := make(chan request, 1)
	ctx, conf := oidcRefreshTestConfig(t, func(w http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		username, password, basic := req.BasicAuth()
		requests <- request{req.Method, req.URL.Path, req.Form.Get("refresh_token"), username, password, basic, err}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"rotated-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600}`))
	})
	authorizer, err := authorization.NewOidcDeviceAuth(ctx, "current", conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, authorizer.Close()) })
	start := time.Now()
	raw, err := json.Marshal(map[string]any{
		"access_token": "old-access", "refresh_token": "old-refresh", "token_type": "Bearer",
		"subject": "user", "issuer": "issuer", "lastVerifiedAt": start.UTC(),
		"receivedAt": start.Add(-time.Hour).UTC(), "expiry": start.Add(-time.Minute).UTC(),
	})
	require.NoError(t, err)
	sess := &houseKeeperTestSession{flow: "current", authorizationToken: raw}
	next, lost, err := authorizer.RefreshSession(ctx, sess)
	require.NoError(t, err)
	require.False(t, lost)
	require.True(t, next.After(time.Now()))
	got := <-requests
	require.NoError(t, got.parseErr)
	require.Equal(t, http.MethodPost, got.method)
	require.Equal(t, "/token", got.path)
	require.Equal(t, "old-refresh", got.refresh)
	require.True(t, got.basic)
	require.Equal(t, "client", got.username)
	require.Equal(t, "secret", got.password)
	var stored struct {
		AccessToken    string    `json:"access_token"`
		RefreshToken   string    `json:"refresh_token"`
		Subject        string    `json:"subject"`
		Issuer         string    `json:"issuer"`
		LastVerifiedAt time.Time `json:"lastVerifiedAt"`
	}
	require.NoError(t, json.Unmarshal(sess.authorizationToken, &stored))
	require.Equal(t, "rotated-access", stored.AccessToken)
	require.Equal(t, "rotated-refresh", stored.RefreshToken)
	require.Equal(t, "user", stored.Subject)
	require.Equal(t, "issuer", stored.Issuer)
	require.False(t, stored.LastVerifiedAt.Before(start))
	require.False(t, stored.LastVerifiedAt.After(time.Now()))
	require.Equal(t, 1, sess.setAuthorizationTokenCalls)
}
