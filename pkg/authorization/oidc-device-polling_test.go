package authorization

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/errors"
)

type oidcDevicePollingTestResult struct {
	token *oauth2.Token
	err   error
}

func oidcDevicePollingTestAuthorizer(t *testing.T, handler http.HandlerFunc) (*OidcDeviceAuthAuthorizer, context.Context) {
	t.Helper()
	ctx := oidcTimingTestContext(t, func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "https://issuer.example/token", req.URL.String())
		assert.Equal(t, http.MethodPost, req.Method)
		if !assert.NoError(t, req.ParseForm()) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", req.Form.Get("grant_type"))
		assert.Equal(t, "device-code", req.Form.Get("device_code"))
		assert.Equal(t, "client", req.Form.Get("client_id"))
		assert.Equal(t, "openid", req.Form.Get("scope"))
		username, password, basic := req.BasicAuth()
		assert.True(t, basic)
		assert.Equal(t, "client", username)
		assert.Equal(t, "secret", password)
		assert.Empty(t, req.Form.Get("client_secret"))
		w.Header().Set("Content-Type", "application/json")
		handler(w, req)
	})
	return &OidcDeviceAuthAuthorizer{oauth2Config: oauth2.Config{
		ClientID: "client", ClientSecret: "secret", Scopes: []string{"openid"},
		Endpoint: oauth2.Endpoint{TokenURL: "https://issuer.example/token", AuthStyle: oauth2.AuthStyleInHeader},
	}}, ctx
}

func TestOidcDevicePollingIntervalAndSlowDown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval int64
		replies  []string
		gaps     []time.Duration
	}{
		{"default interval", 0, []string{"authorization_pending"}, []time.Duration{5 * time.Second, 5 * time.Second}},
		{"provider interval", 2, []string{"authorization_pending"}, []time.Duration{2 * time.Second, 2 * time.Second}},
		{"negative interval", -1, []string{"authorization_pending"}, []time.Duration{5 * time.Second, 5 * time.Second}},
		{"overflowing interval", math.MaxInt64, []string{"authorization_pending"}, []time.Duration{5 * time.Second, 5 * time.Second}},
		{"persistent slow down", 2, []string{"slow_down", "authorization_pending", "slow_down"}, []time.Duration{2 * time.Second, 7 * time.Second, 7 * time.Second, 12 * time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				var polls []time.Time
				a, ctx := oidcDevicePollingTestAuthorizer(t, func(w http.ResponseWriter, _ *http.Request) {
					polls = append(polls, time.Now())
					if len(polls) <= len(tc.replies) {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = fmt.Fprintf(w, `{"error":%q}`, tc.replies[len(polls)-1])
						return
					}
					_, _ = fmt.Fprint(w, `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600}`)
				})
				using := &oauth2.DeviceAuthResponse{DeviceCode: "device-code", Interval: tc.interval, Expiry: start.Add(5 * time.Minute)}
				done := make(chan oidcDevicePollingTestResult, 1)
				go func() {
					token, err := a.retrieveDeviceAuthToken(ctx, using)
					done <- oidcDevicePollingTestResult{token, err}
				}()
				synctest.Wait()
				require.Empty(t, polls, "the initial poll must also wait for the interval")
				var elapsed time.Duration
				for i, gap := range tc.gaps {
					synctest.Sleep(gap - time.Nanosecond)
					require.Len(t, polls, i, "no early poll before interval %d", i)
					require.Empty(t, done)
					synctest.Sleep(time.Nanosecond)
					elapsed += gap
					require.Len(t, polls, i+1)
					require.Equal(t, start.Add(elapsed), polls[i])
				}
				got := <-done
				require.NoError(t, got.err)
				require.Equal(t, "access", got.token.AccessToken)
				require.Equal(t, "refresh", got.token.RefreshToken)
				require.Equal(t, "Bearer", got.token.TokenType)
				require.Equal(t, time.Now().Add(time.Hour), got.token.Expiry)
				synctest.Sleep(time.Minute)
				require.Len(t, polls, len(tc.gaps), "successful polling must terminate, not continue in the background")
			})
		})
	}
}

func TestOidcDevicePollingMaxWait(t *testing.T) {
	for _, tc := range []struct {
		name         string
		expiresAfter time.Duration
		parentWait   time.Duration
		wait         time.Duration
		polls        int
		inFlight     bool
		slowDown     bool
	}{
		{name: "device expires before first poll", expiresAfter: 3 * time.Second, parentWait: time.Hour, wait: 3 * time.Second},
		{name: "device expires between polls", expiresAfter: 12 * time.Second, parentWait: time.Hour, wait: 12 * time.Second, polls: 2},
		{name: "device expires in flight", expiresAfter: 12 * time.Second, parentWait: time.Hour, wait: 12 * time.Second, polls: 1, inFlight: true},
		{name: "slow down cannot extend device expiry", expiresAfter: 12 * time.Second, parentWait: time.Hour, wait: 12 * time.Second, polls: 1, slowDown: true},
		{name: "earlier caller deadline", expiresAfter: 12 * time.Second, parentWait: 6 * time.Second, wait: 6 * time.Second, polls: 1},
		{name: "caller deadline without device expiry", parentWait: 12 * time.Second, wait: 12 * time.Second, polls: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				polls := 0
				stopped := make(chan struct{})
				a, ctx := oidcDevicePollingTestAuthorizer(t, func(w http.ResponseWriter, req *http.Request) {
					polls++
					if tc.inFlight {
						<-req.Context().Done()
						close(stopped)
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					if tc.slowDown {
						_, _ = fmt.Fprint(w, `{"error":"slow_down"}`)
					} else {
						_, _ = fmt.Fprint(w, `{"error":"authorization_pending"}`)
					}
				})
				ctx, cancel := context.WithTimeout(ctx, tc.parentWait)
				defer cancel()
				start := time.Now()
				using := &oauth2.DeviceAuthResponse{DeviceCode: "device-code"}
				if tc.expiresAfter != 0 {
					using.Expiry = start.Add(tc.expiresAfter)
				}
				done := make(chan oidcDevicePollingTestResult, 1)
				go func() {
					token, err := a.retrieveDeviceAuthToken(ctx, using)
					done <- oidcDevicePollingTestResult{token, err}
				}()
				synctest.Sleep(tc.wait - time.Nanosecond)
				require.Empty(t, done, "pending authorization must not terminate before the effective deadline")
				require.Equal(t, tc.polls, polls)
				synctest.Sleep(time.Nanosecond)
				got := <-done
				require.Nil(t, got.token)
				require.ErrorContains(t, got.err, "authorize of device timed out")
				require.True(t, errors.IsType(got.err, errors.User))
				require.Equal(t, tc.wait, time.Since(start))
				if tc.inFlight {
					<-stopped
				}
				synctest.Sleep(time.Minute)
				require.Equal(t, tc.polls, polls, "an expired authorization must never poll again")
			})
		})
	}
}

func TestOidcDevicePollingCancellation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wait     time.Duration
		inFlight bool
		polls    int
	}{
		{"before first poll", 0, false, 0},
		{"between polls", 5 * time.Second, false, 1},
		{"in flight", 5 * time.Second, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				polls := 0
				stopped := make(chan struct{})
				a, ctx := oidcDevicePollingTestAuthorizer(t, func(w http.ResponseWriter, req *http.Request) {
					polls++
					if tc.inFlight {
						<-req.Context().Done()
						close(stopped)
						return
					}
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprint(w, `{"error":"authorization_pending"}`)
				})
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				done := make(chan oidcDevicePollingTestResult, 1)
				go func() {
					token, err := a.retrieveDeviceAuthToken(ctx, &oauth2.DeviceAuthResponse{DeviceCode: "device-code"})
					done <- oidcDevicePollingTestResult{token, err}
				}()
				synctest.Sleep(tc.wait)
				require.Equal(t, tc.polls, polls)
				require.Empty(t, done)
				cancel()
				got := <-done
				require.Nil(t, got.token)
				require.ErrorContains(t, got.err, "authorize canceled by user")
				require.True(t, errors.IsType(got.err, errors.User))
				if tc.inFlight {
					<-stopped
				}
				synctest.Sleep(time.Minute)
				require.Equal(t, tc.polls, polls, "cancellation must stop all subsequent polling")
			})
		})
	}
}

func TestOidcDevicePollingTerminalProviderError(t *testing.T) {
	for _, tc := range []struct {
		code    string
		kind    errors.Type
		message string
	}{
		{"expired_token", errors.User, "timed out by IdP"},
		{"access_denied", errors.Network, "cannot authorize device"},
		{"server_error", errors.Network, "cannot authorize device"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				polls := 0
				a, ctx := oidcDevicePollingTestAuthorizer(t, func(w http.ResponseWriter, _ *http.Request) {
					polls++
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprintf(w, `{"error":%q}`, tc.code)
				})
				start := time.Now()
				token, err := a.retrieveDeviceAuthToken(ctx, &oauth2.DeviceAuthResponse{DeviceCode: "device-code"})
				require.Nil(t, token)
				require.ErrorContains(t, err, tc.message)
				require.True(t, errors.IsType(err, tc.kind))
				require.Equal(t, 5*time.Second, time.Since(start))
				synctest.Sleep(time.Minute)
				require.Equal(t, 1, polls, "terminal provider errors must not be retried")
			})
		})
	}
}
