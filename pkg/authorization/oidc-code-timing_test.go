package authorization

import (
	"context"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
)

type oidcCodeTimingTestBrowser func(InteractiveRequest, *OidcDeviceAuthAuthorizer) (*oauth2.Token, error)

func (f oidcCodeTimingTestBrowser) Login(req InteractiveRequest, a *OidcDeviceAuthAuthorizer) (*oauth2.Token, error) {
	return f(req, a)
}

type oidcCodeTimingTestRequest struct {
	InteractiveRequest
	ctx      context.Context
	deadline time.Time
}

func (r oidcCodeTimingTestRequest) Context() context.Context { return r.ctx }
func (r oidcCodeTimingTestRequest) AuthenticationDeadline() time.Time {
	return r.deadline
}
func (oidcCodeTimingTestRequest) Selection() connection.Selection {
	return connection.Selection{Transport: connection.TransportSsh}
}

func TestOidcCodeLoginDeadlineAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		adapterWait  time.Duration
		parentWait   time.Duration
		wait         time.Duration
		cancelCaller bool
	}{
		{"configured deadline", 0, time.Hour, 3 * time.Minute, false},
		{"earlier adapter deadline", time.Minute, time.Hour, time.Minute, false},
		{"earlier parent deadline", 0, 30 * time.Second, 30 * time.Second, false},
		{"later adapter cannot extend deadline", 5 * time.Minute, time.Hour, 3 * time.Minute, false},
		{"caller cancellation", 0, time.Hour, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, cooperative := range []bool{true, false} {
				name := "context-aware browser"
				if !cooperative {
					name = "browser returns late credentials"
				}
				t.Run(name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						start := time.Now()
						ctx, cancel := context.WithTimeout(t.Context(), tc.parentWait)
						request := oidcCodeTimingTestRequest{ctx: ctx}
						if tc.adapterWait != 0 {
							request.deadline = start.Add(tc.adapterWait)
						}
						entered := make(chan context.Context, 1)
						release := make(chan struct{}, 1)
						stopped := make(chan struct{})
						defer func() {
							cancel()
							close(release)
						}()
						a := &OidcDeviceAuthAuthorizer{
							code: &configuration.AuthorizationOidcAuthorizationCode{LoginTimeout: common.DurationOf(3 * time.Minute)},
							browser: oidcCodeTimingTestBrowser(func(req InteractiveRequest, _ *OidcDeviceAuthAuthorizer) (*oauth2.Token, error) {
								defer close(stopped)
								entered <- req.Context()
								if cooperative {
									<-req.Context().Done()
									return nil, req.Context().Err()
								}
								<-release
								return &oauth2.Token{AccessToken: "late-credentials"}, nil
							}),
						}
						type result struct {
							auth Authorization
							err  error
						}
						done := make(chan result, 1)
						go func() {
							auth, err := a.AuthorizeInteractive(request)
							done <- result{auth, err}
						}()
						browserCtx := <-entered
						deadline, bounded := browserCtx.Deadline()
						require.True(t, bounded)
						wantWait := tc.wait
						if tc.cancelCaller {
							wantWait = 3 * time.Minute
						}
						require.Equal(t, start.Add(wantWait), deadline)
						wantError := context.DeadlineExceeded
						if tc.cancelCaller {
							synctest.Wait()
							require.NoError(t, browserCtx.Err())
							require.Empty(t, done)
							cancel()
							wantError = context.Canceled
						} else {
							synctest.Sleep(tc.wait - time.Nanosecond)
							require.NoError(t, browserCtx.Err())
							require.Empty(t, done)
							synctest.Sleep(time.Nanosecond)
						}
						if !cooperative {
							synctest.Wait()
							require.Empty(t, done, "the browser has not returned yet")
							release <- struct{}{}
						}
						got := <-done
						require.Nil(t, got.auth, "canceled or expired credentials must never reach primary authorization")
						require.ErrorContains(t, got.err, "OIDC browser authentication failed")
						require.ErrorIs(t, browserCtx.Err(), wantError)
						require.Equal(t, tc.wait, time.Since(start))
						<-stopped
					})
				})
			}
		})
	}
}

func TestOidcCodeExchangeDeadlineCancelsProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan context.Context, 1)
		stopped := make(chan struct{})
		ctx := oidcTimingTestContext(t, func(_ http.ResponseWriter, req *http.Request) {
			entered <- req.Context()
			<-req.Context().Done()
			close(stopped)
		})
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		a := &OidcDeviceAuthAuthorizer{
			code: &configuration.AuthorizationOidcAuthorizationCode{},
			oauth2Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{
				TokenURL: "https://issuer.example/token", AuthStyle: oauth2.AuthStyleInHeader,
			}},
		}
		done := make(chan error, 1)
		go func() {
			result, err := a.ExchangeCode(ctx, "private-code", "verifier", "nonce")
			if result != nil {
				t.Error("expired code exchange returned credentials")
			}
			done <- err
		}()
		providerCtx := <-entered
		synctest.Sleep(time.Minute - time.Nanosecond)
		require.NoError(t, providerCtx.Err())
		require.Empty(t, done)
		synctest.Sleep(time.Nanosecond)
		err := <-done
		require.ErrorContains(t, err, "code exchange failed")
		require.NotContains(t, err.Error(), "private-code")
		require.ErrorIs(t, providerCtx.Err(), context.DeadlineExceeded)
		<-stopped
	})
}
