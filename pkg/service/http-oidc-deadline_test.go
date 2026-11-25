package service

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func oidcDeadlineTestConfiguration(conf *configuration.Configuration, _ *oidcCodeProvider) {
	conf.Flows[0].Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode).LoginTimeout = common.DurationOf(3 * time.Second)
}

// Web deadline cases keep the real provider's PKCE/JWKS/signature checks, but
// replace its socket before discovery. The SSH cases below retain real TLS/TCP.
func oidcDeadlineTimingConfiguration(conf *configuration.Configuration, provider *oidcCodeProvider) {
	oidcDeadlineTestConfiguration(conf, provider)
	provider.server.Close()
	provider.server.Client().Transport = oidcRefreshTimingTransport(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			defer req.Body.Close()
		}
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		response := httptest.NewRecorder()
		provider.serveCode(response, req)
		return response.Result(), nil
	})
}

func oidcDeadlineTestTransaction(t *testing.T, svc *service, browser oidcBrowserFixture) *oidcBrowserTransaction {
	t.Helper()
	svc.web.oidcMutex.Lock()
	defer svc.web.oidcMutex.Unlock()
	tx := svc.web.oidcBrowsers[sha256.Sum256([]byte(browser.id))]
	require.NotNil(t, tx)
	return tx
}

func awaitOidcDeadline(t *testing.T, tx *oidcBrowserTransaction) {
	t.Helper()
	select {
	case <-tx.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("OIDC transaction did not reach its configured deadline")
	}
}

func awaitOidcPrimary(t *testing.T, svc *service, token string) {
	t.Helper()
	key, _ := webAttemptKey(token)
	svc.web.mutex.Lock()
	attempt := svc.web.attempts[key]
	svc.web.mutex.Unlock()
	require.NotNil(t, attempt)
	select {
	case <-attempt.done:
		require.NoError(t, attempt.err)
		require.NotNil(t, attempt.auth)
		require.True(t, attempt.auth.IsAuthorized())
	case <-time.After(2 * time.Second):
		t.Fatal("primary authorization did not finish before the login deadline")
	}
}

func TestOidcCodeExpiredWebClaimCannotIssueAccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc, handler, provider, recorder := oidcCodeFixture(t, oidcDeadlineTimingConfiguration)
		token, link, handler := startOidcWeb(t, handler)
		browser := openOidcBrowser(t, handler, provider, link)
		require.Equal(t, http.StatusOK, oidcCallbackRequest(handler, browser.callback, browser.cookie).Code)
		awaitOidcPrimary(t, svc, token)
		tx := oidcDeadlineTestTransaction(t, svc, browser)
		deadline, bounded := tx.ctx.Deadline()
		require.True(t, bounded)
		synctest.Sleep(time.Until(deadline) - time.Nanosecond)
		require.NoError(t, tx.ctx.Err())
		awaitOidcDeadline(t, tx)
		require.Equal(t, deadline.UTC(), time.Now().UTC())
		require.Equal(t, "expired", oidcView(t, oidcAPI(handler, "status", map[string]string{"id": browser.id}, browser.cookie)).Status)
		require.Equal(t, http.StatusServiceUnavailable, finishWebAttempt(t, handler, token, "Work").Code)
		require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted))
		svc.web.mutex.Lock()
		defer svc.web.mutex.Unlock()
		require.Empty(t, svc.web.access)
	})
}

type oidcUndeliveredDeadlineContext struct{ context.Context }

func (oidcUndeliveredDeadlineContext) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

func TestOidcCodeAcceptanceChecksDeadlineBeforeCancellationIsDelivered(t *testing.T) {
	web := &webService{ctx: t.Context()}
	tx := &oidcBrowserTransaction{ctx: oidcUndeliveredDeadlineContext{context.Background()}, cancel: func() {}, phase: "authorizing", done: make(chan *authorization.OidcCodeResult, 1)}
	attempt := &oidcAuthentication{transactions: []*oidcBrowserTransaction{tx}, current: tx}
	require.NoError(t, tx.ctx.Err(), "simulate a scheduler that has not delivered cancellation")
	require.False(t, web.finishOidcAuthentication(attempt, true, "access_denied"))
	require.Equal(t, "expired", tx.phase)
	require.Equal(t, "timeout", tx.reason)
}

type oidcDelayedCompletionRecorder struct {
	audit.Recorder
	entered       chan context.Context
	release       chan struct{}
	ignoreContext bool
}

func (r *oidcDelayedCompletionRecorder) Record(ctx context.Context, event audit.Event) error {
	if event.Name == audit.EventNameAuthenticationCompleted && event.Outcome == audit.EventOutcomeSuccess {
		r.entered <- ctx
		<-r.release
		if !r.ignoreContext && ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return r.Recorder.Record(ctx, event)
}

func TestOidcCodeFinalAuditCannotOutliveLoginDeadline(t *testing.T) {
	for _, transport := range []string{"web", "ssh"} {
		for _, ignore := range []bool{false, true} {
			name := "context-aware"
			if ignore {
				name = "ignores-cancellation"
			}
			t.Run(transport+"/"+name, func(t *testing.T) {
				run := func(t *testing.T) {
					configuration := oidcDeadlineTestConfiguration
					if transport == "web" {
						configuration = oidcDeadlineTimingConfiguration
					}
					svc, handler, provider, recorder := oidcCodeFixture(t, configuration)
					delayed := &oidcDelayedCompletionRecorder{Recorder: recorder, entered: make(chan context.Context, 1), release: make(chan struct{}), ignoreContext: ignore}
					var release sync.Once
					t.Cleanup(func() { release.Do(func() { close(delayed.release) }) })
					for flow := range svc.flowAuditRecorders {
						svc.flowAuditRecorders[flow] = delayed
					}
					done := make(chan bool, 1)
					var browser oidcBrowserFixture
					if transport == "web" {
						token, link, initiatingBrowser := startOidcWeb(t, handler)
						handler = initiatingBrowser
						browser = openOidcBrowser(t, handler, provider, link)
						require.Equal(t, http.StatusOK, oidcCallbackRequest(handler, browser.callback, browser.cookie).Code)
						awaitOidcPrimary(t, svc, token)
						go func() {
							response := webAttemptRequest(handler, "poll", token, map[string]string{"slug": "Work"})
							done <- response.Code == http.StatusOK
						}()
					} else {
						address := serveOidcSSH(t, svc, provider)
						messages := make(chan string, 4)
						go func() {
							client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "alice", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 8 * time.Second,
								Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, instruction string, questions []string, _ []bool) ([]string, error) {
									messages <- instruction
									return make([]string, len(questions)), nil
								})}})
							if client != nil {
								_ = client.Close()
							}
							done <- err == nil
						}()
						var message string
						select {
						case message = <-messages:
						case <-time.After(2 * time.Second):
							t.Fatal("no SSH login instruction")
						}
						browser = openOidcBrowser(t, handler, provider, regexp.MustCompile(`https://\S+`).FindString(message))
						view := oidcView(t, oidcCallbackRequest(handler, browser.callback, browser.cookie))
						comparison := regexp.MustCompile(`code "([3479CDFHJKMNPRTUVWXY]{2})"`).FindStringSubmatch(message)
						require.Len(t, comparison, 2)
						require.Equal(t, http.StatusOK, oidcAPI(handler, "approve", map[string]string{"id": browser.id, "csrf": view.CSRF, "code": comparison[1]}, browser.cookie).Code)
					}
					var auditCtx context.Context
					select {
					case auditCtx = <-delayed.entered:
					case <-time.After(2 * time.Second):
						t.Fatal("final audit was not reached before expiration")
					}
					tx := oidcDeadlineTestTransaction(t, svc, browser)
					deadline, _ := tx.ctx.Deadline()
					auditDeadline, bounded := auditCtx.Deadline()
					require.True(t, bounded, "final audit must retain the OIDC deadline")
					require.False(t, auditDeadline.After(deadline))
					if transport == "web" {
						synctest.Sleep(time.Until(deadline) - time.Nanosecond)
						require.NoError(t, auditCtx.Err())
					}
					awaitOidcDeadline(t, tx)
					require.Equal(t, "expired", oidcView(t, oidcAPI(handler, "status", map[string]string{"id": browser.id}, browser.cookie)).Status)
					release.Do(func() { close(delayed.release) })
					select {
					case accepted := <-done:
						require.False(t, accepted, "an expired login must never become transport access")
					case <-time.After(3 * time.Second):
						t.Fatal("transport did not finish after the audit returned")
					}
					require.Equal(t, "expired", oidcView(t, oidcAPI(handler, "status", map[string]string{"id": browser.id}, browser.cookie)).Status)
					svc.web.mutex.Lock()
					require.Empty(t, svc.web.access)
					svc.web.mutex.Unlock()
				}
				if transport == "web" {
					synctest.Test(t, run)
				} else {
					run(t)
				}
			})
		}
	}
}
