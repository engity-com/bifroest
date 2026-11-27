package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func runtimeHttpAccess(t *testing.T, svc *service, current *service, token, slug string) *webAccess {
	t.Helper()
	access, err := svc.web.forService(current).lookup(webScope{Origin: "https://app.example.org", Slug: slug}, token, false)
	require.NoError(t, err)
	return access
}

func runtimeHttpInspect(handler http.Handler, token, slug string) *httptest.ResponseRecorder {
	return webTestRequest(handler, http.MethodPost, "app.example.org", webAPI+"access", `{"slug":"`+slug+`"}`, token)
}

func TestRuntimeHttpChangedFlowRequiresNewLoginButUnchangedGrantSurvives(t *testing.T) {
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		stable := conf.Flows[0]
		stable.Name = "stable"
		stable.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Stable$")
		conf.Flows = append(conf.Flows, stable)
	})
	old := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	stable := webTestToken(t, webTestPassword(handler, "alice", "correct", "Stable"))
	original := runtimeHttpAccess(t, svc, svc, old, "Work")
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(19)
	})
	runtimeSshActivate(t, svc, next)
	require.Equal(t, http.StatusUnauthorized, runtimeHttpInspect(handler, old, "Work").Code)
	require.Equal(t, http.StatusOK, runtimeHttpInspect(handler, stable, "Stable").Code)
	require.False(t, original.closed, "invalidating new actions must not close a grant's running children")
	require.Equal(t, http.StatusUnauthorized, webTestPassword(handler, "alice", "correct", "Work").Code)
	fresh := webTestToken(t, webTestPassword(handler, "alice", "changed", "Work"))
	current := runtimeHttpAccess(t, svc, next, fresh, "Work")
	require.Same(t, next, current.owner)
	require.NotEqual(t, original.auth.FindSession().Id(), current.auth.FindSession().Id())
	require.Equal(t, http.StatusOK, runtimeHttpInspect(handler, fresh, "Work").Code)
	reverted := runtimeSshCandidate(t, next, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:correct")
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(0)
	})
	runtimeSshActivate(t, svc, reverted)
	require.Equal(t, http.StatusUnauthorized, runtimeHttpInspect(handler, old, "Work").Code, "changing back must not revive old browser grants")
	require.Equal(t, http.StatusOK, runtimeHttpInspect(handler, stable, "Stable").Code)
	logout := webTestRequest(handler, http.MethodPost, "app.example.org", webAPI+"logout", `{"slug":"Work"}`, old)
	require.Equal(t, http.StatusNoContent, logout.Code, "stale grants remain addressable for explicit logout")
}

func TestRuntimeHttpPresentationChangeKeepsBrowserGrantAndPendingRememberProof(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	challenge := rememberTestStart(t, handler, "enroll", token, map[string]string{"slug": "Work", "publicKey": public})
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Flows[0].Title = "new title"
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).Banner = template.MustNewString("new banner")
	})
	runtimeSshActivate(t, svc, next)
	require.Equal(t, http.StatusOK, runtimeHttpInspect(handler, token, "Work").Code)
	proof := rememberTestProve(t, handler, challenge, key)
	require.Equal(t, http.StatusCreated, proof.Code, proof.Body.String())
	require.Same(t, svc.generation.flows[svc.Configuration.Flows[0].Name].actions, next.generation.flows[svc.Configuration.Flows[0].Name].actions)
}

func runtimeHttpRequest(t *testing.T, client *http.Client, path, body, token string) (int, []byte, httptrace.GotConnInfo, int) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://app.example.org"+webAPI+path, strings.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Origin", "https://app.example.org")
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	var info httptrace.GotConnInfo
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(value httptrace.GotConnInfo) { info = value }}))
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return response.StatusCode, data, info, response.ProtoMajor
}

func runtimeHttpToken(t *testing.T, code int, data []byte) string {
	t.Helper()
	require.Equal(t, http.StatusOK, code, string(data))
	var result struct {
		Token string `json:"accessToken"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	require.NotEmpty(t, result.Token)
	return result.Token
}

func TestRuntimeHttpNewLoginsUseCurrentGenerationOnExistingHttpConnections(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[http2], func(t *testing.T) {
			fixture := newWebSocketFixture(t, nil)
			transport := fixture.client.Transport.(*http.Transport).Clone()
			transport.ForceAttemptHTTP2 = http2
			if !http2 {
				transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
				transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
			}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			body := `{"slug":"Work","user":"alice","password":"correct"}`
			code, data, initial, major := runtimeHttpRequest(t, client, "login/password", body, "")
			runtimeHttpToken(t, code, data)
			require.Equal(t, map[bool]int{false: 1, true: 2}[http2], major)
			next := runtimeSshCandidate(t, fixture.svc, func(conf *configuration.Configuration) {
				conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
			})
			runtimeSshActivate(t, fixture.svc, next)
			code, _, reused, _ := runtimeHttpRequest(t, client, "login/password", body, "")
			require.Equal(t, http.StatusUnauthorized, code)
			require.True(t, reused.Reused)
			require.Same(t, initial.Conn, reused.Conn)
			code, data, reused, _ = runtimeHttpRequest(t, client, "login/password", strings.Replace(body, "correct", "changed", 1), "")
			token := runtimeHttpToken(t, code, data)
			require.Same(t, initial.Conn, reused.Conn)
			require.Same(t, next, runtimeHttpAccess(t, fixture.svc, next, token, "Work").owner)
		})
	}
}

func TestRuntimeHttpCanLoginAfterInitialProvidersHaveDrained(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "new" })
	runtimeSshActivate(t, svc, next)
	runtimeResourcesWaitClosed(t, svc)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	require.Same(t, next, runtimeHttpAccess(t, svc, next, token, "Work").owner)
	require.Equal(t, http.StatusOK, runtimeHttpInspect(handler, token, "Work").Code)
}

func TestRuntimeHttpReloadDoesNotResetBrowserBudgets(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	for range webMaximumLoginsPerMinute {
		require.Equal(t, http.StatusUnauthorized, webTestPassword(handler, "alice", "wrong", "Work").Code)
	}
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "new" })
	runtimeSshActivate(t, svc, next)
	response := webTestPassword(handler, "alice", "correct", "Work")
	require.Equal(t, http.StatusTooManyRequests, response.Code)
	require.Empty(t, svc.web.access)
}

func TestRuntimeHttpRunningTerminalSurvivesButOldGrantCannotOpenAnother(t *testing.T) {
	entered := make(chan environment.TerminalTask, 1)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		entered <- task
		select {
		case <-task.Context().Done():
			return -1, task.Context().Err()
		case <-release:
		}
		_, err := io.WriteString(task.Terminal(), "old-generation")
		return 7, err
	})
	token := fixture.login(t)
	old := fixture.dial(t)
	require.NoError(t, old.WriteJSON(webSocketOpen(token)))
	requireWebSocketReady(t, old)
	var task environment.TerminalTask
	select {
	case task = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal did not start")
	}
	next := runtimeSshCandidate(t, fixture.svc, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(19)
	})
	runtimeSshActivate(t, fixture.svc, next)
	require.NoError(t, task.Context().Err())
	denied := fixture.dial(t)
	require.NoError(t, denied.WriteJSON(webSocketOpen(token)))
	require.Equal(t, `"error"`, string(webSocketStatus(t, denied)["type"]))
	freshToken := fixture.login(t)
	fresh := fixture.dial(t)
	require.NoError(t, fresh.WriteJSON(webSocketOpen(freshToken)))
	requireWebSocketReady(t, fresh)
	_, _, result := webSocketResult(t, fresh)
	require.Equal(t, "19", string(result["status"]))
	unblock()
	output, _, result := webSocketResult(t, old)
	require.Equal(t, "old-generation", string(output))
	require.Equal(t, "7", string(result["status"]))
}

func TestRuntimeHttpPendingLoginCannotPublishChangedFlowButCanFinishUnchangedFlow(t *testing.T) {
	for _, modified := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "changed"}[modified], func(t *testing.T) {
			svc, handler, _ := webTestFixture(t)
			token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
			step := waitWebLoginStep(t, handler, token, "Work")
			next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
				if modified {
					conf.Flows[0].Ssh.Enabled = common.P(false)
				} else {
					other := conf.Flows[0]
					other.Name = "unrelated"
					other.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Other$")
					conf.Flows = append(conf.Flows, other)
				}
			})
			runtimeSshActivate(t, svc, next)
			require.Equal(t, http.StatusAccepted, answerWebStep(handler, token, "Work", step, "correct").Code)
			response := finishWebAttempt(t, handler, token, "Work")
			if modified {
				require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
				require.Empty(t, svc.web.access)
			} else {
				access := webTestToken(t, response)
				require.Equal(t, http.StatusOK, runtimeHttpInspect(handler, access, "Work").Code)
				require.Same(t, svc, runtimeHttpAccess(t, svc, next, access, "Work").owner)
			}
		})
	}
}

func TestRuntimeHttpDelayedAuthenticationAuditCannotPublishAfterReload(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	flow := svc.Configuration.Flows[0].Name
	gate := &maintenanceTestAuditGate{Recorder: svc.flowAuditRecorders[flow], name: audit.EventNameAuthenticationCompleted, entered: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	svc.flowAuditRecorders[flow] = gate
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- webTestPassword(handler, "alice", "correct", "Work") }()
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("login did not reach final audit")
	}
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Ssh.Enabled = common.P(false) })
	runtimeSshActivate(t, svc, next) // Slow external work must not own the publication lock.
	unblock()
	result := <-response
	require.Equal(t, http.StatusServiceUnavailable, result.Code, result.Body.String())
	require.Empty(t, svc.web.access, "no obsolete grant may appear after accepted activation")
}

func TestRuntimeHttpCanceledAttemptPinsItsProviderUntilWorkerReturns(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	delegate := svc.authorizer
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	svc.authorizer = &webInteractionTestAuthorizer{CloseableAuthorizer: delegate, run: func(req authorization.InteractiveRequest) (authorization.Authorization, error) {
		close(entered)
		<-release
		return nil, req.Context().Err()
	}}
	token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("login worker did not start")
	}
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Ssh.Enabled = common.P(false) })
	runtimeSshActivate(t, svc, next)
	require.Equal(t, http.StatusNoContent, webAttemptRequest(handler, "cancel", token, map[string]string{"slug": "Work"}).Code)
	runtimeGenerationTestNotDrained(t, svc.generation)
	unblock()
	runtimeResourcesWaitClosed(t, svc)
}

type runtimeHttpManagementRepository struct {
	environment.CloseableRepository
	entered chan struct{}
	release chan struct{}
}

func (this *runtimeHttpManagementRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, _ := environment.SessionTargetResolverFor(this.CloseableRepository, ctx.Authorization().Flow())
	return resolver.ResolveSessionTarget(ctx)
}

func (this *runtimeHttpManagementRepository) Ensure(req environment.Request) (environment.Environment, error) {
	env, err := this.CloseableRepository.Ensure(req)
	if err != nil {
		return nil, err
	}
	return &runtimeHttpManagementEnvironment{Environment: env, gate: this}, nil
}

type runtimeHttpManagementEnvironment struct {
	environment.Environment
	gate *runtimeHttpManagementRepository
}

func (this *runtimeHttpManagementEnvironment) ReadManagement(task environment.TaskContext, req protocol.ReadRequest, output io.Writer) (int, error) {
	close(this.gate.entered)
	select {
	case <-this.gate.release:
	case <-task.Context().Done():
		return -1, task.Context().Err()
	}
	return this.Environment.(environment.ManagementReader).ReadManagement(task, req, output)
}

func TestRuntimeHttpManagementChannelKeepsRunningReadButRequiresNewLoginForNextAction(t *testing.T) {
	fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	gate := &runtimeHttpManagementRepository{CloseableRepository: fixture.svc.environments, entered: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	fixture.svc.environments = gate
	socket := managementChannelDial(t, fixture, fixture.login(t), false)
	requireWebSocketReady(t, socket)
	require.NoError(t, socket.WriteJSON(map[string]any{"type": "request", "requestId": "1", "action": "management/flows/list", "fields": map[string]string{}}))
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("management read did not start")
	}
	next := runtimeSshCandidate(t, fixture.svc, func(conf *configuration.Configuration) { conf.Flows[0].Ssh.Enabled = common.P(false) })
	runtimeSshActivate(t, fixture.svc, next)
	unblock()
	status := webSocketStatus(t, socket)
	require.Equal(t, `"response"`, string(status["type"]))
	require.Equal(t, "200", string(status["status"]))
	for {
		kind, data, err := socket.ReadMessage()
		require.NoError(t, err)
		if kind == websocket.TextMessage {
			require.Contains(t, string(data), `"complete"`)
			break
		}
	}
	code, _ := managementChannelRead(t, socket, "2", "version/show", nil)
	require.Equal(t, http.StatusUnauthorized, code)
	fresh := managementChannelDial(t, fixture, fixture.login(t), false)
	requireWebSocketReady(t, fresh)
	code, _ = managementChannelRead(t, fresh, "1", "version/show", nil)
	require.Equal(t, http.StatusOK, code)
}

func TestRuntimeHttpUnchangedManagementChannelReadsCurrentWorkspace(t *testing.T) {
	fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
		other := conf.Flows[0]
		other.Name = "other"
		other.Title = "before"
		other.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Other$")
		conf.Flows = append(conf.Flows, other)
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	socket := managementChannelDial(t, fixture, fixture.login(t), false)
	requireWebSocketReady(t, socket)
	next := runtimeSshCandidate(t, fixture.svc, func(conf *configuration.Configuration) { conf.Flows[1].Name = "after-reload" })
	runtimeSshActivate(t, fixture.svc, next)
	code, data := managementChannelRead(t, socket, "1", "flows/list", nil)
	require.Equal(t, http.StatusOK, code, string(data))
	require.Contains(t, string(data), "after-reload", "the old channel must not select the initial workspace for new operations")
}

func TestRuntimeHttpRememberProofMustRestartAfterFlowChange(t *testing.T) {
	for _, resume := range []bool{false, true} {
		t.Run(map[bool]string{false: "enroll", true: "resume"}[resume], func(t *testing.T) {
			svc, handler, _ := webTestFixture(t)
			key, public := rememberTestKey(t)
			token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
			access := runtimeHttpAccess(t, svc, svc, token, "Work")
			var challenge rememberTestChallenge
			var binding rememberTestBinding
			if resume {
				binding = rememberTestEnroll(t, handler, token, public, key)
				challenge = rememberTestStart(t, handler, "resume", "", binding.selector())
			} else {
				challenge = rememberTestStart(t, handler, "enroll", token, map[string]string{"slug": "Work", "publicKey": public})
			}
			next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Ssh.Enabled = common.P(false) })
			runtimeSshActivate(t, svc, next)
			response := rememberTestProve(t, handler, challenge, key)
			require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
			entries, err := access.auth.FindSession().(session.BrowserBindingSession).BrowserBindings(t.Context())
			require.NoError(t, err)
			if resume {
				require.Len(t, entries, 1)
				require.EqualValues(t, 1, entries[0].Revision, "a rejected old proof must not consume/renew the stored binding")
				fresh := rememberTestResume(t, handler, binding, key)
				require.Equal(t, http.StatusOK, runtimeHttpInspect(handler, fresh, "Work").Code)
			} else {
				require.Empty(t, entries)
			}
		})
	}
}

func TestRuntimeHttpRememberAuditCannotRenewOldProofAfterReload(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	key, public := rememberTestKey(t)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	access := runtimeHttpAccess(t, svc, svc, token, "Work")
	binding := rememberTestEnroll(t, handler, token, public, key)
	challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
	gate := &maintenanceTestAuditGate{Recorder: svc.flowAuditRecorders[access.auth.Flow()], name: audit.EventNameAuthenticationCompleted, entered: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	svc.flowAuditRecorders[access.auth.Flow()] = gate
	signature := rememberTestSignature(t, key, challenge)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- rememberTestRequest(handler, "prove", challenge.AttemptToken, map[string]string{"slug": "Work", "signature": signature})
	}()
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("RememberMe did not reach final audit")
	}
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Ssh.Enabled = common.P(false) })
	runtimeSshActivate(t, svc, next)
	unblock()
	response := <-done
	require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
	entries, err := access.auth.FindSession().(session.BrowserBindingSession).BrowserBindings(t.Context())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.EqualValues(t, 1, entries[0].Revision)
	require.Len(t, svc.web.access, 1, "no new grant published from the delayed proof")
}

func TestRuntimeHttpGrantAndInFlightRequestPinAuthorizationOwner(t *testing.T) {
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		other := conf.Flows[0]
		other.Name = "other"
		other.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Other$")
		conf.Flows = append(conf.Flows, other)
	})
	// The later login reuses an initial session; its newer authorizer must
	// nevertheless survive as long as a grant or request still uses it.
	webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	second := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "second" })
	runtimeSshActivate(t, svc, second)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	access := runtimeHttpAccess(t, svc, second, token, "Work")
	require.Same(t, svc.generation, svc.runtime.sessionOwner(access.auth.FindSession()))
	third := runtimeSshCandidate(t, second, func(conf *configuration.Configuration) { conf.Flows[1].Title = "third" })
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	provider := third.environments
	var once sync.Once
	third.environments = &executionTestRepository{CloseableRepository: provider, onAccept: func(ctx environment.Context) (bool, error) {
		once.Do(func() { close(entered) })
		<-release
		return provider.WillBeAccepted(ctx)
	}}
	runtimeSshActivate(t, svc, third)
	runtimeGenerationTestNotDrained(t, second.generation)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- runtimeHttpInspect(handler, token, "Work") }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("grant inspection did not start")
	}
	logout := webTestRequest(handler, http.MethodPost, "app.example.org", webAPI+"logout", `{"slug":"Work"}`, token)
	require.Equal(t, http.StatusNoContent, logout.Code)
	runtimeGenerationTestNotDrained(t, second.generation)
	unblock()
	require.Equal(t, http.StatusUnauthorized, (<-done).Code, "concurrent logout still wins before response")
	runtimeResourcesWaitClosed(t, second)
}

func TestRuntimeHttpRemovedFlowClosesRunningTerminalAndCannotReviveGrant(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		close(entered)
		<-task.Context().Done()
		close(canceled)
		return -1, task.Context().Err()
	})
	token := fixture.login(t)
	access := runtimeHttpAccess(t, fixture.svc, fixture.svc, token, "Work")
	socket := fixture.dial(t)
	require.NoError(t, socket.WriteJSON(webSocketOpen(token)))
	requireWebSocketReady(t, socket)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal did not start")
	}
	removed := runtimeSshCandidate(t, fixture.svc, func(conf *configuration.Configuration) { conf.Flows[0].Name = "replacement" })
	runtimeSshActivate(t, fixture.svc, removed)
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("flow deletion did not cancel the old terminal")
	}
	recreated := runtimeSshCandidate(t, removed, func(conf *configuration.Configuration) { conf.Flows[0].Name = access.auth.Flow() })
	runtimeSshActivate(t, fixture.svc, recreated)
	code, _, _, _ := runtimeHttpRequest(t, fixture.client, "access", `{"slug":"Work"}`, token)
	require.Equal(t, http.StatusUnauthorized, code)
	fresh := fixture.login(t)
	current := runtimeHttpAccess(t, fixture.svc, recreated, fresh, "Work")
	require.NotEqual(t, access.auth.FindSession().Id(), current.auth.FindSession().Id())
}

func TestRuntimeHttpWatchModesReconnectOnlyWhenRequested(t *testing.T) {
	for _, mode := range []configuration.WatchMode{configuration.WatchModePreserve, configuration.WatchModeReconnect, configuration.WatchModeReuse} {
		t.Run(mode.String(), func(t *testing.T) {
			entered, canceled := make(chan struct{}), make(chan struct{})
			fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
				close(entered)
				<-task.Context().Done()
				close(canceled)
				return -1, task.Context().Err()
			})
			fixture.svc.Watch, fixture.svc.runtime.watch = mode, mode
			token := fixture.login(t)
			socket := fixture.dial(t)
			require.NoError(t, socket.WriteJSON(webSocketOpen(token)))
			requireWebSocketReady(t, socket)
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("terminal did not start")
			}
			next := runtimeSshCandidate(t, fixture.svc, func(conf *configuration.Configuration) { conf.Flows[0].Ssh.Enabled = common.P(false) })
			runtimeSshActivate(t, fixture.svc, next)
			require.Equal(t, http.StatusUnauthorized, runtimeHttpInspect(fixture.svc.web, token, "Work").Code)
			if mode == configuration.WatchModeReconnect {
				select {
				case <-canceled:
				case <-time.After(3 * time.Second):
					t.Fatal("reconnect mode did not stop the affected terminal")
				}
			} else {
				select {
				case <-canceled:
					t.Fatal("preserving mode stopped a running terminal")
				default:
				}
			}
		})
	}
}

func TestRuntimeHttpOidcFinalClaimCannotPublishAnOldFlow(t *testing.T) {
	svc, handler, provider, _ := oidcCodeFixture(t)
	login := func() string {
		token, link, initiating := startOidcWeb(t, handler)
		browser := openOidcBrowser(t, initiating, provider, link)
		require.Equal(t, http.StatusOK, oidcCallbackRequest(initiating, browser.callback, browser.cookie).Code)
		return webTestToken(t, finishWebAttempt(t, initiating, token, "Work"))
	}
	first := login()
	original := runtimeHttpAccess(t, svc, svc, first, "Work").auth.FindSession()
	token, link, initiating := startOidcWeb(t, handler)
	browser := openOidcBrowser(t, initiating, provider, link)
	require.Equal(t, http.StatusOK, oidcCallbackRequest(initiating, browser.callback, browser.cookie).Code)
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Ssh.Enabled = common.P(false)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, provider.server.Client())
	next, err := svc.prepareGeneration(ctx, conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(next.generation) {
			<-next.generationClosed
		}
	})
	runtimeSshActivate(t, svc, next)
	require.Equal(t, http.StatusUnauthorized, finishWebAttempt(t, initiating, token, "Work").Code)
	require.Equal(t, "denied", oidcView(t, oidcAPI(initiating, "status", map[string]string{"id": browser.id}, browser.cookie)).Status)
	require.Equal(t, http.StatusUnauthorized, runtimeHttpInspect(handler, first, "Work").Code)
	require.False(t, svc.runtime.sessionRevoked(original), "blocking new HTTP actions must not revoke the retained OIDC session")
	fresh := login()
	require.Equal(t, http.StatusOK, runtimeHttpInspect(handler, fresh, "Work").Code)
	require.Same(t, next, runtimeHttpAccess(t, svc, next, fresh, "Work").owner)
}
