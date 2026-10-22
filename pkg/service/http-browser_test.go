package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/https"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

func webTestFixture(t *testing.T, configure ...func(*configuration.Configuration)) (*service, http.Handler, *recordingAuditRecorder) {
	t.Helper()
	svc, recorder, _ := executionTestFixture(t, func(environment.TerminalTask) (int, error) { return 0, nil }, configure...)
	svc.web = newWebService(svc)
	boundary, err := https.Boundary(configuration.HttpDomains{"app.example.org", "other.example.org"}, svc.web)
	require.NoError(t, err)
	return svc, boundary, recorder
}

func webTestRequest(handler http.Handler, method, authority, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+authority+path, strings.NewReader(body))
	r.URL.Scheme, r.URL.Host = "", "" // Server-side origin-form, never an absolute proxy request.
	r.Host = authority
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: strings.Split(authority, ":")[0]}
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Origin", "https://"+authority)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func webTestPassword(handler http.Handler, user, password, slug string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"slug": slug, "user": user, "password": password})
	return webTestRequest(handler, "POST", "app.example.org", webAPI+"login/password", string(body), "")
}

func webTestToken(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var result struct {
		AccessToken string `json:"accessToken"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.NotEmpty(t, result.AccessToken)
	return result.AccessToken
}

func webTestAccess(t *testing.T, svc *service, token, slug string) *webAccess {
	t.Helper()
	access, err := svc.web.lookup(webScope{Origin: "https://app.example.org", Slug: slug}, token, false)
	require.NoError(t, err)
	return access
}

func TestWebPasswordUsesHttpSelectionAndSharedAuthorizer(t *testing.T) {
	svc, handler, recorder := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Ssh.Enabled = commonBool(false)
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Flows[0].Requirement.IncludedRequestingName = common.MustNewRegexp("^alice$")
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp("^Work$")
	})
	denied := webTestPassword(handler, "alice", "wrong", "Work")
	require.Equal(t, http.StatusUnauthorized, denied.Code)
	require.Empty(t, svc.web.access)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	access := webTestAccess(t, svc, token, "Work")
	require.Equal(t, "alice", access.identity.Principal)
	bound, err := session.AssociationOf(t.Context(), access.auth.FindSession())
	require.NoError(t, err)
	require.NotNil(t, bound)
	require.Equal(t, access.target, bound.Target)
	events := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameAuthenticationCompleted)
	require.Len(t, events, 1)
	require.Equal(t, audit.EventOutcomeSuccess, events[0].Outcome)
	require.NotEmpty(t, events[0].ConnectionId)
	require.NotContains(t, webTestPassword(handler, "alice", "correct", "work").Body.String(), "bwa1.")
	for _, value := range []struct{ host, slug string }{{"other.example.org", "Work"}, {"app.example.org:444", "Work"}, {"app.example.org", "Other"}} {
		w := webTestRequest(handler, "POST", value.host, webAPI+"access", `{"slug":"`+value.slug+`"}`, token)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	}
	ok := webTestRequest(handler, "POST", "APP.EXAMPLE.ORG:443", webAPI+"access", `{"slug":"Work"}`, token)
	require.Equal(t, http.StatusOK, ok.Code)
	require.NotContains(t, ok.Body.String(), token)
	require.Empty(t, ok.Header().Values("Set-Cookie"))
}

func TestWebScopeCanonicalizesAuthorityButKeepsPortAndSlug(t *testing.T) {
	for _, test := range []struct{ host, want string }{{"APP.EXAMPLE.ORG.:00443", "https://app.example.org"}, {"app.example.org:0444", "https://app.example.org:444"}, {"[2001:DB8::1]:443", "https://[2001:db8::1]"}, {"BÜCHER.example", "https://xn--bcher-kva.example"}} {
		scope, err := requestWebScope(&http.Request{Host: test.host}, "Case/Sensitive")
		require.NoError(t, err)
		require.Equal(t, test.want, scope.Origin)
		require.Equal(t, "Case/Sensitive", scope.Slug)
	}
}

func TestWebPublishedSlugNeverFallsThroughAndDiscoveryIsNotAuthorization(t *testing.T) {
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		first := conf.Flows[0]
		first.Name = "fixed"
		first.DiscoverAsSlug = "Private"
		first.Requirement.Http.IncludedRequestingName = common.MustNewRegexp("^other$")
		fallback := conf.Flows[0]
		fallback.Name = "fallback"
		fallback.DiscoverAsSlug = "Public"
		disabled := fallback
		disabled.Name = "off"
		disabled.DiscoverAsSlug = "Hidden"
		disabled.Http.Enabled = commonBool(false)
		onOther := fallback
		onOther.Name = "other"
		onOther.DiscoverAsSlug = "Elsewhere"
		onOther.Requirement.Http.IncludedHost = common.MustNewRegexp("^other\\.example\\.org$")
		conf.Flows = configuration.Flows{first, fallback, disabled, onOther}
	})
	root := webTestRequest(handler, "GET", "app.example.org", "/", "", "")
	require.Equal(t, http.StatusOK, root.Code)
	require.Contains(t, root.Body.String(), `"Private"`)
	require.Contains(t, root.Body.String(), `"Public"`)
	require.NotContains(t, root.Body.String(), "Hidden")
	require.NotContains(t, root.Body.String(), "Elsewhere")
	get := webTestRequest(handler, "GET", "app.example.org", "/Private", "", "")
	require.Equal(t, http.StatusOK, get.Code)
	require.Empty(t, svc.web.access)
	require.Equal(t, http.StatusUnauthorized, webTestPassword(handler, "alice", "correct", "Private").Code)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Public"))
	require.Equal(t, configuration.FlowName("fallback"), webTestAccess(t, svc, token, "Public").auth.Flow())
	token = webTestToken(t, webTestPassword(handler, "alice", "correct", "Unknown"))
	require.Equal(t, configuration.FlowName("fallback"), webTestAccess(t, svc, token, "Unknown").auth.Flow())
	r := httptest.NewRequest("GET", "https://app.example.org/", nil)
	r.URL.Scheme, r.URL.Host = "", ""
	r.Host = "app.example.org"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "app.example.org"}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Contains(t, w.Header().Get("Content-Type"), "text/html")
	require.Contains(t, w.Body.String(), `href="/Private"`)
	require.NotContains(t, w.Body.String(), "Hidden")
}

func TestWebRequestUserDisabledRetainsEmptyRemoteUser(t *testing.T) {
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Http.RequestUser = commonBool(false)
		conf.Flows[0].Authorization.V = &configuration.AuthorizationNone{}
	})
	metadata := webTestRequest(handler, "GET", "app.example.org", "/Work", "", "")
	require.Contains(t, metadata.Body.String(), `"requestUser":false`)
	require.Equal(t, http.StatusUnauthorized, webTestPassword(handler, "alice", "", "Work").Code)
	one := webTestToken(t, webTestPassword(handler, "", "", "Work"))
	two := webTestToken(t, webTestPassword(handler, "", "", "Work"))
	first := webTestAccess(t, svc, one, "Work")
	second := webTestAccess(t, svc, two, "Work")
	require.Empty(t, first.user)
	require.False(t, first.identity.IsAuthenticated())
	require.NotEqual(t, first.auth.FindSession().Id(), second.auth.FindSession().Id(), "anonymous labels cannot share sessions")
	for _, fake := range []string{first.auth.FindSession().Id().String(), "bwa1." + first.auth.FindSession().Id().String(), ""} {
		response := webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, fake)
		require.Equal(t, http.StatusUnauthorized, response.Code)
	}
}

func TestWebJsonBoundaryRejectsAmbiguityBeforeAuthentication(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	for _, body := range []string{
		`{"slug":"Work","user":"alice","password":"correct","user":"other"}`,
		`{"slug":"Work","user":"alice","password":null}`,
		`{"slug":"Work","user":"alice","password":"correct","privateKey":"must stay in tab"}`,
		`{"slug":"Work","user":"alice","password":"correct"}{}`,
		`{"slug":"Work/","user":"alice","password":"correct"}`,
		`{"slug":"Work","password":"correct"}`,
		`{"slug":"Work","user":"alice","password":"` + strings.Repeat("x", webLoginBodyLimit) + `"}`,
	} {
		w := webTestRequest(handler, "POST", "app.example.org", webAPI+"login/password", body, "")
		require.Equal(t, http.StatusBadRequest, w.Code, body[:min(len(body), 100)])
	}
	require.Empty(t, svc.web.access)
	count := 0
	require.NoError(t, svc.sessions.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	require.Zero(t, count)
	for _, path := range []string{"/Work/", "/%57ork", "/Work//Other", "/Work/../Other", webAPI + "login/password?token=secret"} {
		method := http.MethodGet
		if strings.HasPrefix(path, webAPI) {
			method = http.MethodPost
		}
		w := webTestRequest(handler, method, "app.example.org", path, `{"slug":"Work","user":"alice","password":"correct"}`, "")
		require.Equal(t, http.StatusBadRequest, w.Code, path)
	}
}

func TestWebLoginRequiresBoundaryOriginAndDoesNotTrustForwardedPeer(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	for _, origin := range []string{"", "null", "https://other.example.org", "https://app.example.org:444"} {
		r := httptest.NewRequest("POST", "https://app.example.org"+webAPI+"login/password", strings.NewReader(`{"slug":"Work","user":"alice","password":"correct"}`))
		r.URL.Scheme, r.URL.Host = "", ""
		r.Host = "app.example.org"
		r.RemoteAddr = "127.0.0.1:12345"
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "app.example.org"}
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		require.Equal(t, http.StatusForbidden, w.Code)
	}
	r := httptest.NewRequest("POST", "https://app.example.org"+webAPI+"login/password", strings.NewReader(`{"slug":"Work","user":"alice","password":"correct"}`))
	r.URL.Scheme, r.URL.Host = "", ""
	r.Host = "app.example.org"
	r.RemoteAddr = "127.0.0.1:12345"
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "app.example.org"}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://app.example.org")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("Forwarded", "for=10.0.0.1;host=other.example.org")
	r.Header.Set("Cookie", "session=not-an-authentication-proof")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	token := webTestToken(t, w)
	access := webTestAccess(t, svc, token, "Work")
	info, err := access.auth.FindSession().Info(t.Context())
	require.NoError(t, err)
	created, err := info.Created(t.Context())
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", created.Remote().Host().String())
	require.Empty(t, w.Header().Values("Set-Cookie"))
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
}

func TestWebStrictAuthenticationAuditFailureNeverIssuesAccess(t *testing.T) {
	svc, handler, recorder := webTestFixture(t)
	recorder.setErrorBeforeRecordForName(audit.EventNameAuthenticationCompleted, errors.New("test-secret-internal-error"))
	w := webTestPassword(handler, "alice", "correct", "Work")
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.NotContains(t, w.Body.String(), "test-secret")
	require.Empty(t, svc.web.access)
}

func TestWebBestEffortAuditFailureUsesExistingPolicy(t *testing.T) {
	svc, handler, recorder := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Auditlogs[0].FailurePolicy = configuration.AuditlogFailurePolicyBestEffort
	})
	flow := svc.Configuration.Flows[0].Name
	auditlog := svc.flowAuditlogs[flow]
	svc.flowAuditRecorders[flow] = &failurePolicyAuditRecorder{service: svc, auditlog: auditlog, delegate: recorder}
	recorder.setErrorBeforeRecordForName(audit.EventNameAuthenticationCompleted, errors.New("audit unavailable"))
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	require.NotNil(t, webTestAccess(t, svc, token, "Work"))
	require.True(t, svc.auditlogDisabled(auditlog))
}

func TestWebBearerAllowsOnlyItsOwnAnonymousSession(t *testing.T) {
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V = &configuration.AuthorizationNone{}
	})
	token := webTestToken(t, webTestPassword(handler, "", "", "Work"))
	access := webTestAccess(t, svc, token, "Work")
	transport := &executionTestTransport{stream: &executionTestStream{recordingTerminalTestStream: newRecordingTerminalTestStream(t), command: "run"}, id: bconn.MustNewId()}
	conn, err := svc.web.connect(access.scope, token, transport)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(); <-conn.done })
	require.Equal(t, access.auth.FindSession().Id(), conn.session.Id())
	require.Empty(t, conn.Remote().User(), "do not substitute the new adapter's client name")
	code, err := svc.executeTerminal(conn, transport.stream, true)
	require.NoError(t, err)
	require.Zero(t, code)
	_, err = svc.executeTerminal(conn, transport.stream, true)
	require.ErrorContains(t, err, "already has an execution")
}

type webMutableTargetRepository struct {
	environment.CloseableRepository
	version atomic.Int32
}

func (this *webMutableTargetRepository) ResolveSessionTarget(environment.Context) (session.Target, error) {
	return session.NewTarget("web-test", map[string]string{"target": fmt.Sprint(this.version.Load())})
}

func TestWebAnonymousPermissionAlsoPinsTheEffectiveTarget(t *testing.T) {
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V = &configuration.AuthorizationNone{}
	})
	repo := &webMutableTargetRepository{CloseableRepository: svc.environments}
	svc.environments = repo
	token := webTestToken(t, webTestPassword(handler, "", "", "Work"))
	access := webTestAccess(t, svc, token, "Work")
	repo.version.Add(1)
	w := webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, token)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	transport := &executionTestTransport{stream: &executionTestStream{recordingTerminalTestStream: newRecordingTerminalTestStream(t)}, id: bconn.MustNewId()}
	conn, err := svc.web.connect(access.scope, token, transport)
	require.Nil(t, conn)
	require.ErrorContains(t, err, "target changed")
}

func TestWebLoginDoesNotReserveQuotaButEachConnectionDoes(t *testing.T) {
	svc, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) { conf.Session.V.(*configuration.SessionFs).MaxConnections = 1 })
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	access := webTestAccess(t, svc, token, "Work")
	newTransport := func() *executionTestTransport {
		return &executionTestTransport{stream: &executionTestStream{recordingTerminalTestStream: newRecordingTerminalTestStream(t)}, id: bconn.MustNewId()}
	}
	first, err := svc.web.connect(access.scope, token, newTransport())
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close(); <-first.done })
	require.Equal(t, http.StatusOK, webTestPassword(handler, "alice", "correct", "Work").Code, "credential verification is not an execution lease")
	second, err := svc.web.connect(access.scope, token, newTransport())
	require.Nil(t, second)
	require.ErrorIs(t, err, session.ErrMaxConnectionsPerSessionReached)
	require.NoError(t, first.Close())
	third, err := svc.web.connect(access.scope, token, newTransport())
	require.NoError(t, err)
	t.Cleanup(func() { _ = third.Close(); <-third.done })
}

func TestWebLogoutAndConnectionAdmissionAreRaceSafe(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	access := webTestAccess(t, svc, token, "Work")
	var group sync.WaitGroup
	for range 12 {
		transport := &executionTestTransport{stream: &executionTestStream{recordingTerminalTestStream: newRecordingTerminalTestStream(t)}, id: bconn.MustNewId()}
		group.Add(1)
		go func() {
			defer group.Done()
			conn, err := svc.web.connect(access.scope, token, transport)
			if err == nil {
				_ = conn.Close()
				<-conn.done
			}
		}()
	}
	require.NoError(t, svc.web.logout(access.scope, token))
	group.Wait()
	access.mutex.Lock()
	require.Empty(t, access.children)
	require.True(t, access.closed)
	access.mutex.Unlock()
}

func TestWebAccessLogoutAndExpiryAreSeparateFromSessionDisposal(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	one := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	two := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	access := webTestAccess(t, svc, one, "Work")
	other := webTestAccess(t, svc, two, "Work")
	require.Equal(t, access.auth.FindSession().Id(), other.auth.FindSession().Id())
	newTransport := func() *executionTestTransport { transport, _ := newExecutionTestLogin(t, svc, "run"); return transport }
	conn, err := svc.web.connect(access.scope, one, newTransport())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(); <-conn.done })
	sibling, err := svc.web.connect(other.scope, two, newTransport())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sibling.Close(); <-sibling.done })
	access.mutex.Lock()
	access.expires = time.Now().Add(-time.Second)
	access.mutex.Unlock()
	w := webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, one)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.False(t, conn.IsClosed(), "expiry cannot kill existing execution")
	logout := webTestRequest(handler, "POST", "app.example.org", webAPI+"logout", `{"slug":"Work"}`, one)
	require.Equal(t, http.StatusNoContent, logout.Code)
	require.True(t, conn.IsClosed())
	require.False(t, sibling.IsClosed())
	info, err := access.auth.FindSession().Info(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, session.StateDisposed, info.State())
	require.Equal(t, http.StatusOK, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, two).Code)
	require.NoError(t, svc.sessionConnections.revoke(access.auth.Flow(), access.auth.FindSession().Id()))
	require.True(t, sibling.IsClosed())
	require.Equal(t, http.StatusUnauthorized, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, two).Code)
}

func TestWebBudgetsAreBoundedAndIndependentOfForwardedHeaders(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	for range webMaximumLoginsPerMinute {
		require.Equal(t, http.StatusUnauthorized, webTestPassword(handler, "alice", "wrong", "Work").Code)
	}
	w := webTestPassword(handler, "alice", "correct", "Work")
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.Equal(t, "60", w.Header().Get("Retry-After"))
	peer := netip.MustParseAddr("192.0.2.1")
	var releases []func()
	for range webMaximumWorkersPerPeer {
		release, ok := svc.web.admit(peer, false)
		require.True(t, ok)
		releases = append(releases, release)
	}
	_, ok := svc.web.admit(peer, false)
	require.False(t, ok)
	for _, release := range releases {
		release()
	}
	release, ok := svc.web.admit(peer, false)
	require.True(t, ok)
	release()
	require.LessOrEqual(t, len(svc.web.peers), webMaximumPeers)
}

func TestWebShutdownCancelsAndDrainsAuthentication(t *testing.T) {
	svc, handler, _ := webTestFixture(t)
	entered := make(chan struct{})
	var once sync.Once
	svc.environments.(*executionTestRepository).onAccept = func(ctx environment.Context) (bool, error) {
		once.Do(func() { close(entered) })
		<-ctx.Context().Done()
		return false, ctx.Context().Err()
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- webTestPassword(handler, "alice", "correct", "Work") }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("authentication did not start")
	}
	require.NoError(t, svc.environments.(*executionTestRepository).shutdown())
	select {
	case w := <-done:
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("authentication was not drained")
	}
	require.Empty(t, svc.web.access)
}

func TestRealHttpsPasswordAndSshLoginShareOneStoredSession(t *testing.T) {
	var root *x509.Certificate
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:correct")
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Http = &configuration.Http{}
		require.NoError(t, conf.Http.SetDefaults())
		conf.Http.Enabled = true
		conf.Http.Domains = configuration.HttpDomains{"app.example.org"}
		conf.Http.Addresses = bnet.NetAddresses{bnet.MustNewAddress("127.0.0.1:0")}
		root = httpListenerTestCertificate(t, conf, nil)
	})
	ssh := server.mustDial(t)
	defer ssh.Close()
	sshSession, err := ssh.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.Run("first"))
	svc := server.service
	require.NoError(t, svc.https.Prepare(t.Context()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- svc.https.Serve(listener) }()
	t.Cleanup(func() {
		require.NoError(t, svc.https.Close())
		select {
		case err := <-done:
			require.ErrorIs(t, err, http.ErrServerClosed)
		case <-time.After(2 * time.Second):
			t.Error("HTTPS did not stop")
		}
	})
	pool := x509.NewCertPool()
	pool.AddCert(root)
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	body, _ := json.Marshal(map[string]string{"slug": "Work", "user": server.username, "password": "correct"})
	request, err := http.NewRequest("POST", "https://app.example.org"+webAPI+"login/password", strings.NewReader(string(body)))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://app.example.org")
	response, err := client.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode, string(raw))
	require.Equal(t, 2, response.ProtoMajor)
	var result struct {
		AccessToken string `json:"accessToken"`
	}
	require.NoError(t, json.Unmarshal(raw, &result))
	access := webTestAccess(t, svc, result.AccessToken, "Work")
	var sessions []session.Session
	require.NoError(t, svc.sessions.FindAll(t.Context(), func(_ context.Context, sess session.Session) (bool, error) {
		sessions = append(sessions, sess)
		return true, nil
	}, nil))
	require.Len(t, sessions, 1)
	require.Equal(t, sessions[0].Id(), access.auth.FindSession().Id())
	association, err := session.AssociationOf(t.Context(), sessions[0])
	require.NoError(t, err)
	require.Equal(t, server.username, association.Subject)

	// Stop web admissions while HTTP itself is still running and a real peer is
	// withholding the rest of its JSON body. Repository shutdown must not wait on
	// that peer or on the ordinary server read timeout.
	slow, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "app.example.org", MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	defer slow.Close()
	_, err = io.WriteString(slow, "POST "+webAPI+"login/password HTTP/1.1\r\nHost: app.example.org\r\nOrigin: https://app.example.org\r\nContent-Type: application/json\r\nContent-Length: 10000\r\n\r\n{\"slug\":")
	require.NoError(t, err)
	require.Eventually(t, func() bool { svc.web.mutex.Lock(); defer svc.web.mutex.Unlock(); return svc.web.active > 0 }, time.Second, time.Millisecond)
	stopped := make(chan error, 1)
	go func() { stopped <- svc.web.Close() }()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		_ = slow.Close()
		t.Fatal("web shutdown did not interrupt slow request body")
	}
}
