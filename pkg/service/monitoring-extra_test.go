package service

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func enableMonitoringTest(conf *configuration.Configuration) {
	conf.Monitoring = &configuration.Monitoring{}
	_ = conf.Monitoring.SetDefaults()
	conf.Monitoring.Enabled = true
}

func prepareMonitoringTestService(t *testing.T, definition *Service) (*service, error) {
	t.Helper()
	m, err := newServiceMonitoring(definition.Configuration)
	if err != nil {
		return nil, err
	}
	if m != nil {
		t.Cleanup(func() { require.NoError(t, m.endpoint.Close()) })
	}
	return definition.prepareContextWithMonitoring(context.Background(), m)
}

func TestMonitoringAgeSnapshotMathAndEmptySets(t *testing.T) {
	var ages monitoringAges
	now := time.Now()
	ages.add(time.Time{}, now)
	require.Zero(t, ages.count)
	ages.add(now.Add(-10*time.Second), now)
	ages.add(now.Add(-50*time.Second), now)
	ages.add(now.Add(time.Second), now)
	require.Equal(t, 3, ages.count)
	require.Equal(t, 60.0, ages.sum)
	require.Equal(t, 50.0, ages.oldest)
	require.Zero(t, ages.youngest)
	m, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	m.service.Store(&service{})
	text := monitoringTestScrape(t, m)
	require.Contains(t, text, `bifroest_connections_age_observations{transport="ssh"} 0`)
	require.NotContains(t, text, `bifroest_connections_oldest_age_seconds{`)
	require.NotContains(t, text, `bifroest_sessions_average_age_seconds{`)
}

func TestMonitoringMetricNamesConformToPrometheus(t *testing.T) {
	m, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	m.service.Store(&service{})
	problems, err := testutil.GatherAndLint(m.registry)
	require.NoError(t, err)
	require.Empty(t, problems, "gauge names must not use reserved histogram/summary suffixes")
}

func TestMonitoringSessionAgeSurvivesReconnectionWithoutScrapeIO(t *testing.T) {
	svc, _, _ := executionTestFixture(t, func(environment.TerminalTask) (int, error) { return 0, nil }, enableMonitoringTest)
	transport, auth := newExecutionTestLogin(t, svc, "run")
	info, err := auth.FindSession().Info(t.Context())
	require.NoError(t, err)
	created, err := info.Created(t.Context())
	require.NoError(t, err)
	first := registerExecutionTestConnection(t, svc, transport, auth)
	key := sessionConnectionKey{auth.Flow(), auth.FindSession().Id()}
	require.Equal(t, created.At(), svc.sessionConnections.sessions[key].created)
	before := svc.sessionConnections.monitoringAges(time.Now())[auth.Flow()]
	require.Equal(t, 1, before[0].count)
	require.NoError(t, first.Close())
	<-first.done
	transport, _ = newExecutionTestLogin(t, svc, "run")
	second := registerExecutionTestConnection(t, svc, transport, auth)
	require.Equal(t, created.At(), svc.sessionConnections.sessions[key].created)
	require.NoError(t, second.Close())
	<-second.done
	require.Empty(t, svc.sessionConnections.created)
}

func TestMonitoringSSHCountsAttemptsNotPublicKeyEligibilityOrNone(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, enableMonitoringTest)
	m := server.service.monitoring
	blocking := &blockingIncomingCertificateSigner{Signer: server.signer, signStarted: make(chan struct{}), releaseSign: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(blocking.releaseSign) }) }
	defer release()
	done := make(chan error, 1)
	go func() {
		client, err := dialAuthorizedKeysTestServer(server, blocking)
		if client != nil {
			_ = client.Close()
		}
		done <- err
	}()
	select {
	case <-blocking.signStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("no public-key probe")
	}
	require.NotContains(t, monitoringTestScrape(t, m), "bifroest_authentication_attempts_total{")
	require.Contains(t, monitoringTestScrape(t, m), "bifroest_connections_unauthenticated 1")
	release()
	require.NoError(t, <-done)
	require.Eventually(t, func() bool { return testutil.CollectAndCount(m.access.attempts) == 1 }, time.Second, time.Millisecond)
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.attempts))
	_, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{User: server.username, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second}) //nolint:gosec // Local test server.
	require.Error(t, err)
	closedWithoutAttempt := func() float64 {
		var result float64
		for _, reason := range []string{"closed", "peer_closed", "protocol_error", "timeout"} {
			result += testutil.ToFloat64(m.access.withoutAttempt.WithLabelValues(reason))
		}
		return result
	}
	require.Eventually(t, func() bool { return closedWithoutAttempt() >= 1 }, time.Second, time.Millisecond)
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.attempts))
	raw, err := net.Dial("tcp", server.address)
	require.NoError(t, err)
	_, err = raw.Write([]byte("not SSH\r\n"))
	require.NoError(t, err)
	_ = raw.Close()
	require.Eventually(t, func() bool { return closedWithoutAttempt() >= 2 }, time.Second, time.Millisecond)
	text := monitoringTestScrape(t, m)
	require.NotContains(t, text, server.username)
	require.Contains(t, text, `method="public-key",result="success",transport="ssh"} 1`)
}

func TestMonitoringHTTPBoundaryLabelsAndBodyLimits(t *testing.T) {
	svc, handler, _ := webTestFixture(t, enableMonitoringTest)
	m := svc.monitoring
	handler = m.observeHTTPRequest(handler)
	require.Equal(t, 401, webTestPassword(handler, "alice", "wrong", "Work").Code)
	require.Equal(t, 200, webTestPassword(handler, "alice", "correct", "Work").Code)
	// Unauthorized access is not another failed login.
	require.Equal(t, 401, webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, "invalid-secret").Code)
	require.Equal(t, 2.0, testutil.ToFloat64(m.access.attempts.WithLabelValues(append(m.flowLabels(""), "http", "password", "denied")...))+testutil.ToFloat64(m.access.attempts.WithLabelValues(append(m.flowLabels(svc.Configuration.Flows[0].Name), "http", "password", "success")...)))
	for n := range 20 {
		require.Equal(t, 404, webTestRequest(handler, "SECRET-METHOD", "app.example.org", fmt.Sprintf("/private-%d?secret=x", n), "", "").Code)
	}
	oversized := `{"slug":"` + strings.Repeat("x", webLoginBodyLimit) + `"}`
	require.Equal(t, 400, webTestRequest(handler, "POST", "app.example.org", webAPI+"discovery", oversized, "").Code)
	require.Equal(t, 1.0, testutil.ToFloat64(m.http.rejections.WithLabelValues("discovery", "body_limit")))
	text := monitoringTestScrape(t, m)
	for _, secret := range []string{"private-", "secret=x", "SECRET-METHOD", "alice", "invalid-secret"} {
		require.NotContains(t, text, secret)
	}
	require.Contains(t, text, `method="unknown",route="unknown",status="404"} 20`)
}

func TestMonitoringHTTP2SocketsAndHijackedWebSockets(t *testing.T) {
	f := newWebSocketFixture(t, func(environment.TerminalTask) (int, error) { return 0, nil }, enableMonitoringTest)
	m := f.svc.monitoring
	_ = f.login(t)
	_ = f.login(t)
	response, err := f.client.Get("https://app.example.org/unknown")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	require.Equal(t, 2, response.ProtoMajor, "monitoring must preserve HTTP/2 negotiation")
	require.Equal(t, 1.0, testutil.ToFloat64(m.http.opened), "HTTP/2 requests reuse their physical socket")
	require.Equal(t, 1.0, testutil.ToFloat64(m.http.handshakes.WithLabelValues("success", "")))
	ws := f.dial(t)
	require.Eventually(t, func() bool { return testutil.ToFloat64(m.http.channelActive.WithLabelValues("terminal")) == 1 }, time.Second, time.Millisecond)
	require.Equal(t, 2.0, testutil.ToFloat64(m.http.opened))
	require.NoError(t, ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"invalid"}`)))
	_, _, _ = ws.ReadMessage()
	_ = ws.Close()
	require.Eventually(t, func() bool { return testutil.ToFloat64(m.http.channelActive.WithLabelValues("terminal")) == 0 }, time.Second, time.Millisecond)
	text := monitoringTestScrape(t, m)
	require.Contains(t, text, `route="terminal",status="101"} 1`)
	require.Contains(t, text, `bifroest_http_channels_closed_total{kind="terminal",reason="protocol_error"} 1`)
	require.NotContains(t, text, `bifroest_http_request_duration_seconds_count{flow="",method="GET",route="terminal"`)
	require.Contains(t, text, "bifroest_http_tls_certificate_expiration_timestamp_seconds{")
	require.Eventually(t, func() bool { m.http.mutex.Lock(); defer m.http.mutex.Unlock(); return len(m.http.connections) == 1 }, time.Second, time.Millisecond)
}

func TestMonitoringTunnelPreservesFullDuplexAndHTTP2(t *testing.T) {
	for _, mode := range []string{"https1", "https2", "wss"} {
		t.Run(mode, func(t *testing.T) {
			f := newSshTunnelFixture(t, false, false, true, false, enableMonitoringTest)
			conn := f.transportConn(t, mode)
			secure, channels, requests, err := gossh.NewClientConn(conn, "tunnel", &gossh.ClientConfig{User: "test", Auth: []gossh.AuthMethod{gossh.Password("test")}, HostKeyCallback: gossh.InsecureIgnoreHostKey()}) //nolint:gosec // Local test tunnel.
			if err != nil {
				_ = conn.Close()
			}
			require.NoError(t, err)
			client := gossh.NewClient(secure, channels, requests)
			require.Equal(t, 1.0, testutil.ToFloat64(f.svc.monitoring.http.channelActive.WithLabelValues("ssh_tunnel")))
			ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			require.NoError(t, err, "the monitored tunnel must remain usable until client shutdown")
			require.True(t, ok)
			require.NoError(t, client.Close())
			_ = conn.Close()
			require.Eventually(t, func() bool {
				return testutil.ToFloat64(f.svc.monitoring.http.channelActive.WithLabelValues("ssh_tunnel")) == 0
			}, time.Second, time.Millisecond)
		})
	}
}

func TestMonitoringRequestWriterInterfacesAndAccounting(t *testing.T) {
	m, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	handler := m.observeHTTPRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hijack := w.(http.Hijacker)
		require.False(t, hijack)
		_, flush := w.(http.Flusher)
		require.True(t, flush)
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "abc")
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	require.Equal(t, 3.0, testutil.ToFloat64(m.http.output.WithLabelValues("document", "GET", "201", "")))
}

func TestMonitoringHTTPInformationalResponsesKeepFinalStatus(t *testing.T) {
	m, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	server := httptest.NewServer(m.observeHTTPRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(103)
		w.WriteHeader(201)
		_, _ = io.WriteString(w, "abc")
	})))
	defer server.Close()
	response, err := server.Client().Get(server.URL)
	require.NoError(t, err)
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, 201, response.StatusCode)
	require.Equal(t, "abc", string(data))
	require.Equal(t, 3.0, testutil.ToFloat64(m.http.output.WithLabelValues("document", "GET", "201", "")))
}

func TestMonitoringSuppressionAndJournalObservationStayReadOnly(t *testing.T) {
	svc, _, _ := executionTestFixture(t, func(environment.TerminalTask) (int, error) { return 0, nil }, enableMonitoringTest)
	m := svc.monitoring
	startMonitoringJournalObserverTest(t, m, svc)
	require.Eventually(t, func() bool { return testutil.CollectAndCount(m.journal.available) > 0 }, time.Second, time.Millisecond)
	require.Greater(t, testutil.CollectAndCount(m.journal.available), 0)
	text := monitoringTestScrape(t, m)
	require.Contains(t, text, "bifroest_auditlog_space_observation_valid{")
	// A scrape uses the cached sample, not the journal observer.
	before := testutil.ToFloat64(m.journal.available)
	require.Greater(t, before, 0.0)
	_ = monitoringTestScrape(t, m)
	require.Equal(t, before, testutil.ToFloat64(m.journal.available))
	m.suppress(svc.Configuration.Flows[0].Auditlog, "rate_limit")
	m.suppress(svc.Configuration.Flows[0].Auditlog, "journal_reserve")
	require.Equal(t, 2, testutil.CollectAndCount(m.access.suppressed))
	m.accessDecision(svc.Configuration.Flows[0].Name, audit.Event{Name: audit.EventNameSessionPtyDecided, Outcome: audit.EventOutcomeDenied, Reason: audit.EventReasonAuthorizedKeyPolicy})
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.denials))
}

func TestMonitoringSuppressionCountsEachDetailOnce(t *testing.T) {
	for _, reserve := range []bool{false, true} {
		t.Run(fmt.Sprint(reserve), func(t *testing.T) {
			conf := monitoringTestConfiguration(t)
			conf.Ssh.UnauthenticatedAudit.PerSourceLimit = 1
			conf.Ssh.UnauthenticatedAudit.GlobalLimit = 1
			m, err := newServiceMonitoring(conf)
			require.NoError(t, err)
			limiter := newUnauthenticatedAuditLimiter(conf.Ssh.UnauthenticatedAudit)
			limiter.onSuppressed = m.suppress
			now := time.Now()
			limiter.now = func() time.Time { return now }
			recorder := newLimiterTestRecorder(!reserve)
			for range 10 {
				require.NoError(t, limiter.Record(t.Context(), "operations", true, recorder, audit.Event{Outcome: audit.EventOutcomeDenied}))
			}
			if reserve {
				require.Equal(t, 10.0, testutil.ToFloat64(m.access.suppressed.WithLabelValues("operations", "journal_reserve")))
			} else {
				require.Equal(t, 9.0, testutil.ToFloat64(m.access.suppressed.WithLabelValues("operations", "rate_limit")))
			}
			require.NoError(t, limiter.Flush(t.Context()))
		})
	}
}

func TestMonitoringTLSAbortsAndBoundaryFailuresAreNotLogins(t *testing.T) {
	f := newSshTunnelFixture(t, false, true, false, false, func(conf *configuration.Configuration) {
		enableMonitoringTest(conf)
		conf.Http.ReadHeaderTimeout = common.DurationOf(150 * time.Millisecond)
	})
	m := f.svc.monitoring
	raw, err := net.Dial("tcp", f.address)
	require.NoError(t, err)
	defer raw.Close()
	require.Eventually(t, func() bool { return testutil.ToFloat64(m.http.handshakes.WithLabelValues("aborted", "timeout")) == 1 }, 2*time.Second, time.Millisecond)
	request, err := http.NewRequest("POST", "https://app.example.org"+webAPI+"discovery", strings.NewReader(`{"slug":"work"}`))
	require.NoError(t, err)
	request.Header.Set("Origin", "https://hostile.invalid")
	response, err := (&http.Client{Transport: f.transport, Timeout: time.Second}).Do(request)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	require.Equal(t, 403, response.StatusCode)
	require.Equal(t, 1.0, testutil.ToFloat64(m.http.rejections.WithLabelValues("discovery", "origin")))
	require.Zero(t, testutil.CollectAndCount(m.access.attempts))
	require.NotContains(t, monitoringTestScrape(t, m), "hostile.invalid")
}

func TestMonitoringBrowserAttemptsFinishOnceAcrossPollAndCancel(t *testing.T) {
	svc, handler, _ := webTestFixture(t, enableMonitoringTest)
	m := svc.monitoring
	handler = m.observeHTTPRequest(handler)
	token := startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	step := waitWebLoginStep(t, handler, token, "Work")
	require.Equal(t, 202, answerWebStep(handler, token, "Work", step, "correct").Code)
	require.Equal(t, 200, finishWebAttempt(t, handler, token, "Work").Code)
	require.Equal(t, 401, webAttemptRequest(handler, "poll", token, map[string]string{"slug": "Work"}).Code)
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.attempts))
	token = startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	_ = waitWebLoginStep(t, handler, token, "Work")
	require.Equal(t, 204, webAttemptRequest(handler, "cancel", token, map[string]string{"slug": "Work"}).Code)
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.attempts.WithLabelValues(append(m.flowLabels(""), "http", "keyboard-interactive", "abandoned")...)))
	token = startWebAttempt(t, handler, "interactive", "alice", "Work", nil)
	step = waitWebLoginStep(t, handler, token, "Work")
	require.Equal(t, 202, answerWebStep(handler, token, "Work", step, "wrong").Code)
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(m.access.attempts.WithLabelValues(append(m.flowLabels(""), "http", "keyboard-interactive", "denied")...)) == 1
	}, time.Second, time.Millisecond)
	require.Equal(t, 401, finishWebAttempt(t, handler, token, "Work").Code)
	_, err := m.registry.Gather()
	require.NoError(t, err)
}

func TestMonitoringRememberMeDoesNotCountBindingEnrollmentAsLogin(t *testing.T) {
	svc, handler, _ := webTestFixture(t, enableMonitoringTest)
	m := svc.monitoring
	handler = m.observeHTTPRequest(handler)
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	key, public := rememberTestKey(t)
	binding := rememberTestEnroll(t, handler, token, public, key)
	require.Equal(t, 1, testutil.CollectAndCount(m.access.attempts))
	challenge := rememberTestStart(t, handler, "resume", "", binding.selector())
	require.Equal(t, 401, rememberTestRequest(handler, "prove", challenge.AttemptToken, map[string]string{"slug": "Work", "signature": "invalid"}).Code)
	challenge = rememberTestStart(t, handler, "resume", "", binding.selector())
	require.Equal(t, 200, rememberTestProve(t, handler, challenge, key).Code)
	flow := svc.Configuration.Flows[0].Name
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.attempts.WithLabelValues(append(m.flowLabels(flow), "http", "browser-remember-me", "denied")...)))
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.attempts.WithLabelValues(append(m.flowLabels(flow), "http", "browser-remember-me", "success")...)))
}

type monitoringSpaceTestRecorder struct {
	audit.Recorder
	calls atomic.Int32
	fail  atomic.Bool
}

func (r *monitoringSpaceTestRecorder) JournalAvailableBytes() (uint64, error) {
	r.calls.Add(1)
	if r.fail.Load() {
		return 0, fmt.Errorf("private path and diagnostic")
	}
	return 123456789, nil
}

func TestMonitoringJournalFailureCannotChangePolicyOrBlockScrapes(t *testing.T) {
	conf := monitoringTestConfiguration(t)
	m, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	recorder := &monitoringSpaceTestRecorder{}
	svc := &service{monitoring: m, auditRecorders: map[configuration.AuditlogName]audit.Recorder{"operations": &failurePolicyAuditRecorder{delegate: recorder}}}
	m.service.Store(svc)
	ticks, _ := startMonitoringJournalObserverTest(t, m, svc)
	require.Eventually(t, func() bool {
		return testutil.CollectAndCount(m.journal.valid) == 1 && testutil.ToFloat64(m.journal.valid) == 1
	}, time.Second, time.Millisecond)
	require.Equal(t, 123456789.0, testutil.ToFloat64(m.journal.available))
	recorder.fail.Store(true)
	ticks <- time.Now()
	require.Eventually(t, func() bool { return recorder.calls.Load() == 2 && testutil.ToFloat64(m.journal.valid) == 0 }, time.Second, time.Millisecond)
	require.Zero(t, testutil.ToFloat64(m.journal.valid))
	require.Equal(t, 123456789.0, testutil.ToFloat64(m.journal.available), "retain the prior value only with invalid/stale observation metadata")
	require.Empty(t, svc.auditlogStates)
	text := monitoringTestScrape(t, m)
	require.Equal(t, int32(2), recorder.calls.Load(), "scraping must not query the filesystem")
	require.NotContains(t, text, "private path")
	require.Zero(t, testutil.CollectAndCount(m.auditErrors))
}

func TestMonitoringConcurrentConnectionSnapshots(t *testing.T) {
	m, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	m.service.Store(&service{})
	var wait sync.WaitGroup
	for range 3 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 20 {
				c := &connection{createdAt: time.Now()}
				m.connectionOpened(c)
				http := m.httpConnectionOpened()
				http("handshake_complete")
				_, err := m.registry.Gather()
				if err != nil {
					t.Error(err)
				}
				c.closed.Store(true)
				m.connectionClosed(c)
				m.connectionFinished(c)
				http("closed")
			}
		}()
	}
	wait.Wait()
	require.Equal(t, 60.0, testutil.ToFloat64(m.http.opened))
	require.Equal(t, 60.0, testutil.ToFloat64(m.access.withoutAttempt))
}

type monitoringErrorAuthorizer struct {
	authorization.CloseableAuthorizer
}

func (monitoringErrorAuthorizer) AuthorizePassword(authorization.PasswordRequest) (authorization.Authorization, error) {
	return nil, berrors.System.Newf("private backend diagnostic")
}

func TestMonitoringAuthenticationTechnicalErrorsAreNotCredentialDenials(t *testing.T) {
	require.Equal(t, "error", monitoringBrowserAuthenticationResult(fmt.Errorf("untyped backend failure")))
	require.Equal(t, "denied", monitoringBrowserAuthenticationResult(errWebKeyProof))
	require.Equal(t, "denied", monitoringBrowserAuthenticationResult(berrors.User.Newf("invalid credentials")))
	require.Equal(t, "abandoned", monitoringBrowserAuthenticationResult(context.Canceled))
	svc, handler, _ := webTestFixture(t, enableMonitoringTest)
	svc.authorizer = monitoringErrorAuthorizer{svc.authorizer}
	handler = svc.monitoring.observeHTTPRequest(handler)
	require.Equal(t, 503, webTestPassword(handler, "alice", "correct", "Work").Code)
	m := svc.monitoring
	require.Equal(t, 1.0, testutil.ToFloat64(m.access.attempts.WithLabelValues(append(m.flowLabels(""), "http", "password", "error")...)))
	require.NotContains(t, monitoringTestScrape(t, m), "private backend diagnostic")
}
