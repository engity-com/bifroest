package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func monitoringTestConfiguration(t *testing.T) configuration.Configuration {
	t.Helper()
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(`monitoring:
  enabled: true
  addresses: ['127.0.0.1:0']
authorizations:
  login: {type: none}
environments:
  sandbox: {type: dummy}
auditlogs:
  operations:
    failurePolicy: bestEffort
    recording: {enabled: true}
flows:
  - name: shell
    authorization: login
    environment: sandbox
    auditlog: operations
`), ""))
	return conf
}

func monitoringTestScrape(t *testing.T, monitor *serviceMonitoring) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	monitor.endpoint.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	return response.Body.String()
}

func TestMonitoringLabelsAndFailureState(t *testing.T) {
	conf := monitoringTestConfiguration(t)
	monitor, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	svc := &service{Service: &Service{Configuration: conf}, monitoring: monitor, executions: newConnectionLifecycle(), auditlogStates: map[configuration.AuditlogName]*auditlogRuntimeState{"operations": {policy: configuration.AuditlogFailurePolicyBestEffort}}}
	monitor.service.Store(svc)
	observation := authorization.FlowAuthorizationObservation{Flow: "shell", Method: authorization.FlowAuthorizationMethodPublicKey, Phase: authorization.FlowAuthorizationPhaseCandidate, Outcome: authorization.FlowAuthorizationOutcomeAccepted, Duration: 25 * time.Millisecond, ConnectionId: "private-connection-id", SessionId: "private-session-id"}
	monitor.observeFlow(observation)
	text := monitoringTestScrape(t, monitor)
	require.Contains(t, text, `authorization="login"`)
	require.Contains(t, text, `environment="sandbox"`)
	require.Contains(t, text, `auditlog="operations"`)
	require.Contains(t, text, `flow="shell"`)
	require.Contains(t, text, `phase="candidate"`)
	require.NotContains(t, text, "bifroest_authentication_completions_total{")
	require.NotContains(t, text, "private-connection-id")
	require.NotContains(t, text, "private-session-id")
	require.Contains(t, text, `bifroest_auditlog_enabled{auditlog="operations"} 1`)
	require.Contains(t, text, `bifroest_recording_spool_accounting_valid{auditlog="operations"} 0`)
	monitor.observeCompletion("shell", audit.AuthenticationMethodPublicKey, audit.EventOutcomeSuccess, nil)
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.completions))
	require.NoError(t, svc.handleRecordingFailure("operations", "Recording spool", errors.System.Newf("private payload and username")))
	text = monitoringTestScrape(t, monitor)
	require.Contains(t, text, `bifroest_auditlog_disabled{auditlog="operations"} 1`)
	require.Contains(t, text, `bifroest_auditlog_enabled{auditlog="operations"} 0`)
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.auditErrors))
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.recordingErrors))
	require.NotContains(t, text, "private payload")
	require.NotContains(t, text, "username")
	monitor.endpoint.SetReady(true)
	require.NoError(t, svc.handleRecordingFailure("operations", "capture", errors.System.Newf("failure")))
	require.True(t, monitor.endpoint.Ready(), "backend failures must not become a liveness/restart signal")
	// Unconfigured names, including restored sessions from removed flows, are never labels.
	observation.Flow = "unbounded-user-supplied-name"
	monitor.observeFlow(observation)
	require.NotContains(t, monitoringTestScrape(t, monitor), "unbounded-user-supplied-name")
	other, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	require.NotContains(t, monitoringTestScrape(t, other), "bifroest_authentication_completions_total{")
}

func TestMonitoringCountsDistinctLiveSessionsAndTasks(t *testing.T) {
	conf := monitoringTestConfiguration(t)
	monitor, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	svc := &service{Service: &Service{Configuration: conf}, executions: newConnectionLifecycle()}
	monitor.service.Store(svc)
	sess := &houseKeeperTestSession{flow: "shell", id: session.MustNewId()}
	first := newTrackedSessionConnection(t, svc)
	second := newTrackedSessionConnection(t, svc)
	svc.sessionConnections.track(first, sess)
	svc.sessionConnections.track(second, sess)
	release, ok := svc.executions.register()
	require.True(t, ok)
	finishTask := monitor.taskStarted("shell")
	text := monitoringTestScrape(t, monitor)
	require.Contains(t, text, "bifroest_connections_active 2")
	require.Contains(t, text, `bifroest_sessions_active{auditlog="operations",authorization="login",environment="sandbox",flow="shell"} 1`)
	require.Contains(t, text, `bifroest_session_connections_active{auditlog="operations",authorization="login",environment="sandbox",flow="shell"} 2`)
	require.Contains(t, text, `bifroest_tasks_active{auditlog="operations",authorization="login",environment="sandbox",flow="shell"} 1`)
	require.NoError(t, first.Close())
	require.NoError(t, second.Close())
	release()
	finishTask()
	text = monitoringTestScrape(t, monitor)
	require.Contains(t, text, "bifroest_connections_active 0")
	require.Contains(t, text, `bifroest_tasks_active{auditlog="operations",authorization="login",environment="sandbox",flow="shell"} 0`)
	require.Contains(t, text, `bifroest_sessions_active{auditlog="operations",authorization="login",environment="sandbox",flow="shell"} 0`)
}

func TestMonitoringConcurrentStateChangesAndScrapes(t *testing.T) {
	monitor, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	var wait sync.WaitGroup
	for index := 0; index < 3; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 20 {
				monitor.observeCompletion("shell", audit.AuthenticationMethodPassword, audit.EventOutcomeDenied, nil)
				monitor.cleanup("shell", "session_dispose", errors.Network.Newf("redacted"))
				monitor.endpoint.SetReady(true)
				request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
				response := httptest.NewRecorder()
				monitor.endpoint.ServeHTTP(response, request)
				if response.Code != http.StatusOK {
					t.Errorf("scrape failed: %d", response.Code)
				}
			}
		}()
	}
	wait.Wait()
	require.Equal(t, 60.0, testutil.ToFloat64(monitor.completions))
	require.Equal(t, 60.0, testutil.ToFloat64(monitor.cleanupRuns))
}

func TestMonitoringReadinessFollowsJointListenerLifecycle(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	httpListenerTestCertificate(t, &conf, nil)
	conf.Monitoring = &configuration.Monitoring{}
	require.NoError(t, conf.Monitoring.SetDefaults())
	conf.Monitoring.Enabled = true
	monitor, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	svc := prepareHTTPListenerTestService(t, conf)
	svc.monitoring = monitor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bound := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	done := make(chan error, 1)
	go func() {
		calls := 0
		_, err := svc.runListeners(ctx, func(address bnet.Address) (net.Listener, error) {
			calls++
			if calls == 1 {
				close(bound)
				<-release
			}
			return address.Listen()
		})
		done <- err
	}()
	select {
	case <-bound:
	case <-time.After(3 * time.Second):
		t.Fatal("listener startup not reached")
	}
	require.False(t, monitor.endpoint.Ready())
	response := httptest.NewRecorder()
	monitor.endpoint.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/status", nil))
	require.Equal(t, http.StatusOK, response.Code)
	unblock()
	require.Eventually(t, monitor.endpoint.Ready, 3*time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("listeners did not stop")
	}
	require.False(t, monitor.endpoint.Ready())
}

func TestMonitoringCapturesSuppressedCleanupFailure(t *testing.T) {
	monitor, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, &houseKeeperTestAuthorizer{restoreErr: fmt.Errorf("permanent failure")})
	hk.service.monitoring = monitor
	sess := &houseKeeperTestSession{flow: "current", id: session.MustNewId(), state: session.StateDisposed, validUntil: time.Now().Add(time.Hour)}
	hk.service.flowAuditRecorders[sess.flow] = &recordingAuditRecorder{}
	_, err = hk.inspectSession(t.Context(), sess)
	require.NoError(t, err)
	text := monitoringTestScrape(t, monitor)
	require.Contains(t, text, `operation="session_dispose",result="failure"`)
	require.NotContains(t, text, "permanent failure")
}

func TestMonitoringDuringSlowServicePreparationWithoutBrowserAccess(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	conf.Http = nil
	conf.Monitoring = &configuration.Monitoring{}
	require.NoError(t, conf.Monitoring.SetDefaults())
	conf.Monitoring.Enabled = true
	conf.Monitoring.Addresses = bnet.NetAddresses{bnet.MustNewAddress("127.0.0.1:0")}
	started := make(chan struct{})
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	t.Cleanup(issuer.Close)
	auth := &configuration.AuthorizationOidcDeviceAuth{}
	require.NoError(t, auth.SetDefaults())
	auth.Issuer = template.MustNewUrl(issuer.URL)
	auth.ClientId = template.MustNewString("test")
	auth.ClientSecret = template.MustNewString("test-only")
	conf.Flows[0].Authorization.V = auth
	monitor, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	require.NoError(t, monitor.endpoint.Start(nil))
	t.Cleanup(func() { require.NoError(t, monitor.endpoint.Close()) })
	ctx, cancel := context.WithCancel(coidc.ClientContext(t.Context(), issuer.Client()))
	defer cancel()
	done := make(chan error, 1)
	go func() {
		svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepareContextWithMonitoring(ctx, monitor)
		if svc != nil {
			_ = svc.Close()
		}
		done <- err
	}()
	await := awaitHTTPListenerTestRun(t, done)
	t.Cleanup(func() { cancel(); _ = await() })
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("slow initialization not reached")
	}
	for path, expected := range map[string]int{"/status": http.StatusOK, "/ready": http.StatusServiceUnavailable, "/metrics": http.StatusOK} {
		response := httptest.NewRecorder()
		monitor.endpoint.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, expected, response.Code, path)
	}
	cancel()
	require.ErrorIs(t, await(), context.Canceled)
}

func TestMonitoringTLSRejectsSSHKeyReuseWithoutBrowserAccess(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	httpListenerTestCertificate(t, &conf, key)
	conf.Monitoring = &configuration.Monitoring{}
	require.NoError(t, conf.Monitoring.SetDefaults())
	conf.Monitoring.Enabled = true
	conf.Monitoring.Addresses = bnet.NetAddresses{bnet.MustNewAddress("127.0.0.1:0")}
	conf.Monitoring.Tls.Enabled = true
	for _, certificate := range conf.Http.Tls.Certificates {
		conf.Monitoring.Tls.Certificates = append(conf.Monitoring.Tls.Certificates, configuration.MonitoringCertificate(certificate))
	}
	conf.Http = nil
	paths, err := conf.Ssh.Keys.HostKeys.Render(noopContext{})
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, bfcrypto.WriteBootstrapFile(paths[0], pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), false))
	monitor, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, monitor.endpoint.Close()) })
	_, err = (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepareContextWithMonitoring(t.Context(), monitor)
	require.ErrorContains(t, err, "monitoring TLS key separation")
	require.ErrorContains(t, err, "must be distinct")
}

func TestMonitoringCleanupProblemSnapshotBoundsNamesAndResets(t *testing.T) {
	monitor, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	hk := &houseKeeper{service: &service{knownFlows: map[configuration.FlowName]struct{}{"shell": {}}}, monitoringProblems: make(map[configuration.FlowName]int)}
	hk.monitoringProblem("shell")
	hk.monitoringProblem("deleted-flow-secret")
	monitor.cleanupSnapshot(hk.monitoringProblems)
	text := monitoringTestScrape(t, monitor)
	require.Contains(t, text, `bifroest_cleanup_problems{auditlog="operations",authorization="login",environment="sandbox",flow="shell"} 1`)
	require.NotContains(t, text, "deleted-flow-secret")
	monitor.cleanupSnapshot(nil)
	text = monitoringTestScrape(t, monitor)
	require.Contains(t, text, `bifroest_cleanup_problems{auditlog="operations",authorization="login",environment="sandbox",flow="shell"} 0`)
}
