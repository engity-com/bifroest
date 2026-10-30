package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/webui"
)

type uiInteractiveAuthorizer struct{ *webInteractionTestAuthorizer }

func (this *uiInteractiveAuthorizer) ResumeSession(req authorization.SessionResumeRequest) (authorization.Authorization, error) {
	return this.CloseableAuthorizer.(authorization.SessionResumer).ResumeSession(req)
}

func TestBrowserLoginUiWithRememberRecoveryAndStrictCsp(t *testing.T) {
	testBrowserLoginUi(t, true, "profile")
}

func TestBrowserLoginUiPreservesDisabledRequestingName(t *testing.T) {
	testBrowserLoginUi(t, false, "name-free")
}

func TestBrowserTerminalUiFreshExecutionResizeSignalsExitAndDisconnect(t *testing.T) {
	testBrowserLoginUi(t, true, "terminal")
}

func TestBrowserTerminalTabsUiBoundsAndCanceledInitialization(t *testing.T) {
	testBrowserLoginUi(t, true, "terminal-tabs")
}

func TestBrowserTerminalGrantExpiryUiKeepsExistingShell(t *testing.T) {
	testBrowserLoginUi(t, true, "terminal-expiry")
}

func TestBrowserTerminalLostLogoutUiDoesNotClaimSuccessOrReplay(t *testing.T) {
	testBrowserLoginUi(t, true, "terminal-logout-lost")
}

func TestBrowserInteractiveLoginUiPlainTextEchoAndCancel(t *testing.T) {
	testBrowserLoginUi(t, true, "interactive")
}

func TestBrowserOidcDeviceLoginUiVerifiedIdentityAndRemember(t *testing.T) {
	testBrowserLoginUi(t, false, "oidc")
}

func TestBrowserOidcDeviceCancelUiStopsProviderRequest(t *testing.T) {
	testBrowserLoginUi(t, false, "oidc-cancel")
}

func TestBrowserInteractiveLostClaimUiDoesNotReplay(t *testing.T) {
	testBrowserLoginUi(t, true, "interactive-lost")
}

func TestBrowserManagementUiStructuredTablesAndActorIsolation(t *testing.T) {
	testBrowserLoginUi(t, true, "management")
}

func TestBrowserConnectionWorkspaceUiKeepsFlowActorAndManagementContexts(t *testing.T) {
	testBrowserLoginUi(t, true, "workspace", func(conf *configuration.Configuration) {
		other := conf.Flows[0]
		other.Name, other.DiscoverAsSlug = "other", "Other"
		manager := conf.Flows[0]
		manager.Name, manager.DiscoverAsSlug = "manage", "Manage"
		manager.Environment.V = &configuration.EnvironmentManagement{}
		conf.Flows = append(conf.Flows, other, manager)
	})
}

func TestBrowserConnectionWorkspaceUiCancellationAndUnknownDoNotStartSiblingAccess(t *testing.T) {
	testBrowserLoginUi(t, true, "workspace-races", func(conf *configuration.Configuration) {
		other := conf.Flows[0]
		other.Name, other.DiscoverAsSlug = "other", "Other"
		conf.Flows = append(conf.Flows, other)
	})
}

func TestBrowserManagementWorkspaceUiRetiresHiddenPreparationAndPinsActionOwner(t *testing.T) {
	testBrowserLoginUi(t, true, "workspace-actions")
}

func TestBrowserManagementWorkspaceUiCloseDialogCannotRetireUnknownOwner(t *testing.T) {
	testBrowserLoginUi(t, true, "workspace-actions-close")
}

func TestBrowserManagementForcedReadUiWithholdsUnexposedIdentity(t *testing.T) {
	testBrowserLoginUi(t, true, "management-forced")
}

func TestBrowserManagementForcedAuditReadUiPagesWithoutTransfer(t *testing.T) {
	testBrowserLoginUi(t, true, "management-forced-audit")
}

func TestBrowserManagementForcedVersionUiKeepsShortOutputAndEscapesMetadata(t *testing.T) {
	testBrowserLoginUi(t, true, "management-forced-version")
}

func TestBrowserManagementForcedDisconnectUiHasNoInspectionGrant(t *testing.T) {
	testBrowserLoginUi(t, true, "management-forced-disconnect")
}

func TestBrowserManagementForcedDisposeUiLostReplyIsNotReplayed(t *testing.T) {
	testBrowserLoginUi(t, true, "management-forced-dispose")
}

func testBrowserLoginUi(t *testing.T, requestUser bool, mode string, configure ...func(*configuration.Configuration)) {
	t.Helper()
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_UI=1 after building web/ and installing Chromium")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	core, err := os.ReadFile(filepath.Join(root, "var", "webui-client-build", "remember.js"))
	require.NoError(t, err)
	var svc *service
	var lifecycleRecorder *recordingAuditRecorder
	var protocolHandler http.Handler
	var provider *oidcAssociationProvider
	var keyFixture string
	var authorizedKeys bfcrypto.AuthorizedKeys
	forcedActionMode := mode == "management-forced-disconnect" || mode == "management-forced-dispose"
	workspaceActionMode := mode == "workspace-actions" || mode == "workspace-actions-close"
	forcedReadMode := mode == "management-forced" || mode == "management-forced-audit" || mode == "management-forced-version"
	keyMode := mode == "key" || strings.HasPrefix(mode, "key-")
	if keyMode || forcedReadMode || forcedActionMode {
		keyFixture, authorizedKeys = browserKeyUiFixture(t)
	}
	if mode == "oidc" || mode == "oidc-cancel" {
		svc, protocolHandler, provider, _ = webOidcLoginFixture(t, mode == "oidc-cancel")
	} else {
		svc, _, lifecycleRecorder = webTestFixture(t, func(conf *configuration.Configuration) {
			conf.Flows[0].Http.RequestUser = commonBool(requestUser)
			if mode == "management" {
				base := conf.Flows[0]
				base.Environment.V = &configuration.EnvironmentManagement{}
				settings := base.Authorization.V.(*configuration.AuthorizationSimple)
				settings.Entries = append(settings.Entries, configuration.AuthorizationSimpleEntry{Name: "bob", Password: bfcrypto.Password("plain:correct")})
				conf.Flows = nil
				for index := 20; index >= 0; index-- {
					flow := base
					flow.Name = configuration.FlowName(fmt.Sprintf("manager%02d", index))
					flow.DiscoverAsSlug = ""
					conf.Flows = append(conf.Flows, flow)
				}
			}
			if mode == "management-actions" || workspaceActionMode || forcedActionMode {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
				worker := conf.Flows[0]
				worker.Name = "worker"
				worker.DiscoverAsSlug = "Worker"
				worker.Environment.V = &configuration.EnvironmentDummy{}
				worker.Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "bob", Password: bfcrypto.Password("plain:correct")}}}
				conf.Flows = append(conf.Flows, worker)
			}
			if forcedReadMode {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{AllowArtifactTransfer: mode == "management-forced-audit" || mode == "management-forced-version"}
				settings := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
				settings.Entries = append(settings.Entries, configuration.AuthorizationSimpleEntry{Name: "bob", Password: bfcrypto.Password("plain:correct")})
				var keys strings.Builder
				for _, line := range strings.Split(strings.TrimSpace(string(authorizedKeys)), "\n") {
					if !strings.HasPrefix(line, "cert-authority ") {
						switch mode {
						case "management-forced-audit":
							keys.WriteString(`command="audit ls" `)
						case "management-forced-version":
							keys.WriteString(`command="version --long=false" `)
						default:
							keys.WriteString(`command="session ls --user=alice --format=table" `)
						}
					}
					keys.WriteString(line + "\n")
				}
				settings.Entries[0].AuthorizedKeys = bfcrypto.AuthorizedKeys(keys.String())
			}
			if keyMode {
				conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = authorizedKeys
			}
			if mode == "terminal" || mode == "workspace" || mode == "workspace-races" || workspaceActionMode {
				settings := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
				settings.Entries = append(settings.Entries, configuration.AuthorizationSimpleEntry{Name: "bob", Password: bfcrypto.Password("plain:correct")})
			}
			for _, change := range configure {
				change(conf)
			}
		})
		protocolHandler = svc.web
	}
	if mode == "management" || mode == "management-actions" || workspaceActionMode || forcedReadMode || forcedActionMode || mode == "workspace" {
		if mode != "workspace" {
			svc.environments = svc.environments.(*executionTestRepository).CloseableRepository
		}
		application := svc.managementApplication
		svc.managementApplication = nil
		t.Cleanup(func() { svc.managementApplication = application })
	}
	if mode == "management-forced-audit" {
		addForcedAuditSummaries(svc)
	}
	if mode == "management-forced-version" {
		svc.Version = versionMarkupTestVersion{}
	}
	var actionTargets *actionUITargetRepository
	if mode == "management-actions" || workspaceActionMode || forcedActionMode {
		actionTargets = &actionUITargetRepository{CloseableRepository: svc.environments}
		svc.environments = actionTargets
	}
	if workspaceActionMode {
		worker := webTestToken(t, webTestPassword(svc.web, "bob", "correct", "Worker"))
		target := webTestAccess(t, svc, worker, "Worker").auth.FindSession()
		keyFixture = filepath.Join(t.TempDir(), "action-target.json")
		raw, err := json.Marshal(map[string]string{"flow": target.Flow().String(), "id": target.Id().String()})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(keyFixture, raw, 0600))
	}
	if forcedActionMode {
		worker := webTestToken(t, webTestPassword(svc.web, "bob", "correct", "Worker"))
		target := webTestAccess(t, svc, worker, "Worker").auth.FindSession()
		action := strings.TrimPrefix(mode, "management-forced-")
		var keys strings.Builder
		for _, line := range strings.Split(strings.TrimSpace(string(authorizedKeys)), "\n") {
			if !strings.HasPrefix(line, "cert-authority ") {
				_, _ = fmt.Fprintf(&keys, "command=%q ", "session "+action+" "+target.Id().String())
			}
			keys.WriteString(line + "\n")
		}
		svc.Configuration.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = bfcrypto.AuthorizedKeys(keys.String())
		raw, err := os.ReadFile(keyFixture)
		require.NoError(t, err)
		var fixture map[string]string
		require.NoError(t, json.Unmarshal(raw, &fixture))
		fixture["action"], fixture["flow"], fixture["id"] = action, target.Flow().String(), target.Id().String()
		raw, err = json.Marshal(fixture)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(keyFixture, raw, 0600))
	}
	if mode == "interactive" {
		delegate := svc.authorizer
		svc.authorizer = &uiInteractiveAuthorizer{&webInteractionTestAuthorizer{CloseableAuthorizer: delegate, run: func(req authorization.InteractiveRequest) (authorization.Authorization, error) {
			if err := req.SendInfo(`<b>plain provider text</b><script>window.providerInjected = true</script>`); err != nil {
				return nil, err
			}
			if err := req.SendError("Provider warning, shown as text"); err != nil {
				return nil, err
			}
			if _, err := req.Prompt("Echo is allowed for this response", true); err != nil {
				return nil, err
			}
			return delegate.AuthorizeInteractive(req)
		}}}
	}
	var terminalCounters *terminalUiCounters
	if mode == "terminal" || mode == "terminal-expiry" || mode == "terminal-logout-lost" || mode == "workspace" || mode == "workspace-races" {
		terminalCounters = installTerminalUiBackend(svc)
	}
	settings := &configuration.Http{}
	require.NoError(t, settings.SetDefaults())
	settings.Enabled = true
	settings.Domains = configuration.HttpDomains{"app.example.org", "other.example.org"}
	directory := t.TempDir()
	custom := filepath.Join(directory, "custom.js")
	css := filepath.Join(directory, "custom.css")
	require.NoError(t, os.WriteFile(custom, []byte(`window.addEventListener('bifroest:configure', e => { e.detail.title = 'Fixture brand'; });`), 0644))
	require.NoError(t, os.WriteFile(css, []byte(`.workspace { border-top: 3px solid rgb(1, 2, 3); }`), 0644))
	settings.CustomJs = []string{custom}
	settings.CustomCss = []string{css}
	settings.CustomHtmlBody = `<script>window.fixtureInline = true;</script>`
	assets, err := webui.New(settings)
	require.NoError(t, err)
	svc.web.assets = assets
	require.True(t, assets.Available(), "requested UI test needs mise run build:web, not just the source marker")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	httpListenerTestCertificate(t, &configuration.Configuration{Http: settings}, key)
	var interrupt atomic.Bool
	var interrupted atomic.Int32
	var providerReplyBarriers atomic.Int32
	var holdPreparation atomic.Bool
	holdPreparation.Store(workspaceActionMode)
	preparationEntered := make(chan struct{})
	preparationReleased := make(chan struct{})
	var preparationRelease atomic.Bool
	releasePreparation := func() {
		if preparationRelease.CompareAndSwap(false, true) {
			close(preparationReleased)
		}
	}
	t.Cleanup(releasePreparation)
	if mode == "interactive-lost" {
		interrupt.Store(true)
	}
	endpoint, err := https.NewEndpoint(settings, https.EndpointOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if workspaceActionMode && r.URL.Path == "/_bifroest/test/preparation-entered" {
			select {
			case <-preparationEntered:
				w.WriteHeader(204)
			case <-r.Context().Done():
			}
			return
		}
		if workspaceActionMode && r.URL.Path == "/_bifroest/test/preparation-release" {
			releasePreparation()
			w.WriteHeader(204)
			return
		}
		if workspaceActionMode && r.URL.Path == webAPI+"management/sessions/prepare" && holdPreparation.CompareAndSwap(true, false) {
			recorder := httptest.NewRecorder()
			protocolHandler.ServeHTTP(recorder, r)
			if recorder.Code != 202 {
				http.Error(w, "controlled preparation did not complete", 500)
				return
			}
			close(preparationEntered)
			select {
			case <-preparationReleased:
			case <-r.Context().Done():
				return
			}
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		if mode == "terminal-logout-lost" && r.URL.Path == webAPI+"logout" && interrupt.CompareAndSwap(false, true) {
			recorder := httptest.NewRecorder()
			protocolHandler.ServeHTTP(recorder, r)
			if recorder.Code != http.StatusNoContent {
				http.Error(w, "logout fixture did not commit", http.StatusInternalServerError)
				return
			}
			interrupted.Add(1)
			// Commit through the real protocol, then reset the HTTP stream before
			// delivering headers. No fake success/failure or handler replay.
			panic(http.ErrAbortHandler)
		}
		if mode == "terminal-expiry" && r.URL.Path == "/_bifroest/test/expire-current-access" && r.Method == http.MethodPost {
			// Test-only clock boundary: expire the real server grant without
			// waiting ten minutes or changing a production timeout/policy.
			svc.web.mutex.Lock()
			if len(svc.web.access) != 1 {
				svc.web.mutex.Unlock()
				http.Error(w, "expected one original access grant", http.StatusInternalServerError)
				return
			}
			var advanceTo int64
			for _, access := range svc.web.access {
				access.mutex.Lock()
				advanceTo = access.expires.Add(time.Second).UnixMilli()
				access.expires = time.Now().Add(-time.Second)
				access.mutex.Unlock()
			}
			svc.web.mutex.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int64{"advanceTo": advanceTo})
			return
		}
		if mode == "oidc-cancel" && r.URL.Path == webAPI+"login/reply" {
			// Deliver the real acknowledgement only after the provider request
			// starts. An extra browser GET is not part of the cancellation proof.
			recorder := httptest.NewRecorder()
			protocolHandler.ServeHTTP(recorder, r)
			if recorder.Code == http.StatusAccepted {
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				defer cancel()
				select {
				case <-provider.deviceTokenStarted:
					providerReplyBarriers.Add(1)
				case <-ctx.Done():
					http.Error(w, "provider token request did not start", http.StatusServiceUnavailable)
					return
				}
			}
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		if r.URL.Path == "/_bifroest/test/interrupt-enrollment" && r.Method == http.MethodPost {
			interrupt.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if (mode == "management-actions" || workspaceActionMode || forcedActionMode) && r.URL.Path == "/_bifroest/test/interrupt-management-confirm" && r.Method == http.MethodPost {
			interrupt.Store(true)
			w.WriteHeader(204)
			return
		}
		if (mode == "management-actions" || workspaceActionMode || forcedActionMode) && r.URL.Path == webAPI+"management/sessions/confirm" && interrupt.Load() {
			recorder := httptest.NewRecorder()
			protocolHandler.ServeHTTP(recorder, r)
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			if recorder.Code == 200 && interrupt.CompareAndSwap(true, false) {
				interrupted.Add(1)
				w.Header().Set("Content-Length", "1000")
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"status":`))
				return
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		if r.URL.Path == "/_bifroest/test/client.js" {
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = w.Write(core)
			return
		}
		if r.URL.Path == webAPI+"remember/prove" && interrupt.Load() {
			recorder := httptest.NewRecorder()
			protocolHandler.ServeHTTP(recorder, r)
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			if recorder.Code == http.StatusCreated && interrupt.CompareAndSwap(true, false) {
				interrupted.Add(1)
				w.Header().Set("Content-Length", "1000")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"status":`))
				return
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		if mode == "interactive-lost" && r.URL.Path == webAPI+"login/poll" && interrupt.Load() {
			recorder := httptest.NewRecorder()
			protocolHandler.ServeHTTP(recorder, r)
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			if recorder.Code == http.StatusOK && strings.Contains(recorder.Body.String(), `"status":"authorized"`) && interrupt.CompareAndSwap(true, false) {
				interrupted.Add(1)
				w.Header().Set("Content-Length", "1000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":`))
				return
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		protocolHandler.ServeHTTP(w, r)
	})})
	require.NoError(t, err)
	require.NoError(t, endpoint.Prepare(t.Context()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- endpoint.Serve(listener) }()
	t.Cleanup(func() {
		require.NoError(t, endpoint.Close())
		select {
		case err := <-done:
			require.ErrorIs(t, err, http.ErrServerClosed)
		case <-time.After(3 * time.Second):
			t.Error("UI HTTPS endpoint did not stop")
		}
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	node := os.Getenv("BIFROEST_TEST_NODE")
	if node == "" {
		node, err = exec.LookPath("node")
		require.NoError(t, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, filepath.Join(root, "web", "test", "ui.mjs"), "https://app.example.org:"+port, mode, keyFixture)
	command.Dir = filepath.Join(root, "web")
	output, err := command.CombinedOutput()
	if err != nil && terminalCounters != nil {
		t.Logf("terminal backend runs=%d resizes=%d interrupts=%d", terminalCounters.runs.Load(), terminalCounters.resizes.Load(), terminalCounters.interrupts.Load())
	}
	if err != nil && lifecycleRecorder != nil {
		for _, event := range lifecycleRecorder.eventsSnapshot() {
			if event.Name == audit.EventNameSessionTaskCompleted || event.Name == audit.EventNameSessionRecordingFailed || event.Name == audit.EventNameSessionRecordingIncomplete {
				t.Logf("UI failure lifecycle: name=%s outcome=%s reason=%s category=%s session=%s connection=%s", event.Name, event.Outcome, event.Reason, event.ErrorCategory, event.SessionId, event.ConnectionId)
			}
		}
	}
	require.NoError(t, err, "%s", output)
	var result struct {
		Success bool `json:"success"`
	}
	require.NoError(t, json.Unmarshal(output, &result), "%s", output)
	require.True(t, result.Success)
	expectedInterrupt := 0
	if mode == "profile" || mode == "local-password-profile" || mode == "local-interactive-profile" || mode == "interactive-lost" || mode == "management-actions" || workspaceActionMode || mode == "workspace-races" || mode == "management-forced-dispose" || mode == "terminal-logout-lost" {
		expectedInterrupt = 1
	}
	require.EqualValues(t, expectedInterrupt, interrupted.Load(), "the uncertain claim must commit once without automatic retry")
	expectedSessions := 1
	if mode == "name-free" || mode == "oidc-cancel" {
		expectedSessions = 0
	}
	if mode == "terminal" || mode == "management" || mode == "management-actions" || mode == "management-forced" || forcedActionMode {
		expectedSessions = 2
	}
	if mode == "workspace" {
		expectedSessions = 4
	}
	if mode == "workspace-races" {
		expectedSessions = 2
	}
	if workspaceActionMode {
		expectedSessions = 3
	}
	require.Equal(t, expectedSessions, webSessionCount(t, svc))
	if terminalCounters != nil {
		switch mode {
		case "terminal-expiry":
			require.EqualValues(t, 2, terminalCounters.runs.Load(), "only the original login and fresh confirmed login may start shells")
			require.Zero(t, terminalCounters.interrupts.Load(), "grant expiry must not signal an existing execution")
		case "terminal-logout-lost":
			require.EqualValues(t, 1, terminalCounters.runs.Load(), "unconfirmed logout must not dispatch any new shell")
			require.Zero(t, terminalCounters.interrupts.Load())
		case "workspace-races":
			require.EqualValues(t, 3, terminalCounters.runs.Load(), "retiring a pending/unknown candidate must never launch a sibling access")
			require.Positive(t, terminalCounters.interrupts.Load())
			require.Positive(t, terminalCounters.resizes.Load())
		default:
			require.EqualValues(t, 5, terminalCounters.runs.Load())
			require.Positive(t, terminalCounters.resizes.Load())
			require.Positive(t, terminalCounters.interrupts.Load())
		}
	}
	if mode == "key-no-pty" {
		require.Empty(t, auditEventsNamed(lifecycleRecorder.eventsSnapshot(), audit.EventNameSessionTaskStarted), "a certificate without permit-pty cannot start an execution through the UI")
	}
	if actionTargets != nil {
		expectedRuns := 3
		if mode == "management-forced-dispose" {
			expectedRuns = 2
		}
		if workspaceActionMode {
			expectedRuns = 0
		}
		require.EqualValues(t, expectedRuns, actionTargets.runs.Load())
	}
	if provider != nil {
		if mode == "oidc-cancel" {
			require.EqualValues(t, 1, providerReplyBarriers.Load(), "cancel must follow one real reply and an active provider request")
			select {
			case <-provider.deviceTokenCanceled:
			case <-time.After(2 * time.Second):
				t.Fatal("UI cancel did not stop provider token request")
			}
		} else {
			require.EqualValues(t, 1, provider.logins.Load(), "remember/resume must reuse the retained grant, not request another device login")
		}
	}
	require.NoError(t, svc.sessions.FindAll(t.Context(), func(ctx context.Context, current session.Session) (bool, error) {
		info, err := current.Info(ctx)
		require.NoError(t, err)
		switch mode {
		case "management-forced", "management-forced-audit", "management-forced-version":
			created, err := info.Created(t.Context())
			require.NoError(t, err)
			if created.Remote().User() == "alice" {
				require.Equal(t, session.StateAuthorized, info.State())
			} else {
				require.Equal(t, session.StateNew, info.State())
			}
		case "management-actions", "management-forced-dispose", "workspace-actions", "workspace-actions-close":
			if current.Flow() == "worker" {
				require.Equal(t, session.StateDisposed, info.State())
			} else {
				require.Equal(t, session.StateAuthorized, info.State())
			}
		case "management-forced-disconnect":
			require.Equal(t, session.StateAuthorized, info.State())
		case "management":
			require.Equal(t, session.StateAuthorized, info.State(), "management operations share session activation/activity")
		case "terminal":
			require.NotEqual(t, session.StateDisposed, info.State(), "disconnect/exit must preserve the shared session")
		case "key-no-pty":
			require.Equal(t, session.StateNew, info.State(), "PTY denial must not activate the session")
		default:
			require.Equal(t, session.StateAuthorized, info.State(), "confirmed terminal-capable browser login opens a fresh shell")
		}
		bindings, err := current.(session.BrowserBindingSession).BrowserBindings(ctx)
		require.NoError(t, err)
		require.Empty(t, bindings)
		return true, nil
	}, nil))
}
