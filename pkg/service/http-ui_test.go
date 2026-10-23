package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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

func testBrowserLoginUi(t *testing.T, requestUser bool, mode string) {
	t.Helper()
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_UI=1 after building web/ and installing Chromium")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	core, err := os.ReadFile(filepath.Join(root, "var", "webui-client-build", "remember.js"))
	require.NoError(t, err)
	var svc *service
	var protocolHandler http.Handler
	var provider *oidcAssociationProvider
	if mode == "oidc" || mode == "oidc-cancel" {
		svc, protocolHandler, provider, _ = webOidcLoginFixture(t, mode == "oidc-cancel")
	} else {
		svc, _, _ = webTestFixture(t, func(conf *configuration.Configuration) {
			conf.Flows[0].Http.RequestUser = commonBool(requestUser)
			if mode == "terminal" {
				settings := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
				settings.Entries = append(settings.Entries, configuration.AuthorizationSimpleEntry{Name: "bob", Password: bfcrypto.Password("plain:correct")})
			}
		})
		protocolHandler = svc.web
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
	if mode == "terminal" {
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
	require.True(t, assets.Available(), "requested UI test needs npm run build:app, not just the source marker")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	httpListenerTestCertificate(t, &configuration.Configuration{Http: settings}, key)
	var interrupt atomic.Bool
	var interrupted atomic.Int32
	if mode == "interactive-lost" {
		interrupt.Store(true)
	}
	endpoint, err := https.NewEndpoint(settings, https.EndpointOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "oidc-cancel" && r.URL.Path == "/_bifroest/test/provider-started" {
			select {
			case <-provider.deviceTokenStarted:
				w.WriteHeader(http.StatusNoContent)
			case <-r.Context().Done():
			}
			return
		}
		if r.URL.Path == "/_bifroest/test/interrupt-enrollment" && r.Method == http.MethodPost {
			interrupt.Store(true)
			w.WriteHeader(http.StatusNoContent)
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
	command := exec.CommandContext(ctx, node, filepath.Join(root, "web", "test", "ui.mjs"), "https://app.example.org:"+port, mode)
	command.Dir = filepath.Join(root, "web")
	output, err := command.CombinedOutput()
	if err != nil && terminalCounters != nil {
		t.Logf("terminal backend runs=%d resizes=%d interrupts=%d", terminalCounters.runs.Load(), terminalCounters.resizes.Load(), terminalCounters.interrupts.Load())
	}
	require.NoError(t, err, "%s", output)
	var result struct {
		Success bool `json:"success"`
	}
	require.NoError(t, json.Unmarshal(output, &result), "%s", output)
	require.True(t, result.Success)
	expectedInterrupt := 0
	if mode == "profile" || mode == "interactive-lost" {
		expectedInterrupt = 1
	}
	require.EqualValues(t, expectedInterrupt, interrupted.Load(), "the uncertain claim must commit once without automatic retry")
	expectedSessions := 1
	if mode == "name-free" || mode == "oidc-cancel" {
		expectedSessions = 0
	}
	if mode == "terminal" {
		expectedSessions = 2
	}
	require.Equal(t, expectedSessions, webSessionCount(t, svc))
	if terminalCounters != nil {
		require.EqualValues(t, 4, terminalCounters.runs.Load())
		require.Positive(t, terminalCounters.resizes.Load())
		require.Positive(t, terminalCounters.interrupts.Load())
	}
	if provider != nil {
		if mode == "oidc-cancel" {
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
		if mode == "terminal" {
			require.NotEqual(t, session.StateDisposed, info.State(), "disconnect/exit must preserve the shared session")
		} else {
			require.Equal(t, session.StateNew, info.State(), "login UI must not provision a workload or acquire an execution lease")
		}
		bindings, err := current.(session.BrowserBindingSession).BrowserBindings(ctx)
		require.NoError(t, err)
		require.Empty(t, bindings)
		return true, nil
	}, nil))
}
