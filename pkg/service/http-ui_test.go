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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/webui"
)

func TestBrowserLoginUiWithRememberRecoveryAndStrictCsp(t *testing.T) {
	testBrowserLoginUi(t, true)
}

func TestBrowserLoginUiPreservesDisabledRequestingName(t *testing.T) {
	testBrowserLoginUi(t, false)
}

func testBrowserLoginUi(t *testing.T, requestUser bool) {
	t.Helper()
	if os.Getenv("BIFROEST_TEST_BROWSER_UI") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_UI=1 after building web/ and installing Chromium")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	core, err := os.ReadFile(filepath.Join(root, "var", "webui-client-build", "remember.js"))
	require.NoError(t, err)
	svc, _, _ := webTestFixture(t, func(conf *configuration.Configuration) { conf.Flows[0].Http.RequestUser = commonBool(requestUser) })
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
	endpoint, err := https.NewEndpoint(settings, https.EndpointOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			svc.web.ServeHTTP(recorder, r)
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
		svc.web.ServeHTTP(w, r)
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
	mode := "profile"
	if !requestUser {
		mode = "name-free"
	}
	command := exec.CommandContext(ctx, node, filepath.Join(root, "web", "test", "ui.mjs"), "https://app.example.org:"+port, mode)
	command.Dir = filepath.Join(root, "web")
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	var result struct {
		Success bool `json:"success"`
	}
	require.NoError(t, json.Unmarshal(output, &result), "%s", output)
	require.True(t, result.Success)
	expected := 1
	if !requestUser {
		expected = 0
	}
	require.EqualValues(t, expected, interrupted.Load(), "the uncertain claim must commit once without automatic retry")
	require.Equal(t, expected, webSessionCount(t, svc))
	require.NoError(t, svc.sessions.FindAll(t.Context(), func(ctx context.Context, current session.Session) (bool, error) {
		info, err := current.Info(ctx)
		require.NoError(t, err)
		require.Equal(t, session.StateNew, info.State(), "login UI must not provision a workload or acquire an execution lease")
		bindings, err := current.(session.BrowserBindingSession).BrowserBindings(ctx)
		require.NoError(t, err)
		require.Empty(t, bindings)
		return true, nil
	}, nil))
}
