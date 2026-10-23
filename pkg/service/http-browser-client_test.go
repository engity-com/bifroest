package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/session"
)

// Explicit opt-in keeps SSH-only Go development independent of npm/Chromium.
// A requested browser run must fail, not skip, if its tools/assets are missing.
func TestBrowserRememberMeClientAgainstRealHttpsAndWebSocket(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_BROWSER_CLIENT") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_CLIENT=1 after building web/ and installing its test browser")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	bundle, err := os.ReadFile(filepath.Join(root, "var", "webui-client-build", "remember.js"))
	require.NoError(t, err)
	require.Less(t, len(bundle), 1<<20)
	node := os.Getenv("BIFROEST_TEST_NODE")
	if node == "" {
		node, err = exec.LookPath("node")
		require.NoError(t, err)
	}
	svc, _, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Session.V.(*configuration.SessionFs).IdleTimeout.SetNative(0)
		conf.Session.V.(*configuration.SessionFs).MaxTimeout.SetNative(0)
	})
	var executions atomic.Int32
	svc.environments.(*executionTestRepository).run = func(task environment.TerminalTask) (int, error) {
		executions.Add(1)
		if _, err := io.WriteString(task.Terminal(), "browser-client-execution-started"); err != nil {
			return -1, err
		}
		<-task.Context().Done()
		return 0, nil
	}
	settings := &configuration.Http{}
	require.NoError(t, settings.SetDefaults())
	settings.Enabled = true
	settings.Domains = configuration.HttpDomains{"app.example.org", "other.example.org"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	httpListenerTestCertificate(t, &configuration.Configuration{Http: settings}, key)
	var cookies, queries, socketCookies, foreign atomic.Int32
	endpoint, err := https.NewEndpoint(settings, https.EndpointOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_bifroest/test/client.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			_, _ = w.Write(bundle)
			return
		case "/_bifroest/test/client.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html lang="en-US"><title>Browser client HTTPS test</title></html>`))
			return
		}
		if strings.HasPrefix(r.URL.Path, webAPI) {
			if strings.HasPrefix(r.Host, "other.example.org") {
				foreign.Add(1)
			}
			if r.URL.Path == webAPI+"terminal" && r.Header.Get("Cookie") != "" {
				socketCookies.Add(1)
			}
			if r.URL.Path != webAPI+"terminal" && r.Header.Get("Cookie") != "" {
				cookies.Add(1)
			}
			if r.URL.RawQuery != "" {
				queries.Add(1)
			}
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
			require.True(t, errors.Is(err, http.ErrServerClosed), "%v", err)
		case <-time.After(3 * time.Second):
			t.Error("browser test HTTPS endpoint did not stop")
		}
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, filepath.Join(root, "web", "test", "https-client.mjs"), "https://app.example.org:"+port)
	command.Dir = filepath.Join(root, "web")
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	var result struct {
		Flow      configuration.FlowName `json:"flow"`
		SessionID session.Id             `json:"sessionId"`
	}
	require.NoError(t, json.Unmarshal(output, &result), "%s", output)
	require.EqualValues(t, 0, cookies.Load(), "HTTP API requests must not send existing browser cookies; WebSocket cookies are ignored, not authentication")
	require.EqualValues(t, 0, queries.Load())
	require.EqualValues(t, 0, foreign.Load(), "same-origin fetch must reject foreign API destinations before sending credentials")
	require.Positive(t, socketCookies.Load(), "browser WebSocket cookies must be ignored even when present")
	require.EqualValues(t, 1, executions.Load(), "only the authenticated terminal may reach backend execution")
	require.Equal(t, 1, webSessionCount(t, svc))
	current, err := svc.sessions.FindBy(t.Context(), result.Flow, result.SessionID, nil)
	require.NoError(t, err)
	info, err := current.Info(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, session.StateDisposed, info.State(), "browser logout must not dispose the shared workload/session")
	bindings, err := current.(session.BrowserBindingSession).BrowserBindings(t.Context())
	require.NoError(t, err)
	require.Empty(t, bindings)
}
