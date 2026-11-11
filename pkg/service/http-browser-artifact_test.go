package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/https"
)

type browserArtifactAuditGate struct {
	delegate audit.Recorder
	active   atomic.Pointer[artifactFinalAuditGate]
}

func (g *browserArtifactAuditGate) Record(ctx context.Context, event audit.Event) error {
	if active := g.active.Load(); active != nil {
		return active.Record(ctx, event)
	}
	return g.delegate.Record(ctx, event)
}

func (*browserArtifactAuditGate) Close() error { return nil }

// Observe admission failures without buffering/changing the streaming response,
// admission state, or any production limit. Never capture headers or bodies.
type browserArtifactResponseObserver struct {
	http.ResponseWriter
	observed bool
	status   func(int)
}

func (w *browserArtifactResponseObserver) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *browserArtifactResponseObserver) WriteHeader(code int) {
	if !w.observed {
		w.observed = true
		w.status(code)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *browserArtifactResponseObserver) Write(value []byte) (int, error) {
	if !w.observed {
		w.observed = true
		w.status(http.StatusOK)
	}
	return w.ResponseWriter.Write(value)
}

func (w *browserArtifactResponseObserver) Flush() {
	_ = w.FlushError()
}

func (w *browserArtifactResponseObserver) FlushError() error {
	if !w.observed {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *browserArtifactResponseObserver) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type browserArtifactFlushFailureWriter struct {
	headers http.Header
	err     error
	flushes int
	writes  int
}

func (w *browserArtifactFlushFailureWriter) Header() http.Header { return w.headers }
func (*browserArtifactFlushFailureWriter) WriteHeader(int)       {}
func (w *browserArtifactFlushFailureWriter) Write(value []byte) (int, error) {
	w.writes++
	return len(value), nil
}
func (w *browserArtifactFlushFailureWriter) FlushError() error { w.flushes++; return w.err }

func TestBrowserArtifactResponseObserverPreservesFlushFailure(t *testing.T) {
	sentinel := errors.New("fixture flush failure")
	underlying := &browserArtifactFlushFailureWriter{headers: make(http.Header), err: sentinel}
	var statuses []int
	observer := &browserArtifactResponseObserver{ResponseWriter: underlying, status: func(code int) { statuses = append(statuses, code) }}
	for range 2 {
		require.ErrorIs(t, http.NewResponseController(observer).Flush(), sentinel)
	}
	require.Equal(t, 2, underlying.flushes)
	require.Zero(t, underlying.writes, "observing status must not inject or buffer body bytes")
	require.Equal(t, []int{http.StatusOK}, statuses)
	require.Same(t, underlying, observer.Unwrap())
}

func TestBrowserArtifactTransferUsesGoWasmAndPostDriverCompletion(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_BROWSER_CLIENT") != "1" {
		t.Skip("set BIFROEST_TEST_BROWSER_CLIENT=1 after mise run build:web and browser installation")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	bundle, err := os.ReadFile(filepath.Join(root, "var", "webui-client-build", "remember.js"))
	require.NoError(t, err)
	node := os.Getenv("BIFROEST_TEST_NODE")
	if node == "" {
		node, err = exec.LookPath("node")
		require.NoError(t, err)
	}
	for _, mode := range []string{"normal", "encrypted", "ui-clear", "ui-encrypted", "ui-breadcrumb", "ui-audit-clear", "ui-audit-encrypted", "ui-cancel-clear", "ui-cancel-encrypted", "ui-navigation-encrypted", "catalog-clear", "catalog-encrypted", "catalog-startup-failure", "held-success", "held-failure", "source-held-success", "source-held-failure", "source-cancel"} {
		t.Run(mode, func(t *testing.T) {
			var keyPath, recipient string
			private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
			public, err := ssh.NewPublicKey(private.Public())
			require.NoError(t, err)
			if strings.HasSuffix(mode, "encrypted") {
				block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "public browser test key", []byte("tab fixture secret"))
				require.NoError(t, err)
				keyPath = filepath.Join(t.TempDir(), "offline-key.pem")
				require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600))
				recipient = ssh.FingerprintSHA256(public)
			}
			svc, recorder, _ := executionTestFixture(t, nil, func(conf *configuration.Configuration) {
				conf.Http = &configuration.Http{}
				require.NoError(t, conf.Http.SetDefaults())
				conf.Http.Enabled = true
				conf.Http.Domains = configuration.HttpDomains{"app.example.org"}
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				httpListenerTestCertificate(t, conf, key)
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{AllowArtifactTransfer: true}
				conf.Flows[0].DiscoverAsSlug = "Work"
				if strings.HasPrefix(mode, "ui-") || strings.HasPrefix(mode, "catalog-") {
					settings := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
					settings.Entries = append(settings.Entries, configuration.AuthorizationSimpleEntry{Name: "bob", Password: bfcrypto.Password("plain:correct")})
				}
				if strings.HasSuffix(mode, "encrypted") {
					conf.Auditlogs[0].EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(public)))
				}
				if strings.HasPrefix(mode, "catalog-") {
					root := filepath.Dir(conf.Session.V.(*configuration.SessionFs).Storage)
					for index := range 21 {
						var current configuration.Auditlog
						require.NoError(t, current.SetDefaults())
						current.Name = configuration.AuditlogName(fmt.Sprintf("catalog%02d", index))
						current.IdentityFile = filepath.Join(root, current.Name.String()+"-signer")
						current.Directory = filepath.Join(root, current.Name.String()+"-journal")
						current.Recording.Enabled = index != 20
						current.Recording.Directory = filepath.Join(root, current.Name.String()+"-recordings")
						if strings.HasSuffix(mode, "encrypted") {
							current.EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(public)))
						}
						conf.Auditlogs = append(conf.Auditlogs, current)
					}
				}
			})
			svc.environments = svc.environments.(*executionTestRepository).CloseableRepository
			var playbackID string
			if strings.HasPrefix(mode, "ui-") {
				playbackID = catalogRecording(t, svc, "default", 1, []byte("PLAYBACK_ONLY\r\n\x1b]0;must-not-rename-playback\x07\x1b]52;c;cHJpdmF0ZQ==\x07\x1b]8;;https://must-not-open.invalid/\x07blocked-playback-link\x1b]8;;\x07\r\n\xff")).String()
			}
			if strings.HasPrefix(mode, "catalog-") {
				for index := 1; index <= 21; index++ {
					catalogRecording(t, svc, "catalog00", index)
				}
			}
			flow := svc.Configuration.Flows[0]
			delegate := svc.auditRecorders[flow.Auditlog]
			auditGate := &browserArtifactAuditGate{delegate: delegate}
			svc.flowAuditRecorders[flow.Name] = auditGate
			svc.managementApplication = nil
			require.True(t, svc.web.assets.Available(), "run mise run build:web before the requested browser test")
			var cookies, queries, socketCookies atomic.Int32
			var admissionMutex sync.Mutex
			var rejectedAdmissions []string
			var release sync.Once
			unblock := func() {
				if gate := auditGate.active.Load(); gate != nil {
					release.Do(func() { close(gate.release) })
				}
			}
			t.Cleanup(unblock)
			endpoint, err := https.NewEndpoint(svc.Configuration.Http, https.EndpointOptions{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/_bifroest/test/client.html":
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = w.Write([]byte(`<!doctype html><html lang="en-US"><title>Artifact client test</title></html>`))
					return
				case "/_bifroest/test/client.js":
					w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
					_, _ = w.Write(bundle)
					return
				case "/_bifroest/test/artifact-id":
					ids, err := svc.recordingRepositories[flow.Auditlog].native.ListSealed(r.Context())
					require.NoError(t, err)
					id := playbackID
					if id == "" {
						require.Len(t, ids, 1)
						id = ids[0].String()
					}
					w.Header().Set("Content-Type", "application/json")
					if mode == "ui-breadcrumb" || mode == "ui-navigation-encrypted" {
						_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "producer": svc.auditIdentities[flow.Auditlog].ProducerId().String(), "recipient": recipient, "managementFlow": flow.Name.String(), "flow": flow.Name.String()})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "producer": svc.auditIdentities[flow.Auditlog].ProducerId().String(), "recipient": recipient})
					return
				case "/_bifroest/test/artifact-arm":
					gate := &artifactFinalAuditGate{delegate: delegate, entered: make(chan struct{}), release: make(chan struct{})}
					if strings.HasSuffix(mode, "held-failure") {
						gate.failure = errors.New("private final-audit detail")
					}
					auditGate.active.Store(gate)
					w.WriteHeader(http.StatusNoContent)
					return
				case "/_bifroest/test/artifact-entered":
					gate := auditGate.active.Load()
					if gate == nil {
						http.Error(w, "gate not armed", http.StatusConflict)
						return
					}
					select {
					case <-gate.entered:
						w.WriteHeader(http.StatusNoContent)
					case <-r.Context().Done():
					}
					return
				case "/_bifroest/test/artifact-release":
					unblock()
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if strings.HasPrefix(r.URL.Path, webAPI) {
					if r.Header.Get("Cookie") != "" {
						if r.URL.Path == webAPI+"management/channel" {
							socketCookies.Add(1)
						} else {
							cookies.Add(1)
						}
					}
					if r.URL.RawQuery != "" {
						queries.Add(1)
					}
				}
				observed := &browserArtifactResponseObserver{ResponseWriter: w, status: func(code int) {
					if code != http.StatusTooManyRequests {
						return
					}
					peer, peerErr := webPeer(r)
					resource := "api"
					if strings.HasPrefix(r.URL.Path, "/_bifroest/files/") && (strings.HasSuffix(r.URL.Path, ".js") || strings.HasSuffix(r.URL.Path, ".wasm") || strings.HasSuffix(r.URL.Path, ".wasm.gz")) {
						resource = r.URL.Path
					} else if r.URL.Path == webAPI+"logout" {
						resource = "logout"
					}
					svc.web.mutex.Lock()
					budget := svc.web.peers[peer]
					var diagnostic string
					if peerErr == nil && budget != nil {
						diagnostic = fmt.Sprintf("resource=%s status=%d requests=%d/%d logins=%d/%d active=%d/%d globalActive=%d/%d", resource, code, budget.requests, webMaximumRequestsPerMinute, budget.logins, webMaximumLoginsPerMinute, budget.active, webMaximumWorkersPerPeer, svc.web.active, webMaximumWorkers)
					} else {
						diagnostic = fmt.Sprintf("resource=%s status=%d peerBudgetAvailable=false", resource, code)
					}
					svc.web.mutex.Unlock()
					admissionMutex.Lock()
					if len(rejectedAdmissions) < 32 {
						rejectedAdmissions = append(rejectedAdmissions, diagnostic)
					}
					admissionMutex.Unlock()
				}}
				svc.web.ServeHTTP(observed, r)
			})})
			require.NoError(t, err)
			require.NoError(t, endpoint.Prepare(t.Context()))
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { done <- endpoint.Serve(listener) }()
			t.Cleanup(func() {
				unblock()
				require.NoError(t, endpoint.Close())
				select {
				case err := <-done:
					require.ErrorIs(t, err, http.ErrServerClosed)
				case <-time.After(3 * time.Second):
					t.Error("browser artifact endpoint did not stop")
				}
			})
			_, port, err := net.SplitHostPort(listener.Addr().String())
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			script := "artifact-client.mjs"
			if strings.HasPrefix(mode, "ui-") {
				script = "artifact-ui.mjs"
			}
			if mode == "ui-breadcrumb" {
				script = "recording-breadcrumb-ui.mjs"
			}
			if mode == "ui-navigation-encrypted" {
				script = "encrypted-navigation-ui.mjs"
			}
			if strings.HasPrefix(mode, "catalog-") {
				script = "catalog-ui.mjs"
			}
			command := exec.CommandContext(ctx, node, filepath.Join(root, "web", "test", script), "https://app.example.org:"+port, mode, keyPath)
			command.Dir = filepath.Join(root, "web")
			output, err := command.CombinedOutput()
			svc.web.mutex.Lock()
			peerIndex := 0
			for _, budget := range svc.web.peers {
				peerIndex++
				t.Logf("browser admission final: peer=%d requests=%d/%d logins=%d/%d active=%d/%d globalActive=%d/%d", peerIndex, budget.requests, webMaximumRequestsPerMinute, budget.logins, webMaximumLoginsPerMinute, budget.active, webMaximumWorkersPerPeer, svc.web.active, webMaximumWorkers)
			}
			svc.web.mutex.Unlock()
			if err != nil {
				admissionMutex.Lock()
				for _, diagnostic := range rejectedAdmissions {
					t.Logf("browser admission rejected: %s", diagnostic)
				}
				admissionMutex.Unlock()
				for _, event := range recorder.eventsSnapshot() {
					if event.Name == audit.EventNameSessionTaskCompleted || event.Name == audit.EventNameSessionRecordingCompleted || event.Name == audit.EventNameSessionRecordingFailed || event.Name == audit.EventNameSessionRecordingIncomplete {
						t.Logf("artifact failure lifecycle: name=%s outcome=%s reason=%s category=%s session=%s connection=%s", event.Name, event.Outcome, event.Reason, event.ErrorCategory, event.SessionId, event.ConnectionId)
					}
				}
			}
			require.NoError(t, err, "%s", output)
			admissionMutex.Lock()
			rejectionCount := len(rejectedAdmissions)
			admissionMutex.Unlock()
			require.Zero(t, rejectionCount, "an independent artifact scenario must stay within the unchanged admission limits")
			var result struct {
				Success bool `json:"success"`
			}
			require.NoError(t, json.Unmarshal(output, &result))
			require.True(t, result.Success)
			require.Zero(t, cookies.Load())
			if strings.HasPrefix(mode, "catalog-") {
				require.Positive(t, socketCookies.Load(), "browser WebSockets attach unrelated same-origin cookies, but ONLY the open proof authorizes the channel")
			}
			require.Zero(t, queries.Load())
		})
	}
}
