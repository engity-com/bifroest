package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	for _, mode := range []string{"normal", "encrypted", "held-success", "held-failure"} {
		t.Run(mode, func(t *testing.T) {
			var keyPath, recipient string
			private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
			public, err := ssh.NewPublicKey(private.Public())
			require.NoError(t, err)
			if mode == "encrypted" {
				block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "public browser test key", []byte("tab fixture secret"))
				require.NoError(t, err)
				keyPath = filepath.Join(t.TempDir(), "offline-key.pem")
				require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600))
				recipient = ssh.FingerprintSHA256(public)
			}
			svc, _, _ := executionTestFixture(t, nil, func(conf *configuration.Configuration) {
				conf.Http = &configuration.Http{}
				require.NoError(t, conf.Http.SetDefaults())
				conf.Http.Enabled = true
				conf.Http.Domains = configuration.HttpDomains{"app.example.org"}
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				httpListenerTestCertificate(t, conf, key)
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{AllowArtifactTransfer: true}
				conf.Flows[0].DiscoverAsSlug = "Work"
				if mode == "encrypted" {
					conf.Auditlogs[0].EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(public)))
				}
			})
			svc.environments = svc.environments.(*executionTestRepository).CloseableRepository
			flow := svc.Configuration.Flows[0]
			delegate := svc.auditRecorders[flow.Auditlog]
			auditGate := &browserArtifactAuditGate{delegate: delegate}
			svc.flowAuditRecorders[flow.Name] = auditGate
			svc.managementApplication = nil
			require.True(t, svc.web.assets.Available(), "run mise run build:web before the requested browser test")
			var cookies, queries atomic.Int32
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
					require.Len(t, ids, 1)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{"id": ids[0].String(), "producer": svc.auditIdentities[flow.Auditlog].ProducerId().String(), "recipient": recipient})
					return
				case "/_bifroest/test/artifact-arm":
					gate := &artifactFinalAuditGate{delegate: delegate, entered: make(chan struct{}), release: make(chan struct{})}
					if mode == "held-failure" {
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
			command := exec.CommandContext(ctx, node, filepath.Join(root, "web", "test", "artifact-client.mjs"), "https://app.example.org:"+port, mode, keyPath)
			command.Dir = filepath.Join(root, "web")
			output, err := command.CombinedOutput()
			require.NoError(t, err, "%s", output)
			var result struct {
				Success bool `json:"success"`
			}
			require.NoError(t, json.Unmarshal(output, &result))
			require.True(t, result.Success)
			require.Zero(t, cookies.Load())
			require.Zero(t, queries.Load())
		})
	}
}
