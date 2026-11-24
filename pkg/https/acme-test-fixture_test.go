package https

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Wall-clock phases stay separate from the certificate fixture's simulated clock.
// Never record request bodies, JWS headers, keys or certificate contents.
type acmeTestTrace struct {
	started time.Time
	mutex   sync.Mutex
	events  []string
}

func newACMETestTrace() *acmeTestTrace { return &acmeTestTrace{started: time.Now()} }

func (this *acmeTestTrace) record(format string, args ...any) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.events = append(this.events, fmt.Sprintf("%s: %s", time.Since(this.started), fmt.Sprintf(format, args...)))
}

func (this *acmeTestTrace) Write(raw []byte) (int, error) {
	this.record("%s", strings.TrimSpace(string(raw)))
	return len(raw), nil
}

func (this *acmeTestTrace) String() string {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return strings.Join(this.events, "\n")
}

func prepareACMETestTLS(ctx context.Context, ca *acmeTestCA, source *ACME, manager *TLS) error {
	ca.trace.record("Prepare started; startup timeout=%s", manager.startupTimeout)
	err := manager.Prepare(ctx)
	ca.trace.record("Prepare finished: %v", err)
	if err != nil {
		for _, name := range []string{"account.pem", certificateStateName("app.example.org")} {
			info, statErr := os.Lstat(filepath.Join(source.store.path, name))
			if os.IsNotExist(statErr) {
				ca.trace.record("state %s: absent", name)
			} else if statErr != nil {
				ca.trace.record("state %s: %v", name, statErr)
			} else {
				ca.trace.record("state %s: present, size=%d mode=%s", name, info.Size(), info.Mode())
			}
		}
	}
	return err
}

type failingACMETestListener struct {
	net.Listener
	err error
}

func (this failingACMETestListener) Accept() (net.Conn, error) { return nil, this.err }

func TestACMETestTLSProbeReportsServeFailure(t *testing.T) {
	failure := errors.New("controlled listener failure")
	trace := newACMETestTrace()
	err := serveACMETestTLS(t.Context(), failingACMETestListener{err: failure}, &tls.Config{}, trace)
	require.ErrorIs(t, err, failure)
	require.Contains(t, trace.String(), "TLS probe accept failed: controlled listener failure")
}

func TestACMETestCAReportsHandlerPanicWithoutHidingItAsStartupDelay(t *testing.T) {
	ca := newACMETestCA(t, newACMETestClock(), func(server *http.Server) {
		server.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("controlled fixture handler panic") })
	})
	response, err := ca.server.Client().Get(ca.server.URL + "/directory")
	if response != nil {
		_ = response.Body.Close()
	}
	require.Error(t, err)
	require.Contains(t, ca.trace.String(), "http: panic serving")
	require.Contains(t, ca.trace.String(), "controlled fixture handler panic")
}

func TestACMETestTLSProbeHonorsRequestCancellationDuringHandshake(t *testing.T) {
	ca := newACMETestCA(t, newACMETestClock())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	accepted := make(chan struct{})
	release := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			close(accepted)
			<-release // Deliberately never complete TLS; no sleep or external service.
		}
		serverDone <- err
	}()
	t.Cleanup(func() { close(release); _ = listener.Close(); require.NoError(t, <-serverDone) })
	ca.setProbe(listener.Addr().String())
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- ca.probe(ctx, "app.example.org", "test-token", &ca.key.PublicKey) }()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("TLS probe did not connect to the bound listener")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled, "a canceled CA request must not wait for the independent probe timeout")
	case <-time.After(5 * time.Second):
		t.Fatal("TLS probe ignored its request cancellation")
	}
}

func TestACMETestPreparationTraceDistinguishesBeforeAndAfterIssuance(t *testing.T) {
	for _, phase := range []string{"before CA", "after CA"} {
		t.Run(phase, func(t *testing.T) {
			ca := newACMETestCA(t, newACMETestClock())
			_, source, manager := newACMETestSource(t, ca, "app.example.org")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if phase == "before CA" {
				cancel()
			} else {
				validations := 0
				source.validateKey = func(crypto.PublicKey) error {
					validations++
					if validations == 2 { // Account validated first, issued certificate second.
						cancel()
					}
					return nil
				}
			}
			require.ErrorIs(t, prepareACMETestTLS(ctx, ca, source, manager), context.Canceled)
			trace := ca.trace.String()
			require.Contains(t, trace, "startup timeout=5s")
			require.Contains(t, trace, "Prepare finished:")
			require.Contains(t, trace, "context canceled")
			require.NoFileExists(t, filepath.Join(source.store.path, certificateStateName("app.example.org")))
			require.False(t, manager.Ready())
			if phase == "before CA" {
				require.Zero(t, ca.counts().requests)
				require.Contains(t, trace, "state account.pem: absent")
				require.NotContains(t, trace, "CA GET /directory started")
			} else {
				require.Equal(t, 1, ca.counts().issues)
				require.Contains(t, trace, "CA POST /certificate/1 finished")
				require.Contains(t, trace, "state account.pem: present")
			}
			t.Logf("controlled %s cancellation:\n%s", phase, trace)
		})
	}
}
