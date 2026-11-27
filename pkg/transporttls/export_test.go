package transporttls

import (
	"context"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// AcmeEndpointFixture shares the controlled ACME test double with adapter tests.
func AcmeEndpointFixture(t *testing.T) (*configuration.Http, *ACME, *x509.Certificate, func(string), func() int) {
	t.Helper()
	ca := newACMETestCA(t, newACMETestClock())
	conf, source, _ := newACMETestSource(t, ca, "app.example.org")
	return conf, source, ca.root, ca.setProbe, func() int { return ca.counts().proofs }
}

// KubernetesCAFixture delays the first order until the test driver has inspected
// the unready Pod, then performs real TLS-ALPN probes through the chart Service.
func KubernetesCAFixture(t *testing.T, address string, begin <-chan struct{}) (string, []byte, *x509.Certificate, func() (int, int)) {
	t.Helper()
	ca := newPebbleTestCA(t, address, []string{"app.example.org"}, 12, true)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-begin:
		case <-ctx.Done():
			return
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, ca.url+"/fixture/begin", nil)
		if err == nil {
			var response *http.Response
			response, err = ca.client.Do(request)
			if response != nil {
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Errorf("cannot release Pebble order gate: HTTP %d", response.StatusCode)
				}
			}
		}
		if err != nil && ctx.Err() == nil {
			t.Errorf("cannot release Pebble order gate: %v", err)
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	return ca.directory(), ca.trust, ca.root, func() (int, int) {
		counts := ca.counts()
		return int(counts.Finalizations), int(counts.Registrations)
	}
}
