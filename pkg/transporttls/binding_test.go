package transporttls

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestBindingsShareSnapshotsButNotNamesProtocolsOrReadiness(t *testing.T) {
	first := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	second := newTlsTestCertificate(t, []string{"monitor.example.org"}, false, nil)
	manager, err := NewManaged(Config{Names: configuration.ServerNames{"app.example.org", "monitor.example.org"},
		Profile:        configuration.Tls{MinVersion: "1.3", Certificates: []configuration.TlsCertificate{first.configured, second.configured}},
		StartupTimeout: time.Second}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	http, err := manager.Bind(configuration.ServerNames{"app.example.org"}, []string{"h2", "http/1.1"}, false)
	require.NoError(t, err)
	monitoring, err := manager.Bind(configuration.ServerNames{"monitor.example.org"}, nil, true)
	require.NoError(t, err)
	_, err = manager.Bind(configuration.ServerNames{"attacker.example.org"}, nil, false)
	require.Error(t, err)
	require.False(t, http.Ready())
	require.NoError(t, manager.Prepare(t.Context()))
	require.Len(t, http.Expirations(), 1)
	require.NotContains(t, http.Expirations(), "monitor.example.org")
	app, err := http.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS13), app.MinVersion)
	require.Equal(t, []string{"h2", "http/1.1"}, app.NextProtos)
	private, err := monitoring.Config().GetConfigForClient(testClientHello(""))
	require.NoError(t, err)
	require.Empty(t, private.NextProtos)
	_, err = http.Config().GetConfigForClient(testClientHello("monitor.example.org"))
	require.Error(t, err)
	_, err = http.Config().GetConfigForClient(testClientHello(""))
	require.Error(t, err)
	_, err = monitoring.Config().GetConfigForClient(testClientHello("monitor.example.org", acme.ALPNProto))
	require.Error(t, err)
	manager.mutex.Lock()
	manager.certificates["monitor.example.org"].notAfter = time.Now().Add(-time.Second)
	manager.mutex.Unlock()
	require.False(t, monitoring.Ready())
	require.True(t, http.Ready(), "expiry of an unrelated binding must not block HTTP")
	_, err = http.Config().GetConfigForClient(testClientHello("app.example.org"))
	require.NoError(t, err)
}

func TestChallengeRegistryWorksWithoutHTTPAndBeforeReadiness(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, _, manager := newACMETestSource(t, ca, "app.example.org")
	var registry Registry
	require.NoError(t, registry.Register(manager))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- registry.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Error("challenge listener did not drain")
		}
	})
	ca.setProbe(listener.Addr().String())
	require.False(t, manager.Ready())
	require.NoError(t, manager.Prepare(t.Context()))
	require.Equal(t, 1, ca.counts().proofs)
	_, err = registry.Config(nil).GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.Error(t, err, "a ready certificate does not turn a challenge socket into an application listener")
	_, err = registry.Config(nil).GetConfigForClient(testClientHello("app.example.org", acme.ALPNProto))
	require.Error(t, err, "completed proof must have been removed")
}

func TestRegistryRoutesNonHTTPProofWithoutExpandingHTTPNames(t *testing.T) {
	conf := newTlsTestConfiguration(t, "app.example.org", "database.example.org")
	first := newTlsTestCertificate(t, []string{"app.example.org", "database.example.org"}, false, nil)
	conf.Tls.Certificates = []configuration.HttpCertificate{first.configured}
	manager, err := NewTLS(conf, nil)
	require.NoError(t, err)
	defer manager.Close()
	http, err := manager.Bind(configuration.ServerNames{"app.example.org"}, []string{"h2"}, false)
	require.NoError(t, err)
	registry := &Registry{}
	require.NoError(t, registry.Register(manager))
	proof := newTlsTestProof(t, "database.example.org")
	manager.activeDomain = "database.example.org"
	release, err := manager.installChallenge(t.Context(), "database.example.org", &proof)
	require.NoError(t, err)
	defer release()
	selected, err := registry.Config(http.Config()).GetConfigForClient(testClientHello("database.example.org", acme.ALPNProto))
	require.NoError(t, err)
	require.Equal(t, []string{acme.ALPNProto}, selected.NextProtos)
	require.NoError(t, manager.Prepare(t.Context()))
	_, err = registry.Config(http.Config()).GetConfigForClient(testClientHello("database.example.org", "h2"))
	require.Error(t, err, "challenge registration is not HTTP host authorization")
}
