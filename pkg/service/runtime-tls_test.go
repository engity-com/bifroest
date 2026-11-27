package service

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

func TestRuntimeTLSReloadKeepsSharedManagerBindingsAndMetrics(t *testing.T) {
	conf := sharedTLSConfiguration(t)
	svc := prepareHTTPListenerTestService(t, conf)
	runtimeListenerTestStart(t, svc, nil)
	manager := svc.tlsManagers["tls:shared"]
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "new title" })
	runtimeListenerTestActivate(t, svc, next)
	require.Same(t, manager, next.tlsManagers["tls:shared"])
	require.Same(t, svc.tlsBindings["http"], next.tlsBindings["http"])
	require.Same(t, svc.tlsBindings["monitoring"], next.tlsBindings["monitoring"])
	snapshot, err := next.monitoring.Snapshot(t.Context(), []string{"bifroest_tls_binding_ready", "bifroest_tls_certificate_expiration_timestamp_seconds", "bifroest_http_tls_certificate_expiration_timestamp_seconds"})
	require.NoError(t, err)
	require.Len(t, snapshot.Families, 3)
	get := func(consumer string) []byte {
		t.Helper()
		selected, err := next.tlsBindings[consumer].Config().GetConfigForClient(&tls.ClientHelloInfo{ServerName: "app.example.org"})
		require.NoError(t, err)
		return selected.Certificates[0].Certificate[0]
	}
	before := get("http")
	other := httpListenerTestConfiguration(t)
	httpListenerTestCertificate(t, &other, nil)
	oldPair, newPair := conf.Tls["shared"].Certificates[0], other.Http.Tls.Certificates[0]
	cert, err := os.ReadFile(newPair.CertificateFile)
	require.NoError(t, err)
	key, err := os.ReadFile(newPair.PrivateKeyFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(oldPair.CertificateFile, cert, 0600))
	require.NoError(t, bfcrypto.WriteBootstrapFile(oldPair.PrivateKeyFile, key, true))
	require.NoError(t, manager.ReloadFiles(t.Context()))
	require.NotEqual(t, before, get("http"))
	require.Equal(t, get("http"), get("monitoring"))

	rejected := next.generation.snapshot.Configuration()
	rejected.Tls["shared"] = configuration.Tls{Dummy: true}
	candidate, err := svc.prepareGeneration(t.Context(), rejected)
	require.ErrorContains(t, err, "requires restart")
	require.ErrorContains(t, err, "tls")
	require.Nil(t, candidate)
	require.Same(t, next.generation, svc.runtime.current)
}

func TestRuntimeTLSChallengeOnlyAddressReloadDoesNotServeApplicationTLS(t *testing.T) {
	conf := sharedTLSConfiguration(t)
	conf.Http.Enabled = configuration.HttpAcmeTlsAlpnOnly
	profile := conf.Tls["shared"]
	profile.Acme = &configuration.TlsAcme{
		AcceptTerms: true, DirectoryUrl: configuration.DefaultHttpAcmeDirectoryUrl, Storage: filepath.Join(t.TempDir(), "acme"),
	}
	conf.Tls["shared"] = profile
	svc := prepareHTTPListenerTestService(t, conf)
	run := runtimeListenerTestStart(t, svc, nil)
	original, _ := run.scope(t, "TLS challenge", conf.Http.Addresses[0].String(), 0)
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Http.Addresses = append(conf.Http.Addresses, bnet.MustNewAddress("127.0.0.2:0"))
	})
	runtimeListenerTestActivate(t, svc, next)
	kept, _ := run.scope(t, "TLS challenge", conf.Http.Addresses[0].String(), 0)
	require.Same(t, original, kept)
	_, added := run.scope(t, "TLS challenge", "127.0.0.2:0", 0)
	require.Nil(t, svc.https)
	require.Nil(t, next.https)
	probe := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: "app.example.org", NextProtos: []string{"h2"},
		InsecureSkipVerify: true, //nolint:gosec // Local negative protocol probe, no application data.
	}}
	connection, err := probe.DialContext(t.Context(), "tcp", added.Addr().String())
	if connection != nil {
		_ = connection.Close()
	}
	require.Error(t, err)
	rejected := next.generation.snapshot.Configuration()
	rejected.Http.Enabled = configuration.HttpEnabled
	candidate, err := svc.prepareGeneration(t.Context(), rejected)
	require.ErrorContains(t, err, "requires restart")
	require.Nil(t, candidate)
	require.Same(t, next.generation, svc.runtime.current)
	require.NoDirExists(t, profile.Acme.Storage)
}
