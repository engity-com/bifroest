package https

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func copyReloadPair(t *testing.T, source, target configuration.HttpCertificate) {
	t.Helper()
	for _, files := range [][2]string{{source.CertificateFile, target.CertificateFile}, {source.PrivateKeyFile, target.PrivateKeyFile}} {
		raw, err := os.ReadFile(files[0])
		require.NoError(t, err)
		// A Unix mode alone does not protect a newly created Windows key.
		require.NoError(t, bfcrypto.WriteBootstrapFile(files[1], raw, true))
	}
}

func TestTLSReloadCopiesKeepPrivateKeysProtected(t *testing.T) {
	directory := t.TempDir()
	target := configuration.HttpCertificate{CertificateFile: filepath.Join(directory, "tls.crt"), PrivateKeyFile: filepath.Join(directory, "tls.key")}
	for range 2 {
		source := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
		copyReloadPair(t, source.configured, target)
		// Also runs without symlink privileges and checks the real platform ACL.
		pair, err := loadCertificate(target, time.Now())
		require.NoError(t, err)
		require.Equal(t, source.certificate.Certificate, pair.value.Certificate)
	}
}

func TestTLSFileReloadRetainsLastGoodPairAndRecoversWithoutRestart(t *testing.T) {
	first := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	second := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Acme.Enabled = false
	conf.Tls.Certificates = []configuration.HttpCertificate{first.configured}
	manager, err := NewTLS(conf, nil)
	require.NoError(t, err)
	defer manager.Close()
	require.NoError(t, manager.Prepare(t.Context()))
	original, err := manager.Config().GetConfigForClient(testClientHello("app.example.org"))
	require.NoError(t, err)
	key, err := os.ReadFile(second.configured.PrivateKeyFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(first.configured.PrivateKeyFile, key, 0600))
	require.Error(t, manager.ReloadFiles(t.Context()), "half of a rotated pair must not be published")
	retained, err := manager.Config().GetConfigForClient(testClientHello("app.example.org"))
	require.NoError(t, err)
	require.Equal(t, original.Certificates[0].Certificate, retained.Certificates[0].Certificate)
	copyReloadPair(t, second.configured, first.configured)
	require.NoError(t, manager.ReloadFiles(t.Context()))
	updated, err := manager.Config().GetConfigForClient(testClientHello("app.example.org"))
	require.NoError(t, err)
	require.Equal(t, second.certificate.Certificate, updated.Certificates[0].Certificate)
	require.Equal(t, first.certificate.Certificate, original.Certificates[0].Certificate, "previous handshake snapshots remain immutable")
	manager.validateKey = func(crypto.PublicKey) error { return fmt.Errorf("forbidden key purpose") }
	require.ErrorContains(t, manager.ReloadFiles(t.Context()), "forbidden key purpose")
	manager.validateKey = nil
	manager.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	require.False(t, manager.Ready())
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org"))
	require.Error(t, err)
	extended := newTlsTestCertificate(t, []string{"app.example.org"}, false, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(96 * time.Hour) })
	copyReloadPair(t, extended.configured, first.configured)
	require.NoError(t, manager.ReloadFiles(t.Context()))
	require.True(t, manager.Ready())
}

func TestTLSFileReloadFollowsProjectedSecretAndCertbotSymlinkRotations(t *testing.T) {
	first := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	second := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	directory := t.TempDir()
	for _, generation := range []string{"generation-a", "generation-b"} {
		require.NoError(t, os.Mkdir(filepath.Join(directory, generation), 0700))
	}
	pair := func(generation string) configuration.HttpCertificate {
		return configuration.HttpCertificate{CertificateFile: filepath.Join(directory, generation, "tls.crt"), PrivateKeyFile: filepath.Join(directory, generation, "tls.key")}
	}
	copyReloadPair(t, first.configured, pair("generation-a"))
	copyReloadPair(t, second.configured, pair("generation-b"))
	if err := os.Symlink("generation-a", filepath.Join(directory, "..data")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	require.NoError(t, os.Symlink("..data/tls.crt", filepath.Join(directory, "tls.crt")))
	require.NoError(t, os.Symlink("..data/tls.key", filepath.Join(directory, "tls.key")))
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{{CertificateFile: filepath.Join(directory, "tls.crt"), PrivateKeyFile: filepath.Join(directory, "tls.key")}}
	manager, err := NewTLS(conf, nil)
	require.NoError(t, err)
	defer manager.Close()
	require.NoError(t, manager.Prepare(t.Context()))
	require.NoError(t, os.Symlink("generation-b", filepath.Join(directory, "..data-next")))
	require.NoError(t, os.Rename(filepath.Join(directory, "..data-next"), filepath.Join(directory, "..data")))
	require.NoError(t, manager.ReloadFiles(t.Context()))
	selected, err := manager.Config().GetConfigForClient(testClientHello("app.example.org"))
	require.NoError(t, err)
	require.Equal(t, second.certificate.Certificate, selected.Certificates[0].Certificate)
}

func TestTLSRenewalLoopAutomaticallyReloadsExternalFiles(t *testing.T) {
	first := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	second := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Acme.Enabled = false
	conf.Tls.ReloadInterval = common.DurationOf(time.Millisecond)
	conf.Tls.Certificates = []configuration.HttpCertificate{first.configured}
	manager, err := NewTLS(conf, nil)
	require.NoError(t, err)
	defer manager.Close()
	require.NoError(t, manager.Prepare(t.Context()))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	var failures atomic.Int32
	go func() { done <- manager.RunRenewal(ctx, func(error) { failures.Add(1) }) }()
	copyReloadPair(t, second.configured, first.configured)
	require.Eventually(t, func() bool {
		selected, err := manager.Config().GetConfigForClient(testClientHello("app.example.org"))
		return err == nil && string(selected.Certificates[0].Certificate[0]) == string(second.certificate.Certificate[0])
	}, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestTLSReloadKeepsACMEAndFileDomainCoverageSeparate(t *testing.T) {
	first := newTlsTestCertificate(t, []string{"file.example.org"}, false, nil)
	rotated := newTlsTestCertificate(t, []string{"file.example.org"}, false, nil)
	acme := newTlsTestCertificate(t, []string{"acme.example.org"}, false, nil)
	conf := newTlsTestConfiguration(t, "file.example.org", "acme.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{first.configured}
	var requests int
	manager, err := NewTLS(conf, certificateSourceFunc(func(_ context.Context, domain string, _ Challenge) (*tls.Certificate, error) {
		requests++
		require.Equal(t, "acme.example.org", domain)
		return acme.certificate, nil
	}))
	require.NoError(t, err)
	defer manager.Close()
	require.NoError(t, manager.Prepare(t.Context()))
	copyReloadPair(t, rotated.configured, first.configured)
	require.NoError(t, manager.ReloadFiles(t.Context()))
	for domain, expected := range map[string]*tls.Certificate{"file.example.org": rotated.certificate, "acme.example.org": acme.certificate} {
		selected, err := manager.Config().GetConfigForClient(testClientHello(domain))
		require.NoError(t, err)
		require.Equal(t, expected.Certificate, selected.Certificates[0].Certificate)
	}
	require.Equal(t, 1, requests, "file reload must not issue or renew ACME certificates")
	copyReloadPair(t, acme.configured, first.configured)
	require.ErrorContains(t, manager.ReloadFiles(t.Context()), "no longer cover")
	require.True(t, manager.Ready(), "dropping a file-backed domain must reject the entire rotation")
}
