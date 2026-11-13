package https

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestTlsRejectsInvalidExplicitCertificateWithoutAcmeFallback(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(*x509.Certificate)
		message string
	}{
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }, "expired"},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }, "not valid yet"},
		{"CA leaf", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }, "must not be a CA"},
		{"client authentication only", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, "server authentication"},
		{"encryption only", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }, "digital signatures"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTlsTestCertificate(t, []string{"app.example.org"}, false, test.mutate)
			conf := newTlsTestConfiguration(t, "app.example.org")
			conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
			_, err := NewTLS(conf, certificateSourceFunc(func(context.Context, string, Challenge) (*tls.Certificate, error) {
				t.Fatal("bad explicitly configured material must not cause automatic ACME issuance")
				return nil, nil
			}))
			require.ErrorContains(t, err, test.message)
		})
	}
}

func TestTlsPrivateKeyFormatsAndMinimumStrength(t *testing.T) {
	for _, test := range []struct {
		name     string
		generate func() (crypto.Signer, error)
		accepted bool
	}{
		{"RSA 2048", func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) }, true},
		{"RSA 1024", func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 1024) }, false},
		{"ECDSA P256", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }, true},
		{"ECDSA P224", func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P224(), rand.Reader) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			key, err := test.generate()
			require.NoError(t, err)
			fixture := newTlsTestCertificateWithSigner(t, key, []string{"app.example.org"}, false, nil)
			certificate, err := loadCertificate(fixture.configured, time.Now())
			if test.accepted {
				require.NoError(t, err)
				require.True(t, certificateMatches(certificate.value, "app.example.org"))
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestTlsRejectsUncoveredOrUnrelatedCertificateDomains(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	conf := newTlsTestConfiguration(t, "app.example.org", "other.example.org")
	conf.Tls.Acme.Enabled = false
	conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
	_, err := NewTLS(conf, nil)
	require.ErrorContains(t, err, "no certificate source covers configured domain")
	conf.Domains = configuration.HttpDomains{"other.example.org"}
	_, err = NewTLS(conf, nil)
	require.ErrorContains(t, err, "covers no configured domain")
	_, err = NewTLS(nil, nil)
	require.ErrorContains(t, err, "disabled")
}

func TestTlsDoesNotRequireSendingAnExplicitlyTrustedRootInTheBundle(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, true, nil)
	require.NoError(t, os.WriteFile(fixture.configured.CertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.certificate.Certificate[0]}), 0600))
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
	manager, err := NewTLS(conf, nil)
	require.NoError(t, err)
	defer manager.Close()
	require.NoError(t, manager.Prepare(context.Background()))
	client := &tls.Config{ServerName: "app.example.org", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	client.RootCAs.AddCert(fixture.root)
	_, clientErr, serverErr := testTlsHandshake(t, manager.Config(), client)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
}

func TestTlsFileAndParserErrorsDoNotExposePrivateMaterialOrPaths(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	other := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	configured := fixture.configured
	configured.PrivateKeyFile = other.configured.PrivateKeyFile
	_, err := loadCertificate(configured, time.Now())
	require.ErrorContains(t, err, "do not match")

	const secret = "private-material-do-not-log"
	for _, content := range []string{"-----BEGIN PRIVATE KEY-----\n" + secret + "\n-----END PRIVATE KEY-----", secret} {
		require.NoError(t, os.WriteFile(other.configured.PrivateKeyFile, []byte(content), 0600))
		_, err := loadCertificate(other.configured, time.Now())
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret)
		require.NotContains(t, err.Error(), other.configured.PrivateKeyFile)
	}
	configured.PrivateKeyFile = fixture.configured.PrivateKeyFile + ".missing-secret-path"
	_, err = loadCertificate(configured, time.Now())
	require.Error(t, err)
	require.NotContains(t, err.Error(), "missing-secret-path")
	configured = fixture.configured
	configured.CertificateFile += ".missing-certificate-path"
	_, err = loadCertificate(configured, time.Now())
	require.Error(t, err)
	require.NotContains(t, err.Error(), "missing-certificate-path")
}

func TestTlsReadsOnlyBoundedCertificatePemChains(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	original, err := os.ReadFile(fixture.configured.CertificateFile)
	require.NoError(t, err)
	for _, content := range [][]byte{
		nil, []byte("garbage"), append([]byte("garbage\n"), original...), append(append([]byte(nil), original...), []byte("trailing garbage")...),
		append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), original...),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-certificate")}),
		[]byte(strings.Repeat("X", maximumCertificateFileBytes+1)),
	} {
		require.NoError(t, os.WriteFile(fixture.configured.CertificateFile, content, 0600))
		_, err := loadCertificate(fixture.configured, time.Now())
		require.Error(t, err)
	}
	fixture.configured.CertificateFile = t.TempDir()
	_, err = loadCertificate(fixture.configured, time.Now())
	require.Error(t, err)
}

func TestTlsCannotPublishProviderProofAsApplicationCertificate(t *testing.T) {
	proof := newTlsTestProof(t, "app.example.org")
	manager, err := NewTLS(newTlsTestConfiguration(t, "app.example.org"), certificateSourceFunc(func(context.Context, string, Challenge) (*tls.Certificate, error) { return &proof, nil }))
	require.NoError(t, err)
	defer manager.Close()
	require.Error(t, manager.Prepare(context.Background()))
	require.False(t, manager.Ready())
}

func TestTlsRejectsNilOrInvalidLengthPrivateSignersWithoutPanicking(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	for _, key := range []any{nil, (*ecdsa.PrivateKey)(nil), ed25519.PrivateKey{1}} {
		copyOfCertificate := *fixture.certificate
		copyOfCertificate.PrivateKey = key
		_, err := validateCertificate(&copyOfCertificate, time.Now())
		require.Error(t, err)
	}
}

func TestTlsRechecksEarliestChainExpirationNotOnlyLeaf(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, true, nil, func(root *x509.Certificate) { root.NotAfter = time.Now().Add(time.Hour).Truncate(time.Second) })
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	manager, err := newTLS(conf, nil, func() time.Time { return time.Unix(0, clock.Load()) })
	require.NoError(t, err)
	defer manager.Close()
	require.NoError(t, manager.Prepare(context.Background()))
	require.True(t, manager.Ready())
	require.True(t, fixture.root.NotAfter.Before(fixture.certificate.Leaf.NotAfter))
	clock.Store(fixture.root.NotAfter.UnixNano())
	require.False(t, manager.Ready())
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.Error(t, err)
}

func TestTlsPreparationRechecksEarlierDomainsBeforePublishingReadiness(t *testing.T) {
	first := newTlsTestCertificate(t, []string{"first.example.org"}, false, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(time.Minute).Truncate(time.Second) })
	second := newTlsTestCertificate(t, []string{"second.example.org"}, false, nil)
	conf := newTlsTestConfiguration(t, "first.example.org", "second.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{first.configured}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	manager, err := newTLS(conf, certificateSourceFunc(func(context.Context, string, Challenge) (*tls.Certificate, error) {
		clock.Store(first.certificate.Leaf.NotAfter.UnixNano())
		return second.certificate, nil
	}), func() time.Time { return time.Unix(0, clock.Load()) })
	require.NoError(t, err)
	defer manager.Close()
	require.ErrorContains(t, manager.Prepare(context.Background()), "expired before readiness")
	require.False(t, manager.Ready())
}
