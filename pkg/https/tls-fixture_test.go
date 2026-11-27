package https

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type tlsTestCertificate struct {
	certificate *tls.Certificate
	configured  configuration.HttpCertificate
	root        *x509.Certificate
}

func newTlsTestCertificate(t *testing.T, domains []string, chained bool, mutate func(*x509.Certificate)) tlsTestCertificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	for _, domain := range domains {
		if ip := net.ParseIP(strings.Trim(domain, "[]")); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, domain)
		}
	}
	if mutate != nil {
		mutate(template)
	}
	parent, signer := template, key
	var parentDER []byte
	if chained {
		_, signer, err = ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		parent = &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test-only-ca"}, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(48 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		}
		parentDER, err = x509.CreateCertificate(rand.Reader, parent, parent, signer.Public(), signer)
		require.NoError(t, err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), signer)
	require.NoError(t, err)
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if chained {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parentDER})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(chainPEM, keyPEM)
	require.NoError(t, err)
	rootDER := der
	if chained {
		rootDER = parentDER
	}
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	directory := t.TempDir()
	configured := configuration.HttpCertificate{CertificateFile: filepath.Join(directory, "chain.pem"), PrivateKeyFile: filepath.Join(directory, "key.pem")}
	require.NoError(t, os.WriteFile(configured.CertificateFile, chainPEM, 0600))
	require.NoError(t, bfcrypto.WriteBootstrapFile(configured.PrivateKeyFile, keyPEM, false))
	return tlsTestCertificate{&certificate, configured, root}
}
func newTlsTestConfiguration(t *testing.T, domains ...string) *configuration.Http {
	t.Helper()
	var conf configuration.Http
	require.NoError(t, conf.SetDefaults())
	conf.Enabled = configuration.HttpEnabled
	conf.Domains = configuration.HttpDomains(domains)
	conf.Tls = &configuration.Tls{}
	require.NoError(t, conf.Tls.SetDefaults())
	conf.Tls.Acme = &configuration.TlsAcme{}
	require.NoError(t, conf.Tls.Acme.SetDefaults())
	conf.Tls.Acme.AcceptTerms = true
	return &conf
}
func copyReloadPair(t *testing.T, source, target configuration.HttpCertificate) {
	t.Helper()
	cert, err := os.ReadFile(source.CertificateFile)
	require.NoError(t, err)
	key, err := os.ReadFile(source.PrivateKeyFile)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(target.CertificateFile, cert, 0600))
	require.NoError(t, bfcrypto.WriteBootstrapFile(target.PrivateKeyFile, key, true))
}
