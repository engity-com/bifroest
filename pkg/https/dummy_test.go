package https

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestDummyTlsIsEphemeralExplicitAndConfinedToConfiguredNames(t *testing.T) {
	conf := newTlsTestConfiguration(t, "APP.EXAMPLE.ORG.", "xn--bcher-kva.example", "127.0.0.1", "[::1]")
	conf.Tls.Acme.Enabled = false
	conf.Tls.Dummy = true
	conf.Tls.Acme.Storage = filepath.Join(t.TempDir(), "must-not-be-created")
	now := time.Now()
	clock := func() time.Time { return now }
	manager, err := newTLS(conf, certificateSourceFunc(func(context.Context, string, Challenge) (*tls.Certificate, error) {
		t.Fatal("dummy must not call any certificate source")
		return nil, errors.New("unexpected source")
	}), clock)
	require.NoError(t, err)
	defer manager.Close()
	require.False(t, manager.Ready())
	_, err = manager.configForClient(testClientHello("app.example.org", "h2"))
	require.ErrorIs(t, err, ErrNotReady)
	require.NoError(t, manager.Prepare(t.Context()))
	require.True(t, manager.Ready())
	certificate := manager.certificates["app.example.org"].value
	for _, domain := range []string{"app.example.org", "xn--bcher-kva.example", "127.0.0.1", "::1"} {
		require.NoError(t, certificate.Leaf.VerifyHostname(domain))
	}
	require.False(t, certificate.Leaf.IsCA)
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, certificate.Leaf.ExtKeyUsage)
	require.NoError(t, certificate.Leaf.CheckSignature(certificate.Leaf.SignatureAlgorithm, certificate.Leaf.RawTBSCertificate, certificate.Leaf.Signature))
	require.WithinDuration(t, now.Add(24*time.Hour), certificate.Leaf.NotAfter, time.Second)
	key, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok)
	require.Equal(t, 256, key.Curve.Params().BitSize)
	_, err = manager.configForClient(testClientHello("unconfigured.example.org", "h2"))
	require.Error(t, err)
	_, err = manager.configForClient(testClientHello("", "h2"))
	require.Error(t, err, "multiple names must not make absent SNI acceptable")
	require.NoError(t, manager.RenewDue(t.Context()))
	require.NoDirExists(t, conf.Tls.Acme.Storage)
	second, err := NewTLS(conf, nil)
	require.NoError(t, err)
	defer second.Close()
	require.NotEqual(t, certificate.Certificate[0], second.explicit["app.example.org"].value.Certificate[0])
	require.NotEqual(t, certificate.Leaf.RawSubjectPublicKeyInfo, second.explicit["app.example.org"].value.Leaf.RawSubjectPublicKeyInfo)
	now = now.Add(25 * time.Hour)
	require.False(t, manager.Ready())
	_, err = manager.configForClient(testClientHello("app.example.org", "h2"))
	require.Error(t, err, "expired dummy material cannot trigger fallback or issuance")
}

func TestDummyEndpointStillValidatesKeysAndServesRealHttp2(t *testing.T) {
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Acme.Enabled = false
	conf.Tls.Dummy = true
	sentinel := errors.New("key role rejected")
	_, err := NewEndpoint(conf, EndpointOptions{ValidateKey: func(crypto.PublicKey) error { return sentinel }})
	require.ErrorIs(t, err, sentinel)
	endpoint, err := NewEndpoint(conf, EndpointOptions{})
	require.NoError(t, err)
	listener, _ := startEndpointTestListener(t, endpoint)
	root := endpoint.tls.explicit["app.example.org"].value.Leaf
	client := endpointTestClient(t, listener, root) // Trust this leaf in this client only, never the OS.
	require.NoError(t, endpoint.Prepare(t.Context()))
	response, err := client.Get("https://app.example.org/work")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, 2, response.ProtoMajor)
	require.Equal(t, http.StatusNotImplemented, response.StatusCode)
	_, err = root.Verify(x509.VerifyOptions{Roots: x509.NewCertPool(), DNSName: "app.example.org"})
	require.Error(t, err, "dummy must not invent browser/public trust")
	require.Nil(t, endpoint.source)
}

func TestTlsNeverUsesDummyAsImplicitFallback(t *testing.T) {
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Acme.Enabled = false
	_, err := NewTLS(conf, nil)
	require.Error(t, err)
	conf.Tls.Certificates = []configuration.HttpCertificate{{CertificateFile: "missing/cert.pem", PrivateKeyFile: "missing/key.pem"}}
	_, err = NewTLS(conf, nil)
	require.Error(t, err)
	conf.Tls.Dummy = true
	_, err = NewTLS(conf, nil)
	require.ErrorContains(t, err, "cannot be combined")
}
