package https

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

type certificateSourceFunc func(context.Context, string, Challenge) (*tls.Certificate, error)

func (this certificateSourceFunc) Certificate(ctx context.Context, domain string, challenge Challenge) (*tls.Certificate, error) {
	return this(ctx, domain, challenge)
}

type tlsTestCertificate struct {
	certificate *tls.Certificate
	configured  configuration.HttpCertificate
	root        *x509.Certificate
}

func newTlsTestCertificate(t *testing.T, domains []string, chained bool, mutate func(*x509.Certificate), mutateParent ...func(*x509.Certificate)) tlsTestCertificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return newTlsTestCertificateWithSigner(t, key, domains, chained, mutate, mutateParent...)
}

func newTlsTestCertificateWithSigner(t *testing.T, key crypto.Signer, domains []string, chained bool, mutate func(*x509.Certificate), mutateParent ...func(*x509.Certificate)) tlsTestCertificate {
	t.Helper()
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
		_, parentKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer = parentKey
		parent = &x509.Certificate{
			SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test-only-ca"}, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(48 * time.Hour),
			KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		}
		for _, mutate := range mutateParent {
			mutate(parent)
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
	conf.Enabled = true
	conf.Domains = configuration.HttpDomains(domains)
	conf.Tls.Acme.Enabled, conf.Tls.Acme.AcceptTerms = true, true
	return &conf
}

func testClientHello(name string, protocols ...string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: name, SupportedProtos: protocols}
}

func TestExplicitTlsCertificatesCoverDomainsAndArePreferredWithoutIssuance(t *testing.T) {
	for _, chained := range []bool{false, true} {
		fixture := newTlsTestCertificate(t, []string{"app.example.org", "other.example.org"}, chained, nil)
		conf := newTlsTestConfiguration(t, "APP.EXAMPLE.ORG.", "other.example.org")
		conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
		var calls atomic.Int32
		manager, err := NewTLS(conf, certificateSourceFunc(func(context.Context, string, Challenge) (*tls.Certificate, error) {
			calls.Add(1)
			return nil, errors.New("must not issue")
		}))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, manager.Close()) })
		_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
		require.ErrorIs(t, err, ErrNotReady)
		require.NoError(t, manager.Prepare(context.Background()))
		require.NoError(t, manager.Prepare(context.Background()), "ready preparation is idempotent")
		require.True(t, manager.Ready())
		require.Zero(t, calls.Load())
		for _, domain := range []string{"app.example.org", "OTHER.EXAMPLE.ORG."} {
			selected, err := manager.Config().GetConfigForClient(testClientHello(domain, "h2"))
			require.NoError(t, err)
			require.Equal(t, fixture.certificate.Certificate, selected.Certificates[0].Certificate)
			require.Equal(t, uint16(tls.VersionTLS12), selected.MinVersion)
			require.True(t, selected.SessionTicketsDisabled)
		}
		client := &tls.Config{ServerName: "app.example.org", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}
		client.RootCAs.AddCert(fixture.root)
		state, clientErr, serverErr := testTlsHandshake(t, manager.Config(), client)
		require.NoError(t, clientErr)
		require.NoError(t, serverErr)
		require.Equal(t, "h2", state.NegotiatedProtocol)
	}
}

func TestTlsAllowlistCannotBeExpandedByCertificateSansOrUntrustedClientHello(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"*.example.org"}, false, nil)
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
	manager, err := NewTLS(conf, nil)
	require.NoError(t, err)
	defer manager.Close()
	require.NoError(t, manager.Prepare(context.Background()))
	for _, domain := range []string{"", "other.example.org", "app.example.org:443", "https://app.example.org", "app.example.org.attacker.example"} {
		_, err := manager.Config().GetConfigForClient(testClientHello(domain, "h2"))
		require.Error(t, err, domain)
	}
	_, err = manager.Config().GetConfigForClient(nil)
	require.Error(t, err)
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2", acme.ALPNProto))
	require.Error(t, err)
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", acme.ALPNProto))
	require.Error(t, err, "ordinary certificate must never substitute for a challenge")
}

func TestClientHelloCannotStartOnDemandCertificateAcquisition(t *testing.T) {
	var calls atomic.Int32
	manager, err := NewTLS(newTlsTestConfiguration(t, "app.example.org"), certificateSourceFunc(func(context.Context, string, Challenge) (*tls.Certificate, error) {
		calls.Add(1)
		return nil, errors.New("not called by handshakes")
	}))
	require.NoError(t, err)
	defer manager.Close()
	for _, hello := range []*tls.ClientHelloInfo{testClientHello("app.example.org", "h2"), testClientHello("app.example.org", acme.ALPNProto), testClientHello("other.example.org", "h2")} {
		_, err := manager.Config().GetConfigForClient(hello)
		require.Error(t, err)
	}
	require.Zero(t, calls.Load())
}

func TestTlsWithoutSniOnlySelectsASoleExplicitIpDomain(t *testing.T) {
	for _, domain := range []string{"127.0.0.1", "[::1]"} {
		fixture := newTlsTestCertificate(t, []string{domain}, false, nil)
		conf := newTlsTestConfiguration(t, domain)
		conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
		manager, err := NewTLS(conf, nil)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, manager.Close()) })
		require.NoError(t, manager.Prepare(context.Background()))
		_, err = manager.Config().GetConfigForClient(testClientHello("", "http/1.1"))
		require.NoError(t, err)
		client := &tls.Config{ServerName: strings.Trim(domain, "[]"), RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
		client.RootCAs.AddCert(fixture.root)
		_, clientErr, serverErr := testTlsHandshake(t, manager.Config(), client)
		require.NoError(t, clientErr)
		require.NoError(t, serverErr)
	}
}

func TestTlsReadinessIsAtomicAndOnlyActiveAlpnProofCanBypassIt(t *testing.T) {
	first := newTlsTestCertificate(t, []string{"first.example.org"}, false, nil)
	second := newTlsTestCertificate(t, []string{"second.example.org"}, false, nil)
	proof := newTlsTestProof(t, "second.example.org")
	proofInstalled, continueIssuance := make(chan struct{}), make(chan struct{})
	conf := newTlsTestConfiguration(t, "first.example.org", "second.example.org")
	manager, err := NewTLS(conf, certificateSourceFunc(func(ctx context.Context, domain string, publish Challenge) (*tls.Certificate, error) {
		if domain == "first.example.org" {
			return first.certificate, nil
		}
		release, err := publish(&proof)
		if err != nil {
			return nil, err
		}
		defer release()
		close(proofInstalled)
		select {
		case <-continueIssuance:
			return second.certificate, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	done := make(chan error, 1)
	go func() { done <- manager.Prepare(context.Background()) }()
	select {
	case <-proofInstalled:
	case <-time.After(5 * time.Second):
		t.Fatal("proof was not installed")
	}
	require.False(t, manager.Ready())
	for _, domain := range conf.Domains {
		_, err := manager.Config().GetConfigForClient(testClientHello(domain, "h2"))
		require.ErrorIs(t, err, ErrNotReady)
	}
	_, err = manager.Config().GetConfigForClient(testClientHello("first.example.org", acme.ALPNProto))
	require.Error(t, err)
	selected, err := manager.Config().GetConfigForClient(testClientHello("second.example.org", acme.ALPNProto))
	require.NoError(t, err)
	require.Equal(t, []string{acme.ALPNProto}, selected.NextProtos)
	_, clientErr, serverErr := testTlsHandshake(t, manager.Config(), &tls.Config{ServerName: "second.example.org", NextProtos: []string{acme.ALPNProto}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // ACME proof certificate intentionally has a critical identifier extension.
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	close(continueIssuance)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("preparation did not finish")
	}
	require.True(t, manager.Ready())
	_, err = manager.Config().GetConfigForClient(testClientHello("second.example.org", acme.ALPNProto))
	require.Error(t, err, "proof must disappear after issuance")
}

func TestTlsPreparationFailureNeverPublishesPartialReadiness(t *testing.T) {
	first := newTlsTestCertificate(t, []string{"first.example.org"}, false, nil)
	sentinel := errors.New("test issuance failed")
	conf := newTlsTestConfiguration(t, "first.example.org", "second.example.org")
	manager, err := NewTLS(conf, certificateSourceFunc(func(_ context.Context, domain string, _ Challenge) (*tls.Certificate, error) {
		if domain == "first.example.org" {
			return first.certificate, nil
		}
		return nil, sentinel
	}))
	require.NoError(t, err)
	defer manager.Close()
	require.ErrorIs(t, manager.Prepare(context.Background()), sentinel)
	require.False(t, manager.Ready())
	_, err = manager.Config().GetConfigForClient(testClientHello("first.example.org", "h2"))
	require.ErrorIs(t, err, ErrNotReady)
}

func TestTlsPreparationCancellationTimeoutAndCloseRemoveProofs(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout", "close"} {
		t.Run(mode, func(t *testing.T) {
			conf := newTlsTestConfiguration(t, "app.example.org")
			if mode == "timeout" {
				conf.StartupTimeout = common.DurationOf(100 * time.Millisecond)
			}
			proof := newTlsTestProof(t, "app.example.org")
			installed := make(chan struct{})
			manager, err := NewTLS(conf, certificateSourceFunc(func(ctx context.Context, _ string, publish Challenge) (*tls.Certificate, error) {
				release, err := publish(&proof)
				if err != nil {
					return nil, err
				}
				defer release()
				close(installed)
				<-ctx.Done()
				return nil, ctx.Err()
			}))
			require.NoError(t, err)
			defer manager.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- manager.Prepare(ctx) }()
			select {
			case <-installed:
			case <-time.After(5 * time.Second):
				t.Fatal("proof was not installed")
			}
			// A concurrent waiter must honor its own cancellation rather than
			// waiting behind the active network request's entire timeout.
			waiter, cancelWaiter := context.WithCancel(context.Background())
			cancelWaiter()
			require.ErrorIs(t, manager.Prepare(waiter), context.Canceled)
			switch mode {
			case "cancel":
				cancel()
			case "close":
				require.NoError(t, manager.Close())
			}
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("preparation did not stop")
			}
			require.False(t, manager.Ready())
			_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", acme.ALPNProto))
			require.Error(t, err)
		})
	}
}

func TestTlsRejectsForgedProviderLeafAndWrongDomain(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"other.example.org"}, false, nil)
	for _, candidate := range []*tls.Certificate{nil, fixture.certificate, {Certificate: fixture.certificate.Certificate, PrivateKey: fixture.certificate.PrivateKey, Leaf: &x509.Certificate{DNSNames: []string{"app.example.org"}}}} {
		manager, err := NewTLS(newTlsTestConfiguration(t, "app.example.org"), certificateSourceFunc(func(context.Context, string, Challenge) (*tls.Certificate, error) { return candidate, nil }))
		require.NoError(t, err)
		require.Error(t, manager.Prepare(context.Background()))
		require.False(t, manager.Ready())
		require.NoError(t, manager.Close())
	}
}

func TestTlsHandshakeRechecksLifetimeAndCloseEvenAfterReadiness(t *testing.T) {
	fixture := newTlsTestCertificate(t, []string{"app.example.org"}, false, nil)
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Certificates = []configuration.HttpCertificate{fixture.configured}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	manager, err := newTLS(conf, nil, func() time.Time { return time.Unix(0, clock.Load()) })
	require.NoError(t, err)
	require.NoError(t, manager.Prepare(context.Background()))
	clock.Store(fixture.certificate.Leaf.NotAfter.UnixNano())
	require.Error(t, manager.Prepare(context.Background()), "idempotent preparation must not claim expired material is still ready")
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.Error(t, err)
	require.NoError(t, manager.Close())
	require.NoError(t, manager.Close())
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.ErrorIs(t, err, ErrClosed)
	require.ErrorIs(t, manager.Prepare(context.Background()), ErrClosed)
}

func TestTlsPrepareRejectsPublishedCloseBeforeObservingCallerCancellation(t *testing.T) {
	// Close publishes closed before canceling lifetime. Model that valid
	// intermediate state with the preparation gate occupied, so the old select
	// deterministically returns caller cancellation instead of the closed state.
	manager := &TLS{closed: true, lifetime: context.Background(), startupTimeout: time.Second, preparing: make(chan struct{}, 1)}
	manager.preparing <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, manager.Prepare(ctx), ErrClosed)
	require.Len(t, manager.preparing, 1, "a closed manager must not acquire or alter the active preparation gate")
}

func testTlsHandshake(t *testing.T, serverConfig, clientConfig *tls.Config) (tls.ConnectionState, error, error) {
	t.Helper()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server, client := tls.Server(left, serverConfig), tls.Client(right, clientConfig)
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(ctx) }()
	clientErr := client.HandshakeContext(ctx)
	serverErr := <-done
	return client.ConnectionState(), clientErr, serverErr
}
