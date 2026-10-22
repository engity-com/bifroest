package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/https"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/template"
)

func httpListenerTestConfiguration(t *testing.T) configuration.Configuration {
	t.Helper()
	root := t.TempDir()
	conf := auditSftpDedicatednessTestConfiguration(t, root, nil, "")
	conf.Auditlogs[0].Enabled = false
	conf.Auditlogs[0].Targets = nil
	conf.Http = &configuration.Http{}
	require.NoError(t, conf.Http.SetDefaults())
	conf.Http.Enabled = true
	conf.Http.Domains = configuration.HttpDomains{"app.example.org"}
	conf.Http.Addresses = bnet.NetAddresses{bnet.MustNewAddress("127.0.0.1:0")}
	conf.Http.Tls.Acme.Enabled, conf.Http.Tls.Acme.AcceptTerms = true, true
	conf.Http.Tls.Acme.Storage = filepath.Join(root, "acme")
	conf.Http.GracefulShutdownTimeout = common.DurationOf(100 * time.Millisecond)
	conf.Ssh.GracefulShutdownTimeout = common.DurationOf(100 * time.Millisecond)
	return conf
}

func httpListenerTestCertificate(t *testing.T, conf *configuration.Configuration, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	if signer == nil {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer = key
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test HTTPS"}, DNSNames: []string{"app.example.org", "other.example.org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, signer.Public(), signer)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	key, err := x509.MarshalPKCS8PrivateKey(signer)
	require.NoError(t, err)
	path := t.TempDir()
	pair := configuration.HttpCertificate{CertificateFile: filepath.Join(path, "certificate.pem"), PrivateKeyFile: filepath.Join(path, "key.pem")}
	require.NoError(t, os.WriteFile(pair.CertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	require.NoError(t, bfcrypto.WriteBootstrapFile(pair.PrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), false))
	conf.Http.Tls.Certificates = []configuration.HttpCertificate{pair}
	return root
}

func prepareHTTPListenerTestService(t *testing.T, conf configuration.Configuration) *service {
	t.Helper()
	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return svc
}

func awaitHTTPListenerTestRun(t *testing.T, done <-chan error) func() error {
	t.Helper()
	var once sync.Once
	var result error
	return func() error {
		once.Do(func() {
			select {
			case result = <-done:
			case <-time.After(5 * time.Second):
				result = errors.New("joint listeners did not stop")
				t.Error(result)
			}
		})
		return result
	}
}

func TestJointListenerBindFailureRollsBackWithoutAcmeOrSshServing(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	httpListenerTestCertificate(t, &conf, nil)
	conf.Http.Domains = append(conf.Http.Domains, "needs-acme.example.org")
	svc := prepareHTTPListenerTestService(t, conf)
	var first net.Listener
	calls := 0
	_, err := svc.runListeners(context.Background(), func(address bnet.Address) (net.Listener, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("injected bind failure")
		}
		var err error
		first, err = address.Listen()
		return first, err
	})
	require.ErrorContains(t, err, "cannot bind HTTPS")
	require.ErrorContains(t, err, "injected bind failure")
	replacement, err := net.Listen("tcp", first.Addr().String())
	require.NoError(t, err)
	require.NoError(t, replacement.Close())
	_, err = os.Stat(conf.Http.Tls.Acme.Storage)
	require.True(t, os.IsNotExist(err), "binding must complete before ACME storage or network activity")
}

func TestEveryConfiguredInputIsStartupCritical(t *testing.T) {
	for failAt := 1; failAt <= 4; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			conf := httpListenerTestConfiguration(t)
			conf.Ssh.Addresses = append(conf.Ssh.Addresses, bnet.MustNewAddress("127.0.0.1:0"))
			conf.Http.Addresses = append(conf.Http.Addresses, bnet.MustNewAddress("127.0.0.1:443"))
			svc := prepareHTTPListenerTestService(t, conf)
			var previous []net.Listener
			calls := 0
			_, err := svc.runListeners(context.Background(), func(bnet.Address) (net.Listener, error) {
				calls++
				if calls == failAt {
					return nil, errors.New("injected input failure")
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err == nil {
					previous = append(previous, listener)
				}
				return listener, err
			})
			require.ErrorContains(t, err, "injected input failure")
			for _, listener := range previous {
				reopened, err := net.Listen("tcp", listener.Addr().String())
				require.NoError(t, err)
				require.NoError(t, reopened.Close())
			}
			require.NoDirExists(t, conf.Http.Tls.Acme.Storage)
		})
	}
}

func TestStoredAcmeAccountCannotReuseAnSshKey(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	// ACME account state is P-256; explicitly allow that SSH key in this test
	// so rejection exercises cross-role separation, not SSH's default >=384 rule.
	conf.Ssh.Keys.EcdsaRestriction = bfcrypto.EcdsaRestrictionAtLeast256Bits
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	paths, err := conf.Ssh.Keys.HostKeys.Render(noopContext{})
	require.NoError(t, err)
	require.NoError(t, bfcrypto.WriteBootstrapFile(paths[0], raw, false))
	base, err := bfcrypto.EnsurePrivateDirectory(conf.Http.Tls.Acme.Storage)
	require.NoError(t, err)
	require.NoError(t, base.Close())
	scope := filepath.Join(conf.Http.Tls.Acme.Storage, fmt.Sprintf("ca-%x", sha256.Sum256([]byte(conf.Http.Tls.Acme.DirectoryUrl))))
	directory, err := bfcrypto.EnsurePrivateDirectory(scope)
	require.NoError(t, err)
	require.NoError(t, directory.Close())
	require.NoError(t, bfcrypto.WriteBootstrapFile(filepath.Join(scope, "account.pem"), raw, false))
	svc := prepareHTTPListenerTestService(t, conf)
	_, err = svc.runListeners(context.Background(), nil)
	require.ErrorContains(t, err, "HTTPS/ACME key must be distinct")
	require.False(t, svc.https.Ready())
}

func TestCanceledServicePreparationReleasesOpenedSessionStorage(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	httpListenerTestCertificate(t, &conf, nil)
	started := make(chan struct{})
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	t.Cleanup(issuer.Close)
	auth := &configuration.AuthorizationOidcDeviceAuth{}
	require.NoError(t, auth.SetDefaults())
	auth.Issuer = template.MustNewUrl(issuer.URL)
	auth.ClientId = template.MustNewString("test")
	auth.ClientSecret = template.MustNewString("test-only")
	conf.Flows[0].Authorization.V = auth
	ctx, cancel := context.WithCancel(coidc.ClientContext(context.Background(), issuer.Client()))
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepareContext(ctx)
		if svc != nil {
			err = errors.Join(err, svc.Close())
		}
		done <- err
	}()
	await := awaitHTTPListenerTestRun(t, done)
	t.Cleanup(func() { cancel(); _ = await() })
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("OIDC preparation did not start")
	}
	storage := conf.Session.V.(*configuration.SessionFs).Storage
	lock := filepath.Join(filepath.Dir(storage), ".sessions.bifroest.lock")
	require.FileExists(t, lock, "late preparation must exercise already-open session state")
	cancel()
	require.ErrorIs(t, await(), context.Canceled)
	require.NoFileExists(t, lock, "failed preparation must release repositories and their locks")
	require.NoDirExists(t, conf.Http.Tls.Acme.Storage)
}

func TestJointListenersServeSshAndHttpsAndStopTogether(t *testing.T) {
	for _, stop := range []string{"cancel", "SSH listener failure", "HTTPS listener failure"} {
		t.Run(stop, func(t *testing.T) {
			conf := httpListenerTestConfiguration(t)
			root := httpListenerTestCertificate(t, &conf, nil)
			svc := prepareHTTPListenerTestService(t, conf)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			bound := make(chan net.Listener, 2)
			done := make(chan error, 1)
			go func() {
				_, err := svc.runListeners(ctx, func(address bnet.Address) (net.Listener, error) {
					listener, err := address.Listen()
					if err == nil {
						bound <- listener
					}
					return listener, err
				})
				done <- err
			}()
			await := awaitHTTPListenerTestRun(t, done)
			t.Cleanup(func() { cancel(); _ = await() })
			sshListener, httpListener := <-bound, <-bound
			pool := x509.NewCertPool()
			pool.AddCert(root)
			transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", httpListener.Addr().String())
			}}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			require.Eventually(t, func() bool {
				response, err := client.Get("https://app.example.org/work")
				if response != nil {
					_ = response.Body.Close()
				}
				return err == nil && response.StatusCode == 501
			}, 5*time.Second, 10*time.Millisecond)
			ssh, err := gossh.Dial("tcp", sshListener.Addr().String(), &gossh.ClientConfig{User: "test", Auth: []gossh.AuthMethod{gossh.Password("")}, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second}) //nolint:gosec // Test-local server.
			require.NoError(t, err)
			require.NoError(t, ssh.Close())
			switch stop {
			case "cancel":
				cancel()
			case "SSH listener failure":
				require.NoError(t, sshListener.Close())
			case "HTTPS listener failure":
				require.NoError(t, httpListener.Close())
			}
			err = await()
			if stop == "cancel" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "listener")
			}
			for _, listener := range []net.Listener{sshListener, httpListener} {
				connection, err := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond)
				if connection != nil {
					_ = connection.Close()
				}
				require.Error(t, err)
			}
		})
	}
}

type httpListenerTestSource struct {
	started chan struct{}
	proof   *tls.Certificate
}

func (this httpListenerTestSource) Certificate(ctx context.Context, _ string, publish https.Challenge) (*tls.Certificate, error) {
	release, err := publish(this.proof)
	if err != nil {
		return nil, err
	}
	defer release()
	close(this.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (this httpListenerTestSource) Renew(ctx context.Context, domain string, publish https.Challenge) (*tls.Certificate, error) {
	return this.Certificate(ctx, domain, publish)
}

func TestJointStartupAllowsOnlyAcmeProofsAndCancelsBothInputs(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			conf := httpListenerTestConfiguration(t)
			conf.Http.StartupTimeout = common.DurationOf(time.Second)
			svc := prepareHTTPListenerTestService(t, conf)
			require.NoError(t, svc.https.Close())
			account, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEcdsa}).GenerateKey(nil)
			require.NoError(t, err)
			client := &acme.Client{Key: account.ToSdk()}
			proof, err := client.TLSALPN01ChallengeCert("test-token", "app.example.org")
			require.NoError(t, err)
			source := httpListenerTestSource{started: make(chan struct{}), proof: &proof}
			svc.https, err = https.NewEndpoint(conf.Http, https.EndpointOptions{Source: source})
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			bound := make(chan net.Listener, 2)
			done := make(chan error, 1)
			go func() {
				_, err := svc.runListeners(ctx, func(address bnet.Address) (net.Listener, error) {
					listener, err := address.Listen()
					if err == nil {
						bound <- listener
					}
					return listener, err
				})
				done <- err
			}()
			await := awaitHTTPListenerTestRun(t, done)
			t.Cleanup(func() { cancel(); _ = await() })
			sshListener, httpListener := <-bound, <-bound
			select {
			case <-source.started:
			case <-time.After(5 * time.Second):
				t.Fatal("proof was not installed")
			}
			probe, err := (&tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "app.example.org", NextProtos: []string{acme.ALPNProto}, InsecureSkipVerify: true}}).DialContext(context.Background(), "tcp", httpListener.Addr().String()) //nolint:gosec // Local self-signed ACME proof.
			require.NoError(t, err)
			require.Equal(t, acme.ALPNProto, probe.(*tls.Conn).ConnectionState().NegotiatedProtocol)
			require.NoError(t, probe.Close())
			_, err = (&tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "app.example.org", InsecureSkipVerify: true}}).DialContext(context.Background(), "tcp", httpListener.Addr().String()) //nolint:gosec // Handshake must fail before readiness.
			require.Error(t, err)
			ssh, err := net.DialTimeout("tcp", sshListener.Addr().String(), time.Second)
			require.NoError(t, err)
			require.NoError(t, ssh.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
			var banner [1]byte
			_, err = ssh.Read(banner[:])
			require.Error(t, err, "SSH must not serve before all certificates are ready")
			require.NoError(t, ssh.Close())
			if mode == "cancel" {
				cancel()
			}
			err = await()
			if mode == "cancel" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			require.False(t, svc.https.Ready())
		})
	}
}
