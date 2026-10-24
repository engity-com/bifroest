package https

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func newACMETestSource(t *testing.T, ca *acmeTestCA, domains ...string) (*configuration.Http, *ACME, *TLS) {
	t.Helper()
	conf := newTlsTestConfiguration(t, domains...)
	conf.Tls.Acme.Storage = filepath.Join(t.TempDir(), "acme")
	conf.Tls.Acme.DirectoryUrl = ca.server.URL + "/directory"
	conf.StartupTimeout = common.DurationOf(5 * time.Second)
	source, err := newACME(conf, ca.server.Client(), ca.clock.now)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, source.Close()) })
	manager, err := newTLS(conf, source, ca.clock.now)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	ca.setProbe(startACMETestTLS(t, manager))
	return conf, source, manager
}

func TestACMEIssuesAndPersistsMultipleDomainsWithRealTlsAlpnProofs(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	conf, source, manager := newACMETestSource(t, ca, "first.example.org", "second.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	require.True(t, manager.Ready())
	counts := ca.counts()
	require.Equal(t, 1, counts.registrations)
	require.Equal(t, 2, counts.issues)
	require.Equal(t, 2, counts.proofs)
	requests := counts.requests
	for _, domain := range conf.Domains {
		cached, err := source.Certificate(context.Background(), domain, nil)
		require.NoError(t, err)
		require.True(t, certificateMatches(cached, domain))
		client := &tls.Config{ServerName: domain, RootCAs: x509.NewCertPool(), Time: clock.now, MinVersion: tls.VersionTLS12}
		client.RootCAs.AddCert(ca.root)
		_, clientErr, serverErr := testTlsHandshake(t, manager.Config(), client)
		require.NoError(t, clientErr)
		require.NoError(t, serverErr)
		_, err = manager.Config().GetConfigForClient(testClientHello(domain, acme.ALPNProto))
		require.Error(t, err, "proofs must not remain after issuance")
	}
	require.NoError(t, source.Close())
	ca.server.Close()
	restarted, err := newACME(conf, ca.server.Client(), clock.now)
	require.NoError(t, err)
	defer restarted.Close()
	restartedTLS, err := newTLS(conf, restarted, clock.now)
	require.NoError(t, err)
	defer restartedTLS.Close()
	require.NoError(t, restartedTLS.Prepare(context.Background()))
	require.True(t, restartedTLS.Ready())
	for _, domain := range conf.Domains {
		_, err := restarted.Certificate(context.Background(), domain, nil)
		require.NoError(t, err)
	}
	require.Equal(t, requests, ca.counts().requests, "valid cached certificates must work with the CA offline on restart")
}

func TestACMERenewalUpdatesSnapshotAndReusesAccount(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	before, err := manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.NoError(t, err)
	account, err := source.store.read("account.pem")
	require.NoError(t, err)
	clock.advance(61 * 24 * time.Hour)
	require.NoError(t, manager.RenewDue(context.Background()))
	after, err := manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.NoError(t, err)
	require.NotEqual(t, before.Certificates[0].Certificate, after.Certificates[0].Certificate)
	storedAccount, err := source.store.read("account.pem")
	require.NoError(t, err)
	require.Equal(t, account, storedAccount, "renewal must not rotate or replace the ACME account")
	counts := ca.counts()
	require.Equal(t, 2, counts.issues)
	require.Equal(t, 1, counts.registrations)
	requests := counts.requests
	require.NoError(t, manager.RenewDue(context.Background()))
	require.Equal(t, requests, ca.counts().requests, "fresh material must not be renewed repeatedly")
}

func TestACMEFailureKeepsValidCertificateAndHonorsRetryAfter(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	before, err := source.store.read(certificateStateName("app.example.org"))
	require.NoError(t, err)
	clock.advance(61 * 24 * time.Hour)
	ca.mutex.Lock()
	ca.failOrders = true
	ca.mutex.Unlock()
	err = manager.RenewDue(context.Background())
	require.Error(t, err)
	var problem *acme.Error
	require.True(t, errors.As(err, &problem))
	require.Equal(t, 429, problem.StatusCode)
	require.True(t, manager.Ready())
	after, err := source.store.read(certificateStateName("app.example.org"))
	require.NoError(t, err)
	require.Equal(t, before, after)
	manager.mutex.RLock()
	retry := manager.renewRetry["app.example.org"]
	manager.mutex.RUnlock()
	require.Equal(t, clock.now().Add(2*time.Hour), retry)
	requests := ca.counts().requests
	require.NoError(t, manager.RenewDue(context.Background()))
	require.Equal(t, requests, ca.counts().requests)
}

func TestACMERestrictsDomainsChallengesAndOrderIdentifiers(t *testing.T) {
	for _, mode := range []string{"unknown domain", "wrong identifier", "wrong issued domain", "HTTP-only challenge"} {
		t.Run(mode, func(t *testing.T) {
			clock := newACMETestClock()
			ca := newACMETestCA(t, clock)
			_, source, manager := newACMETestSource(t, ca, "app.example.org")
			switch mode {
			case "unknown domain":
				_, err := source.Certificate(context.Background(), "other.example.org", nil)
				require.ErrorContains(t, err, "not configured")
				require.Zero(t, ca.counts().requests)
			case "wrong identifier":
				ca.mutex.Lock()
				ca.wrongIdentifier = true
				ca.mutex.Unlock()
				require.ErrorContains(t, manager.Prepare(context.Background()), "identifiers")
			case "HTTP-only challenge":
				ca.mutex.Lock()
				ca.httpOnly = true
				ca.mutex.Unlock()
				require.ErrorContains(t, manager.Prepare(context.Background()), "no TLS-ALPN-01")
			case "wrong issued domain":
				ca.mutex.Lock()
				ca.wrongIssuedDomain = true
				ca.mutex.Unlock()
				require.ErrorContains(t, manager.Prepare(context.Background()), "identifiers differ")
			}
			require.False(t, manager.Ready())
			if mode != "wrong issued domain" {
				require.Zero(t, ca.counts().issues)
			}
		})
	}
}

func TestACMESecondDomainFailureCannotPublishPartialReadiness(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, _, manager := newACMETestSource(t, ca, "first.example.org", "second.example.org")
	ca.mutex.Lock()
	ca.failDomain = "second.example.org"
	ca.mutex.Unlock()
	require.Error(t, manager.Prepare(context.Background()))
	require.False(t, manager.Ready())
	require.Equal(t, 1, ca.counts().issues)
	_, err := manager.Config().GetConfigForClient(testClientHello("first.example.org", "h2"))
	require.ErrorIs(t, err, ErrNotReady)
	ca.mutex.Lock()
	ca.failDomain = ""
	ca.mutex.Unlock()
	require.NoError(t, manager.Prepare(context.Background()))
	require.True(t, manager.Ready())
	require.Equal(t, 2, ca.counts().issues, "retry reuses the first domain's persisted certificate")
}

func TestACMEMissingAccountIsNotReplacedDuringRenewal(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	conf, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	path := source.store.path
	require.NoError(t, source.Close())
	require.NoError(t, os.Remove(filepath.Join(path, "account.pem")))
	restarted, err := newACME(conf, ca.server.Client(), clock.now)
	require.NoError(t, err)
	defer restarted.Close()
	_, err = restarted.Certificate(context.Background(), "app.example.org", nil)
	require.NoError(t, err, "valid cached material remains usable without registration")
	clock.advance(61 * 24 * time.Hour)
	_, err = restarted.Renew(context.Background(), "app.example.org", func(*tls.Certificate) (func(), error) { return func() {}, nil })
	require.ErrorContains(t, err, "account key is missing")
	_, err = os.Stat(filepath.Join(path, "account.pem"))
	require.True(t, os.IsNotExist(err))
}

func TestACMEStaleIssuanceCannotOverwriteAGoodCachedCertificate(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	before, err := source.store.read(certificateStateName("app.example.org"))
	require.NoError(t, err)
	clock.advance(61 * 24 * time.Hour)
	ca.mutex.Lock()
	ca.staleIssuedCertificate = true
	ca.mutex.Unlock()
	require.ErrorContains(t, manager.RenewDue(context.Background()), "already requires renewal")
	after, err := source.store.read(certificateStateName("app.example.org"))
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.True(t, manager.Ready())
}

func TestACMEExpiredCacheIsReissuedAfterRestartUsingTheSameAccount(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	conf, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	account, err := source.store.read("account.pem")
	require.NoError(t, err)
	require.NoError(t, source.Close())
	clock.advance(91 * 24 * time.Hour)
	require.False(t, manager.Ready())
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.ErrorContains(t, err, "no longer valid")
	restarted, err := newACME(conf, ca.server.Client(), clock.now)
	require.NoError(t, err)
	defer restarted.Close()
	newManager, err := newTLS(conf, restarted, clock.now)
	require.NoError(t, err)
	defer newManager.Close()
	ca.setProbe(startACMETestTLS(t, newManager))
	require.NoError(t, newManager.Prepare(context.Background()))
	require.True(t, newManager.Ready())
	storedAccount, err := restarted.store.read("account.pem")
	require.NoError(t, err)
	require.Equal(t, account, storedAccount)
	counts := ca.counts()
	require.Equal(t, 1, counts.registrations)
	require.Equal(t, 2, counts.issues)
}

func TestACMEChangedAccountKeyCannotSilentlyReplaceTheActiveAccount(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	path := filepath.Join(source.store.path, "account.pem")
	other, err := openACMEStore(filepath.Join(t.TempDir(), "other"), ca.server.URL+"/directory")
	require.NoError(t, err)
	defer other.close()
	_, err = other.accountKey(context.Background())
	require.NoError(t, err)
	key, err := other.read("account.pem")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, key, 0600))
	requests := ca.counts().requests
	clock.advance(61 * 24 * time.Hour)
	require.ErrorContains(t, manager.RenewDue(context.Background()), "account key changed")
	require.Equal(t, requests, ca.counts().requests, "changed account state must fail before any CA requests")
	stored, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, key, stored, "foreign state must not be overwritten")
	require.True(t, manager.Ready())
}
