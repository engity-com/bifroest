package https

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestACMEActiveRequestsStopOnCancellationTimeoutOrClose(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout", "source close", "TLS close"} {
		t.Run(mode, func(t *testing.T) {
			clock := newACMETestClock()
			ca := newACMETestCA(t, clock)
			conf, source, manager := newACMETestSource(t, ca, "app.example.org")
			ca.mutex.Lock()
			ca.hangOrders = true
			ca.orderStarted = make(chan struct{}, 1)
			started := ca.orderStarted
			ca.mutex.Unlock()
			if mode == "timeout" {
				source.timeout = 500 * time.Millisecond
				manager.startupTimeout = 750 * time.Millisecond
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- manager.Prepare(ctx) }()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("CA did not receive the order")
			}
			switch mode {
			case "cancel":
				cancel()
			case "source close":
				require.NoError(t, source.Close())
			case "TLS close":
				require.NoError(t, manager.Close())
			}
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("ACME request did not stop")
			}
			require.False(t, manager.Ready())
			_, err := manager.Config().GetConfigForClient(testClientHello("app.example.org", "acme-tls/1"))
			require.Error(t, err)
			_, err = os.Stat(filepath.Join(source.store.path, certificateStateName(conf.Domains[0])))
			require.True(t, os.IsNotExist(err), "aborted issuance must not create a cached certificate")
		})
	}
}

func TestACMECancellationReleasesAnActiveChallenge(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, _, manager := newACMETestSource(t, ca, "app.example.org")
	ca.mutex.Lock()
	ca.hangChallenge = true
	ca.challengeStarted = make(chan struct{}, 1)
	started := ca.challengeStarted
	ca.mutex.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- manager.Prepare(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("CA did not receive the active challenge")
	}
	_, err := manager.Config().GetConfigForClient(testClientHello("app.example.org", acme.ALPNProto))
	require.NoError(t, err, "proof must be available until validation finishes")
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.ErrorIs(t, err, ErrNotReady)
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("active challenge did not stop")
	}
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", acme.ALPNProto))
	require.Error(t, err, "canceled proof must not remain available")
}

func TestACMEAutomaticRenewalLoopIsCallerOwnedAndCancellable(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, _, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	before, err := manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.NoError(t, err)
	clock.advance(61 * 24 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- manager.RunRenewal(ctx, nil) }()
	require.Eventually(t, func() bool {
		after, err := manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
		return err == nil && after.Certificates[0].Leaf.SerialNumber.Cmp(before.Certificates[0].Leaf.SerialNumber) != 0
	}, 5*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("renewal loop did not stop")
	}
	require.True(t, manager.Ready(), "stopping the loop does not dispose current certificates or authenticated connections")
}

func TestACMECacheCorruptionNeverCausesSilentReplacementOrCaTraffic(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	path := filepath.Join(source.store.path, certificateStateName("app.example.org"))
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, data := range [][]byte{[]byte("private-material-not-for-logs"), append(append([]byte(nil), original...), []byte("trailing garbage")...)} {
		require.NoError(t, os.WriteFile(path, data, 0600))
		ca.mutex.Lock()
		requests := ca.requests
		ca.mutex.Unlock()
		_, err := source.Certificate(context.Background(), "app.example.org", nil)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "private-material-not-for-logs")
		ca.mutex.Lock()
		after := ca.requests
		ca.mutex.Unlock()
		require.Equal(t, requests, after)
		stored, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, data, stored)
	}
}

func TestACMEStorageIsScopedToTheDirectoryAndRejectsReplacedDirectories(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	conf, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	other := *conf
	other.Tls.Acme.DirectoryUrl += "/different-ca"
	separate, err := newACME(&other, ca.server.Client(), clock.now)
	require.NoError(t, err)
	defer separate.Close()
	require.NotEqual(t, source.store.path, separate.store.path)
	_, err = separate.Certificate(context.Background(), "app.example.org", nil)
	require.ErrorContains(t, err, "challenge publisher")
	path := source.store.path
	renameErr := os.Rename(path, path+".moved")
	// Windows may enforce the anchor directly: EnsurePrivateDirectory's open
	// handle denies deletion/rename. Accept only that exact native error, not an
	// arbitrary permission or I/O failure, and prove the original store still works.
	const windowsSharingViolation = syscall.Errno(32) // ERROR_SHARING_VIOLATION
	if runtime.GOOS == "windows" && errors.Is(renameErr, windowsSharingViolation) {
		require.DirExists(t, path)
		require.NoDirExists(t, path+".moved")
		require.NoError(t, source.store.check())
		_, err = source.Certificate(context.Background(), "app.example.org", nil)
		require.NoError(t, err)
		return
	}
	require.NoError(t, renameErr)
	require.NoError(t, os.Mkdir(path, 0700))
	_, err = source.Certificate(context.Background(), "app.example.org", nil)
	require.ErrorContains(t, err, "replaced")
}

func TestACMERenewalTimeoutHasBackoffAndPreservesExistingReadiness(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	clock.advance(61 * 24 * time.Hour)
	ca.mutex.Lock()
	ca.hangOrders = true
	ca.mutex.Unlock()
	manager.startupTimeout = 100 * time.Millisecond
	source.timeout = time.Second
	require.Error(t, manager.RenewDue(context.Background()))
	require.True(t, manager.Ready())
	manager.mutex.RLock()
	retry := manager.renewRetry["app.example.org"]
	manager.mutex.RUnlock()
	require.Equal(t, clock.now().Add(30*time.Minute), retry)
}

func TestACMERenewalServesTheExistingCertificateDuringValidation(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, _, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	before, err := manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.NoError(t, err)
	clock.advance(61 * 24 * time.Hour)
	ca.mutex.Lock()
	ca.hangChallenge = true
	ca.challengeStarted = make(chan struct{}, 1)
	started := ca.challengeStarted
	ca.mutex.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- manager.RenewDue(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("CA did not start renewal validation")
	}
	_, err = manager.Config().GetConfigForClient(testClientHello("app.example.org", acme.ALPNProto))
	require.NoError(t, err)
	_, clientErr, serverErr := testTlsHandshake(t, manager.Config(), &tls.Config{
		ServerName: "app.example.org", MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, //nolint:gosec // Certificate identity and snapshot are checked explicitly below.
	})
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)
	after, err := manager.Config().GetConfigForClient(testClientHello("app.example.org", "h2"))
	require.NoError(t, err)
	require.Equal(t, before.Certificates[0].Certificate, after.Certificates[0].Certificate)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("renewal did not stop")
	}
	require.True(t, manager.Ready())
}

func TestACMEHttpDowngradesAndOversizedBodiesAreRejected(t *testing.T) {
	transport := httpsOnlyTransport{http.DefaultTransport}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/forbidden", nil)
	require.NoError(t, err)
	_, err = transport.RoundTrip(request)
	require.ErrorContains(t, err, "HTTPS")
	body := &boundedACMEBody{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", 11))), remaining: 10}
	_, err = io.ReadAll(body)
	require.ErrorContains(t, err, "size limit")
	exact := &boundedACMEBody{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", 10))), remaining: 10}
	value, err := io.ReadAll(exact)
	require.NoError(t, err)
	require.Len(t, value, 10)
}

func TestACMEDisabledSourceCreatesNoStorage(t *testing.T) {
	conf := newTlsTestConfiguration(t, "app.example.org")
	conf.Tls.Acme.Enabled = false
	conf.StartupTimeout = common.DurationOf(time.Second)
	conf.Tls.Certificates = []configuration.HttpCertificate{{CertificateFile: "unused", PrivateKeyFile: "unused"}}
	conf.Tls.Acme.Storage = filepath.Join(t.TempDir(), "not-created")
	_, err := NewACME(conf)
	require.ErrorContains(t, err, "disabled")
	_, err = os.Stat(conf.Tls.Acme.Storage)
	require.True(t, os.IsNotExist(err))
}
