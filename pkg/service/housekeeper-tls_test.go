package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/transporttls"
)

type housekeepingTLSSource struct {
	initial, fresh  *tls.Certificate
	issued, renewed atomic.Int32
	renew           func(context.Context, string, transporttls.Challenge) (*tls.Certificate, error)
}

func (this *housekeepingTLSSource) Certificate(context.Context, string, transporttls.Challenge) (*tls.Certificate, error) {
	this.issued.Add(1)
	return this.initial, nil
}

func (this *housekeepingTLSSource) Renew(ctx context.Context, name string, publish transporttls.Challenge) (*tls.Certificate, error) {
	this.renewed.Add(1)
	if this.renew != nil {
		return this.renew(ctx, name, publish)
	}
	return this.fresh, nil
}

func housekeepingTLSCertificate(t *testing.T, serial int64, before, after time.Time) *tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "housekeeping TLS test"},
		DNSNames: []string{"app.example.org"}, NotBefore: before, NotAfter: after,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	require.NoError(t, err)
	return &tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: private}
}

func newHousekeepingTLSManager(t *testing.T, timeout time.Duration) (*transporttls.TLS, *housekeepingTLSSource) {
	t.Helper()
	now := time.Now()
	source := &housekeepingTLSSource{
		initial: housekeepingTLSCertificate(t, 1, now.Add(-48*time.Hour), now.Add(time.Hour)),
		fresh:   housekeepingTLSCertificate(t, 2, now.Add(-time.Minute), now.Add(90*24*time.Hour)),
	}
	automation := &configuration.TlsAcme{}
	require.NoError(t, automation.SetDefaults())
	automation.AcceptTerms, automation.Storage = true, t.TempDir()
	manager, err := transporttls.New(transporttls.Config{
		Profile: configuration.Tls{Acme: automation}, Names: configuration.ServerNames{"app.example.org"},
		StartupTimeout: timeout,
	}, source)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	return manager, source
}

func TestHouseKeeperRenewsEachTLSManagerOnlyAfterListenerStartup(t *testing.T) {
	manager, source := newHousekeepingTLSManager(t, time.Second)
	require.False(t, manager.HasFileCertificates())
	hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, nil)
	hk.service.tlsManagers = map[string]*transporttls.TLS{"tls:shared": manager}
	hk.service.tlsSourceNames = []string{"tls:shared"}
	require.NoError(t, hk.run(hk.logger(), t.Context()))
	require.Zero(t, source.issued.Load(), "initial housekeeping must not issue certificates")
	require.Zero(t, source.renewed.Load())
	require.NoError(t, manager.Prepare(t.Context()))
	require.NoError(t, hk.run(hk.logger(), t.Context()))
	require.Zero(t, source.renewed.Load(), "preparation alone does not activate listener maintenance")
	hk.startTLSRenewal(t.Context())
	require.NoError(t, hk.run(hk.logger(), t.Context()))
	require.EqualValues(t, 1, source.renewed.Load())
	require.True(t, manager.Ready())
	require.NoError(t, hk.run(hk.logger(), t.Context()))
	require.EqualValues(t, 1, source.renewed.Load(), "frequent housekeeping must not renew before due")
}

func TestHouseKeeperTLSFailuresKeepOtherSourcesAndCleanupRunning(t *testing.T) {
	for _, failure := range []string{"CA rate limit", "timeout"} {
		t.Run(failure, func(t *testing.T) {
			first, failing := newHousekeepingTLSManager(t, 50*time.Millisecond)
			second, succeeding := newHousekeepingTLSManager(t, time.Second)
			if failure == "timeout" {
				failing.renew = func(ctx context.Context, _ string, _ transporttls.Challenge) (*tls.Certificate, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
			} else {
				failing.renew = func(context.Context, string, transporttls.Challenge) (*tls.Certificate, error) {
					return nil, &acme.Error{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"7200"}}}
				}
			}
			require.NoError(t, first.Prepare(t.Context()))
			require.NoError(t, second.Prepare(t.Context()))
			injected := errors.New("session inspection failed")
			repository := &houseKeeperTestSessionRepository{findAll: func(context.Context, session.Consumer, *session.FindOpts) error {
				return injected
			}}
			hk := newHouseKeeperForTest(repository, nil)
			hk.service.tlsManagers = map[string]*transporttls.TLS{"tls:first": first, "tls:second": second}
			hk.service.tlsSourceNames = []string{"tls:first", "tls:second"}
			var conf configuration.Configuration
			require.NoError(t, conf.SetDefaults())
			conf.Monitoring = &configuration.Monitoring{}
			require.NoError(t, conf.Monitoring.SetDefaults())
			conf.Monitoring.Enabled = true
			monitor, err := newServiceMonitoring(conf)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, monitor.endpoint.Close()) })
			hk.service.monitoring = monitor
			hk.service.Configuration.Http = &configuration.Http{
				Enabled: configuration.HttpEnabled, Tls: &configuration.Tls{Reference: "first"},
			}
			hk.startTLSRenewal(t.Context())
			_, err = hk.checkedRun(t.Context())
			require.ErrorIs(t, err, injected)
			require.ErrorContains(t, err, `TLS source "tls:first" renewal`)
			require.NotNil(t, repository.findAllOpts)
			require.EqualValues(t, 1, failing.renewed.Load())
			require.EqualValues(t, 1, succeeding.renewed.Load())
			require.True(t, first.Ready(), "failed renewal must retain still-valid material")
			require.Equal(t, float64(1), testutil.ToFloat64(monitor.tlsRenewalErrors.WithLabelValues("tls:first")))
			require.Equal(t, float64(1), testutil.ToFloat64(monitor.http.renewalErrors))
			require.Zero(t, testutil.ToFloat64(monitor.tlsRenewalErrors.WithLabelValues("tls:second")))
			_, _ = hk.checkedRun(t.Context())
			require.EqualValues(t, 1, failing.renewed.Load(), "housekeeping must honor the TLS retry backoff")
			require.EqualValues(t, 1, succeeding.renewed.Load())
		})
	}
}

func TestHouseKeeperRenewsExpiredTLSMaterial(t *testing.T) {
	manager, source := newHousekeepingTLSManager(t, time.Second)
	now := time.Now()
	source.initial = housekeepingTLSCertificate(t, 3, now.Add(-time.Hour), now.Add(time.Second))
	require.NoError(t, manager.Prepare(t.Context()))
	require.Eventually(t, func() bool { return !manager.Ready() }, 2*time.Second, 10*time.Millisecond)
	hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, nil)
	hk.service.tlsManagers = map[string]*transporttls.TLS{"http": manager}
	hk.service.tlsSourceNames = []string{"http"}
	hk.startTLSRenewal(t.Context())
	require.NoError(t, hk.run(hk.logger(), t.Context()))
	require.EqualValues(t, 1, source.renewed.Load(), "expired readiness must not prevent renewal")
	require.True(t, manager.Ready())
}

func TestHouseKeeperTLSRenewalStopsWithItsOwner(t *testing.T) {
	for _, owner := range []string{"listeners", "housekeeping"} {
		t.Run(owner, func(t *testing.T) {
			manager, source := newHousekeepingTLSManager(t, 5*time.Second)
			require.NoError(t, manager.Prepare(t.Context()))
			started, stopped := make(chan struct{}), make(chan struct{})
			source.renew = func(ctx context.Context, _ string, _ transporttls.Challenge) (*tls.Certificate, error) {
				close(started)
				defer close(stopped)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			hk := newHouseKeeperForTest(&houseKeeperTestSessionRepository{}, nil)
			hk.service.tlsManagers = map[string]*transporttls.TLS{"http": manager}
			hk.service.tlsSourceNames = []string{"http"}
			hk.service.Configuration.HouseKeeping.Every.SetNative(time.Millisecond)
			require.NoError(t, hk.init(hk.service))
			t.Cleanup(func() { require.NoError(t, hk.Close()) })
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			hk.startTLSRenewal(ctx)
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("housekeeping did not start the due renewal")
			}
			if owner == "listeners" {
				cancel()
			} else {
				require.NoError(t, hk.Close())
			}
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("housekeeping renewal survived its owner's cancellation")
			}
		})
	}
}

func TestListenerStartupEnablesHousekeepingRenewalAndShutdownDrainsIt(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	conf.HouseKeeping.Every.SetNative(5 * time.Millisecond)
	svc := prepareHTTPListenerTestService(t, conf)
	require.NoError(t, svc.https.Close())
	require.NoError(t, svc.closeTLS())
	manager, source := newHousekeepingTLSManager(t, 5*time.Second)
	svc.tlsManagers["http"] = manager
	binding, err := manager.Bind(conf.Http.Domains, []string{"h2", "http/1.1"}, false)
	require.NoError(t, err)
	svc.tlsBindings["http"] = binding
	svc.tlsChallenges = transporttls.Registry{}
	require.NoError(t, svc.tlsChallenges.Register(manager))
	svc.https, err = https.NewEndpoint(conf.Http, https.EndpointOptions{Binding: binding, Challenges: &svc.tlsChallenges})
	require.NoError(t, err)
	started, stopped := make(chan struct{}), make(chan struct{})
	source.renew = func(ctx context.Context, _ string, _ transporttls.Challenge) (*tls.Certificate, error) {
		close(started)
		defer close(stopped)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := svc.runListeners(ctx, nil); done <- err }()
	await := awaitHTTPListenerTestRun(t, done)
	t.Cleanup(func() { cancel(); _ = await() })
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("running listeners did not activate housekeeping renewal")
	}
	cancel()
	require.NoError(t, await())
	select {
	case <-stopped:
	default:
		t.Fatal("listener shutdown did not drain the active housekeeping renewal")
	}
}
