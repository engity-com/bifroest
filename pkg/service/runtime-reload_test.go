package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	logrecording "github.com/echocat/slf4g/testing/recording"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/template"
)

func runtimeReloadFixture(t *testing.T, ctx context.Context, watch bool, modes ...configuration.WatchMode) (*service, configuration.Configuration) {
	t.Helper()
	root := t.TempDir()
	conf := sessionRecordingTestConfiguration(t, filepath.Join(root, "state"))
	conf.HouseKeeping.InitialDelay = common.DurationOf(time.Hour)
	conf.Flows[0].Authorization.V = &configuration.AuthorizationSimple{
		Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}},
	}
	conf.Monitoring = &configuration.Monitoring{}
	require.NoError(t, conf.Monitoring.SetDefaults())
	conf.Monitoring.Enabled = true
	conf.Monitoring.Addresses = conf.Ssh.Addresses
	conf.Filename = filepath.Join(root, "source", "configuration.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(conf.Filename), 0700))
	runtimeReloadWrite(t, conf)
	var loaded configuration.Configuration
	require.NoError(t, loaded.LoadFromFile(conf.Filename))
	conf = loaded
	monitor, err := newServiceMonitoring(conf, true)
	require.NoError(t, err)
	monitor.reload.enabled.Set(monitoringBool(watch))
	mode := configuration.WatchModeOff
	if watch {
		mode = configuration.WatchModePreserve
	}
	if len(modes) > 0 {
		mode = modes[0]
	}
	svc, err := (&Service{Configuration: conf, Watch: mode, Version: serviceTestVersion{}}).prepareContextWithMonitoring(ctx, monitor)
	require.NoError(t, err)
	svc.configurationWatchOptions.Debounce = 10 * time.Millisecond
	svc.configurationWatchOptions.PollInterval = 40 * time.Millisecond
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	return svc, conf
}

func TestRuntimeReloadModesKeepConnectionsAndSelectSessionReuse(t *testing.T) {
	for _, mode := range []configuration.WatchMode{configuration.WatchModePreserve, configuration.WatchModeReconnect, configuration.WatchModeReuse} {
		t.Run(mode.String(), func(t *testing.T) {
			svc, conf := runtimeReloadFixture(t, t.Context(), true, mode)
			run := runtimeListenerTestStart(t, svc, nil)
			_, listener := run.scope(t, "SSH", conf.Ssh.Addresses[0].String(), 0)
			old := runtimeSshDial(t, svc, listener.Addr().String(), "correct")
			previous := runtimeSshConnection(t, svc, old)
			sessionID := runtimeSshSession(previous).Id()
			runtimeSshRun(t, old, 0)
			conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(17)
			conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
			runtimeReloadWrite(t, conf)
			runtimeReloadAwaitPassword(t, svc, "changed")
			denied, err := gossh.Dial("tcp", listener.Addr().String(), runtimeSshConfig(svc, "correct"))
			if denied != nil {
				_ = denied.Close()
			}
			require.Error(t, err, "reuse must not bypass today's primary credentials")
			if mode == configuration.WatchModeReconnect {
				require.Eventually(t, previous.IsClosed, 3*time.Second, time.Millisecond)
			} else {
				runtimeSshRun(t, old, 0)
			}
			fresh := runtimeSshDial(t, svc, listener.Addr().String(), "changed")
			current := runtimeSshSession(runtimeSshConnection(t, svc, fresh))
			if mode == configuration.WatchModeReuse {
				require.Equal(t, sessionID, current.Id())
				require.Same(t, svc.generation, svc.runtime.sessionOwner(current))
			} else {
				require.NotEqual(t, sessionID, current.Id())
			}
			if mode == configuration.WatchModeReuse {
				runtimeSshRun(t, fresh, 0)
				for _, conn := range svc.runtime.revokeSession(current.Flow(), current.Id()) {
					require.NoError(t, conn.Close())
				}
				replacement := runtimeSshDial(t, svc, listener.Addr().String(), "changed")
				require.NotEqual(t, sessionID, runtimeSshSession(runtimeSshConnection(t, svc, replacement)).Id())
				runtimeSshRun(t, replacement, 17)
			} else {
				runtimeSshRun(t, fresh, 17)
			}
		})
	}
}

func runtimeReloadWrite(t *testing.T, conf configuration.Configuration) {
	t.Helper()
	raw, err := yaml.Marshal(conf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(conf.Filename, raw, 0600))
}

func runtimeReloadAwaitPassword(t *testing.T, svc *service, password string) {
	t.Helper()
	require.Eventually(t, func() bool {
		conf := svc.configurationReloader.Current().Configuration()
		return string(conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password) == "plain:"+password
	}, 5*time.Second, time.Millisecond)
}

func TestRuntimeReloadWatchIsOptInAndExistingSSHConnectionsKeepTheirGeneration(t *testing.T) {
	for _, watch := range []bool{false, true} {
		t.Run(fmt.Sprint(watch), func(t *testing.T) {
			svc, conf := runtimeReloadFixture(t, t.Context(), watch)
			run := runtimeListenerTestStart(t, svc, nil)
			_, listener := run.scope(t, "SSH", conf.Ssh.Addresses[0].String(), 0)
			old := runtimeSshDial(t, svc, listener.Addr().String(), "correct")
			conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
			conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(17)
			runtimeReloadWrite(t, conf)
			if watch {
				runtimeReloadAwaitPassword(t, svc, "changed")
				denied, err := gossh.Dial("tcp", listener.Addr().String(), runtimeSshConfig(svc, "correct"))
				require.Error(t, err)
				if denied != nil {
					_ = denied.Close()
				}
				runtimeSshRun(t, runtimeSshDial(t, svc, listener.Addr().String(), "changed"), 17)
			} else {
				require.Nil(t, svc.configurationReloader)
				require.Never(t, func() bool {
					svc.runtime.mutex.Lock()
					defer svc.runtime.mutex.Unlock()
					return svc.runtime.current != svc.generation
				}, 120*time.Millisecond, 10*time.Millisecond)
				runtimeSshRun(t, runtimeSshDial(t, svc, listener.Addr().String(), "correct"), 0)
			}
			runtimeSshRun(t, old, 0)
		})
	}
}

func TestRuntimeReloadRejectsInvalidAndRestartChangesWithoutLoggingSecretsAndRecovers(t *testing.T) {
	svc, conf := runtimeReloadFixture(t, t.Context(), true)
	logs := logrecording.NewProvider()
	svc.Logger = logs.GetLogger("reload-test")
	run := runtimeListenerTestStart(t, svc, nil)
	_, listener := run.scope(t, "SSH", conf.Ssh.Addresses[0].String(), 0)
	const secret = "PRIVATE-RELOAD-SECRET"
	for _, mode := range []string{"parse", "restart"} {
		before := testutil.ToFloat64(svc.monitoring.reload.attempts.WithLabelValues("rejected"))
		if mode == "parse" {
			require.NoError(t, os.WriteFile(conf.Filename, []byte("unknown-"+secret+": true\n"), 0600))
		} else {
			next := conf
			next.HouseKeeping.Every = common.DurationOf(time.Minute)
			runtimeReloadWrite(t, next)
		}
		require.Eventually(t, func() bool {
			return testutil.ToFloat64(svc.monitoring.reload.attempts.WithLabelValues("rejected")) > before
		}, 5*time.Second, time.Millisecond)
		runtimeSshRun(t, runtimeSshDial(t, svc, listener.Addr().String(), "correct"), 0)
	}
	require.NotContains(t, fmt.Sprint(logs.GetAll()), secret)
	require.Contains(t, fmt.Sprint(logs.GetAll()), "restart_required")
	conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:recovered")
	runtimeReloadWrite(t, conf)
	runtimeReloadAwaitPassword(t, svc, "recovered")
	runtimeSshRun(t, runtimeSshDial(t, svc, listener.Addr().String(), "recovered"), 0)
	require.Equal(t, 1.0, testutil.ToFloat64(svc.monitoring.reload.enabled))
}

func TestRuntimeReloadNativeSetupFailurePreventsStartup(t *testing.T) {
	svc, conf := runtimeReloadFixture(t, t.Context(), true)
	require.NoError(t, os.Rename(filepath.Dir(conf.Filename), filepath.Dir(conf.Filename)+".away"))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err := svc.runListeners(ctx, nil)
	require.ErrorContains(t, err, "configuration watch")
}

func TestRuntimeReloadBindFailureRetainsWholeCandidateAndPollingRetries(t *testing.T) {
	svc, conf := runtimeReloadFixture(t, t.Context(), true)
	run := runtimeListenerTestStart(t, svc, nil)
	_, original := run.scope(t, "SSH", conf.Ssh.Addresses[0].String(), 0)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()
	address := occupied.Addr().String()
	before, err := svc.runtime.persistence.repository.RuntimeState(t.Context())
	require.NoError(t, err)
	conf.Ssh.Addresses = append(conf.Ssh.Addresses, bnet.MustNewAddress(address))
	conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
	runtimeReloadWrite(t, conf)
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(svc.monitoring.reload.attempts.WithLabelValues("rejected")) > 0
	}, 5*time.Second, time.Millisecond)
	current := svc.configurationReloader.Current().Configuration()
	require.Equal(t, "plain:correct", string(current.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password))
	after, err := svc.runtime.persistence.repository.RuntimeState(t.Context())
	require.NoError(t, err)
	require.Equal(t, before, after)
	runtimeSshRun(t, runtimeSshDial(t, svc, original.Addr().String(), "correct"), 0)
	require.NoError(t, occupied.Close())
	runtimeReloadAwaitPassword(t, svc, "changed")
	runtimeSshRun(t, runtimeSshDial(t, svc, address, "changed"), 0)
}

func TestRuntimeReloadDeclarationOnlyChangeKeepsRuntimeGeneration(t *testing.T) {
	svc, conf := runtimeReloadFixture(t, t.Context(), true)
	runtimeListenerTestStart(t, svc, nil)
	require.Empty(t, conf.Environments)
	raw, err := os.ReadFile(conf.Filename)
	require.NoError(t, err)
	raw = append(raw, []byte("\nenvironments:\n  unused: {type: dummy}\n")...)
	require.NoError(t, os.WriteFile(conf.Filename, raw, 0600))
	require.Eventually(t, func() bool {
		return len(svc.configurationReloader.Current().Configuration().Environments) == 1
	}, 5*time.Second, time.Millisecond)
	svc.runtime.mutex.Lock()
	current := svc.runtime.current
	svc.runtime.mutex.Unlock()
	require.Same(t, svc.generation, current)
}

func TestRuntimeReloadCanReenableAccessAfterAllListenersAreDisabled(t *testing.T) {
	svc, conf := runtimeReloadFixture(t, t.Context(), true)
	run := runtimeListenerTestStart(t, svc, nil)
	_, listener := run.scope(t, "SSH", conf.Ssh.Addresses[0].String(), 0)
	old := runtimeSshDial(t, svc, listener.Addr().String(), "correct")
	conf.Ssh.Enabled = common.P(false)
	runtimeReloadWrite(t, conf)
	require.Eventually(t, func() bool {
		return !svc.configurationReloader.Current().Configuration().Ssh.IsEnabled()
	}, 5*time.Second, time.Millisecond)
	require.False(t, svc.monitoring.endpoint.Ready())
	runtimeSshRun(t, old, 0)
	conf.Ssh.Enabled = common.P(true)
	runtimeReloadWrite(t, conf)
	require.Eventually(t, func() bool {
		return svc.configurationReloader.Current().Configuration().Ssh.IsEnabled()
	}, 5*time.Second, time.Millisecond)
	require.True(t, svc.monitoring.endpoint.Ready())
	_, current := run.scope(t, "SSH", conf.Ssh.Addresses[0].String(), 0)
	runtimeSshRun(t, runtimeSshDial(t, svc, current.Addr().String(), "correct"), 0)
}

func TestRuntimeReloadShutdownCancelsAndJoinsProviderPreparation(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	var once sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			http.NotFound(w, r)
			return
		}
		once.Do(func() { close(entered) })
		<-r.Context().Done()
		close(canceled)
	}))
	t.Cleanup(server.Close)
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, server.Client())
	svc, conf := runtimeReloadFixture(t, ctx, true)
	run := runtimeListenerTestStartContext(t, ctx, svc, nil)
	oidc := &configuration.AuthorizationOidcDeviceAuth{}
	require.NoError(t, oidc.SetDefaults())
	oidc.Issuer = template.MustNewUrl(server.URL)
	oidc.ClientId, oidc.ClientSecret = template.MustNewString("client"), template.MustNewString("secret")
	conf.Flows[0].Authorization.V = oidc
	runtimeReloadWrite(t, conf)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not enter provider preparation")
	}
	run.cancel()
	require.NoError(t, run.await())
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("provider preparation survived watcher shutdown")
	}
}

func TestRuntimeReloadRequiresFileSource(t *testing.T) {
	err := (&Service{Watch: configuration.WatchModePreserve}).Run(t.Context())
	require.ErrorContains(t, err, "file source")
	require.ErrorContains(t, (&Service{Watch: configuration.WatchMode(255)}).Run(t.Context()), "illegal watch mode")
}

func TestRuntimeReloadPostCommitCleanupFailureStillAcceptsSource(t *testing.T) {
	svc, conf := runtimeReloadFixture(t, t.Context(), true)
	logs := logrecording.NewProvider()
	svc.Logger = logs.GetLogger("reload-cleanup")
	run := runtimeListenerTestStart(t, svc, func(address bnet.Address) (net.Listener, error) {
		listener, err := address.Listen()
		if err != nil {
			return nil, err
		}
		return &runtimeListenerCloseRetry{Listener: listener}, nil
	})
	_, physical := run.scope(t, "SSH", conf.Ssh.Addresses[0].String(), 0)
	physical.(*runtimeListenerCloseRetry).fail.Store(true)
	conf.Ssh.Enabled = common.P(false)
	runtimeReloadWrite(t, conf)
	require.Eventually(t, func() bool {
		return !svc.configurationReloader.Current().Configuration().Ssh.IsEnabled()
	}, 5*time.Second, time.Millisecond)
	require.False(t, svc.monitoring.endpoint.Ready())
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(svc.monitoring.reload.attempts.WithLabelValues("accepted")) == 1
	}, time.Second, time.Millisecond)
	require.Zero(t, testutil.ToFloat64(svc.monitoring.reload.attempts.WithLabelValues("rejected")))
	require.NotContains(t, fmt.Sprint(logs.GetAll()), "injected listener close failure")
	conf.Ssh.Enabled = common.P(true)
	runtimeReloadWrite(t, conf)
	require.Eventually(t, func() bool {
		return svc.configurationReloader.Current().Configuration().Ssh.IsEnabled()
	}, 5*time.Second, time.Millisecond)
	require.True(t, svc.monitoring.endpoint.Ready())
}

func TestRuntimeReloadMonitoringViewsShareMetricsButRetainGenerationLabels(t *testing.T) {
	svc, conf := runtimeReloadFixture(t, t.Context(), true)
	run := runtimeListenerTestStart(t, svc, nil)
	_, listener := run.scope(t, "SSH", conf.Ssh.Addresses[0].String(), 0)
	old := runtimeSshDial(t, svc, listener.Addr().String(), "correct")
	before := svc.monitoring
	conf.Flows[0].Name = "renamed"
	runtimeReloadWrite(t, conf)
	require.Eventually(t, func() bool {
		return svc.configurationReloader.Current().Configuration().Flows[0].Name == "renamed"
	}, 5*time.Second, time.Millisecond)
	current := before.service.Load().monitoring
	require.NotSame(t, before, current)
	require.Same(t, before.serviceMonitoringState, current.serviceMonitoringState)
	require.Equal(t, "recording-test", before.flowLabels("recording-test")[0])
	require.Equal(t, "renamed", current.flowLabels("renamed")[0])
	require.Equal(t, "", before.flowLabels("renamed")[0])
	runtimeSshRun(t, runtimeSshDial(t, svc, listener.Addr().String(), "correct"), 0)
	text := monitoringTestScrape(t, current)
	require.Contains(t, text, `flow="renamed"`)
	require.NotContains(t, text, "PRIVATE")
	_ = old.Close()
}
