package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	logrecording "github.com/echocat/slf4g/testing/recording"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestMonitoringReloadResultsAndWatchDegradationAreSeparate(t *testing.T) {
	monitor, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, monitor.endpoint.Close()) })
	logs := logrecording.NewProvider()
	svc := &service{Service: &Service{Logger: logs.GetLogger("reload-metrics")}, monitoring: monitor}
	require.Zero(t, testutil.ToFloat64(monitor.reload.enabled))
	require.Zero(t, testutil.ToFloat64(monitor.reload.lastSuccess))
	require.Zero(t, testutil.ToFloat64(monitor.reload.lastAttempt))
	require.Zero(t, testutil.ToFloat64(monitor.reload.lastAccepted))

	svc.configurationReloaded(configuration.ReloadChanges{Changed: true})
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.reload.attempts.WithLabelValues("accepted")))
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.reload.lastSuccess))
	require.Positive(t, testutil.ToFloat64(monitor.reload.lastAttempt))
	accepted := testutil.ToFloat64(monitor.reload.lastAccepted)
	require.Positive(t, accepted)

	const secret = "PRIVATE-PROVIDER-ERROR"
	svc.configurationReloadError(errors.New(secret))
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.reload.attempts.WithLabelValues("rejected")))
	require.Zero(t, testutil.ToFloat64(monitor.reload.lastSuccess))
	require.Equal(t, accepted, testutil.ToFloat64(monitor.reload.lastAccepted))
	lastAttempt := testutil.ToFloat64(monitor.reload.lastAttempt)
	svc.configurationReloadError(&configuration.FileWatchError{Err: errors.New(secret)})
	svc.configurationReloadError(context.Canceled)
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.reload.watchErrors))
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.reload.attempts.WithLabelValues("rejected")))
	require.Equal(t, lastAttempt, testutil.ToFloat64(monitor.reload.lastAttempt))
	require.Zero(t, testutil.ToFloat64(monitor.reload.lastSuccess))

	svc.configurationReloaded(configuration.ReloadChanges{})
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.reload.attempts.WithLabelValues("unchanged")))
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.reload.lastSuccess))
	require.GreaterOrEqual(t, testutil.ToFloat64(monitor.reload.lastAccepted), accepted)
	text := monitoringTestScrape(t, monitor)
	require.NotContains(t, text, secret)
	require.NotContains(t, fmt.Sprint(logs.GetAll()), secret)
	require.Contains(t, text, `bifroest_configuration_reload_attempts_total{result="unchanged"} 1`)
}

func TestMonitoringReloadOptInCollectsWithoutOpeningMonitoringPort(t *testing.T) {
	conf := monitoringTestConfiguration(t)
	conf.Monitoring.Enabled = false
	conf.Monitoring.BearerTokenFile = "/not-provisioned/monitoring-token"
	without, err := newServiceMonitoring(conf)
	require.NoError(t, err)
	require.Nil(t, without)
	monitor, err := newServiceMonitoring(conf, true)
	require.NoError(t, err)
	require.NotNil(t, monitor)
	require.Nil(t, monitor.endpoint)
	view := monitor.view(conf)
	require.Same(t, monitor.serviceMonitoringState, view.serviceMonitoringState)
	view.observeReload("accepted")
	require.Equal(t, 1.0, testutil.ToFloat64(monitor.reload.attempts.WithLabelValues("accepted")))
	snapshot, err := view.Snapshot(t.Context(), []string{"bifroest_configuration_reload_attempts_total"})
	require.NoError(t, err)
	require.Len(t, snapshot.Families, 1)
	require.Equal(t, "bifroest_configuration_reload_attempts_total", snapshot.Families[0].GetName())
}
