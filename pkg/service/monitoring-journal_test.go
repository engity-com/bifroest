package service

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func startMonitoringJournalObserverTest(t *testing.T, m *serviceMonitoring, svc *service) (chan time.Time, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	var result error
	go func() { defer close(done); result = m.observeJournalSpace(ctx, svc, ticks) }()
	stop := func() {
		cancel()
		select {
		case <-done:
			require.NoError(t, result)
		case <-time.After(time.Second):
			t.Fatal("journal observation did not stop after cancellation")
		}
	}
	t.Cleanup(stop)
	return ticks, stop
}

type monitoringBlockingJournal struct {
	audit.Recorder
	calls atomic.Int32
	read  func() (uint64, error)
}

func (r *monitoringBlockingJournal) JournalAvailableBytes() (uint64, error) {
	r.calls.Add(1)
	return r.read()
}

func TestMonitoringJournalBlockedQueryIsBoundedAndCannotPublishAfterCancellation(t *testing.T) {
	m, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	blocked := &monitoringBlockingJournal{read: func() (uint64, error) {
		close(entered)
		<-release
		defer close(returned)
		return 999, nil
	}}
	var healthySamples atomic.Uint64
	healthy := &monitoringBlockingJournal{read: func() (uint64, error) { return healthySamples.Add(1), nil }}
	svc := &service{auditRecorders: map[configuration.AuditlogName]audit.Recorder{
		"blocked": &failurePolicyAuditRecorder{delegate: blocked},
		"healthy": &failurePolicyAuditRecorder{delegate: healthy},
	}}
	m.journal.available.WithLabelValues("blocked").Set(123)
	m.journal.observed.WithLabelValues("blocked").Set(456)
	m.journal.valid.WithLabelValues("blocked").Set(1)
	ticks, stop := startMonitoringJournalObserverTest(t, m, svc)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("blocked query did not start")
	}
	require.Eventually(t, func() bool { return testutil.ToFloat64(m.journal.available.WithLabelValues("healthy")) == 1 }, time.Second, time.Millisecond)
	for i := range 10 {
		ticks <- time.Now()
		require.Eventually(t, func() bool { return testutil.ToFloat64(m.journal.available.WithLabelValues("healthy")) == float64(i+2) }, time.Second, time.Millisecond)
	}
	require.Equal(t, int32(1), blocked.calls.Load(), "ticks must not accumulate blocked syscall workers")
	require.Zero(t, testutil.ToFloat64(m.journal.valid.WithLabelValues("blocked")))
	require.Equal(t, 123.0, testutil.ToFloat64(m.journal.available.WithLabelValues("blocked")))
	require.Equal(t, 456.0, testutil.ToFloat64(m.journal.observed.WithLabelValues("blocked")))
	stop()
	release <- struct{}{}
	<-returned
	require.Zero(t, testutil.ToFloat64(m.journal.valid.WithLabelValues("blocked")))
	require.Equal(t, 123.0, testutil.ToFloat64(m.journal.available.WithLabelValues("blocked")), "late syscall results must not publish")
	require.Equal(t, 456.0, testutil.ToFloat64(m.journal.observed.WithLabelValues("blocked")))
}

func TestMonitoringJournalRecoversAfterSlowQueryWithoutOverlap(t *testing.T) {
	m, err := newServiceMonitoring(monitoringTestConfiguration(t))
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var first atomic.Bool
	first.Store(true)
	observer := &monitoringBlockingJournal{read: func() (uint64, error) {
		if first.CompareAndSwap(true, false) {
			close(entered)
			<-release
		}
		return 789, nil
	}}
	svc := &service{auditRecorders: map[configuration.AuditlogName]audit.Recorder{"operations": &failurePolicyAuditRecorder{delegate: observer}}}
	ticks, _ := startMonitoringJournalObserverTest(t, m, svc)
	<-entered
	ticks <- time.Now()
	require.Eventually(t, func() bool { return testutil.CollectAndCount(m.journal.valid) == 1 }, time.Second, time.Millisecond)
	require.Zero(t, testutil.ToFloat64(m.journal.valid))
	require.Equal(t, int32(1), observer.calls.Load())
	release <- struct{}{}
	require.Eventually(t, func() bool { return testutil.ToFloat64(m.journal.valid) == 1 }, time.Second, time.Millisecond)
	ticks <- time.Now()
	require.Eventually(t, func() bool { return observer.calls.Load() == 2 && testutil.ToFloat64(m.journal.valid) == 1 }, time.Second, time.Millisecond)
	require.Equal(t, 789.0, testutil.ToFloat64(m.journal.available))
}

func TestMonitoringJournalBlockedQueryDoesNotHoldListenerDrain(t *testing.T) {
	conf := httpListenerTestConfiguration(t)
	conf.Http = nil
	enableMonitoringTest(&conf)
	conf.Ssh.GracefulShutdownTimeout = common.DurationOf(20 * time.Millisecond)
	svc, err := prepareMonitoringTestService(t, &Service{Configuration: conf, Version: serviceTestVersion{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	observer := &monitoringBlockingJournal{Recorder: audit.NewNoopRecorder(), read: func() (uint64, error) {
		close(entered)
		<-release
		defer close(returned)
		return 1, nil
	}}
	svc.auditRecorders["operations"] = &failurePolicyAuditRecorder{service: svc, delegate: observer}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := svc.runListeners(ctx, nil); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("journal observation did not start")
	}
	require.Eventually(t, svc.monitoring.ready.Load, time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("blocked journal query held listener shutdown")
	}
	require.Zero(t, testutil.ToFloat64(svc.monitoring.journal.valid.WithLabelValues("operations")))
	release <- struct{}{}
	<-returned
}
