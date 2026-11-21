package audit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

func TestDeliveryMonitoringSnapshotsAreConcurrentAndConstantSpace(t *testing.T) {
	state := new(deliveryMonitoring)
	require.Zero(t, state.snapshot("archive").Errors)
	require.True(t, state.snapshot("archive").PendingSince.IsZero())
	var wait sync.WaitGroup
	for range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				state.pending()
				state.failed()
				_ = state.snapshot("archive")
			}
		}()
	}
	wait.Wait()
	snapshot := state.snapshot("archive")
	require.EqualValues(t, 400, snapshot.Errors)
	require.False(t, snapshot.PendingSince.IsZero())
	state.resolved()
	require.True(t, state.snapshot("archive").PendingSince.IsZero())
	require.EqualValues(t, 400, state.snapshot("archive").Errors)
}

func TestRemoteDeliveryMonitoringFailureAndRecovery(t *testing.T) {
	conf, identity, _ := newRemoteDeliveryTestJournal(t, 1)
	var failed atomic.Bool
	failed.Store(true)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(context.Context, SealedSegment) error {
		if failed.Load() {
			return errors.Network.Newf("unavailable")
		}
		return nil
	})}
	delivery, err := NewRemoteDelivery(t.Context(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, delivery.Close()) })
	setRemoteDeliveryTestOptions(delivery)
	require.NoError(t, delivery.Start())
	require.Eventually(t, func() bool {
		snapshot := delivery.MonitoringSnapshots()[0]
		return snapshot.Errors > 0 && !snapshot.PendingSince.IsZero()
	}, 3*time.Second, time.Millisecond)
	failed.Store(false)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	require.NoError(t, delivery.Flush(ctx))
	require.Eventually(t, func() bool { return delivery.MonitoringSnapshots()[0].PendingSince.IsZero() }, time.Second, time.Millisecond)
	require.Positive(t, delivery.MonitoringSnapshots()[0].Errors)
}

func TestRemoteArtifactMonitoringFailureAndRecovery(t *testing.T) {
	identity, directory, source := newRemoteArtifactDeliveryTestSource(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "recording.bcast", []byte("test"))
	source.set(artifact)
	fingerprint := remoteArtifactDeliveryTestFingerprint("archive")
	var failed atomic.Bool
	failed.Store(true)
	targets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, func(context.Context, RemoteArtifact) error {
		if failed.Load() {
			return errors.Network.Newf("unavailable")
		}
		return nil
	}))
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, targets)
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, directory, source, receipts, targets, remoteArtifactDeliveryTestOptions())
	require.NoError(t, delivery.Start())
	require.Eventually(t, func() bool {
		snapshot := delivery.MonitoringSnapshots()[0]
		return snapshot.Errors > 0 && !snapshot.PendingSince.IsZero()
	}, 3*time.Second, time.Millisecond)
	failed.Store(false)
	remoteArtifactDeliveryTestFlush(t, delivery)
	require.Eventually(t, func() bool { return delivery.MonitoringSnapshots()[0].PendingSince.IsZero() }, 3*time.Second, time.Millisecond)
}
