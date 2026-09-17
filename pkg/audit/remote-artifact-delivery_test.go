package audit

import (
	"context"
	"crypto/sha256"
	goerrors "errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestRemoteArtifactDeliveryPublishesInSortedOrderAndDoesNotRepublishAfterRestart(t *testing.T) {
	identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
	artifacts := []RemoteArtifact{
		newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "b.cast.zst", []byte("second")),
		newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "a.cast.zst", []byte("first")),
	}
	source.set(artifacts...)
	fingerprint := remoteArtifactDeliveryTestFingerprint("archive")
	receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, nil))
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, artifacts, receiptTargets)

	var mutex sync.Mutex
	var published []string
	deliveryTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, func(_ context.Context, artifact RemoteArtifact) error {
		mutex.Lock()
		defer mutex.Unlock()
		published = append(published, artifact.FileName())
		return nil
	}))
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, deliveryTargets, remoteArtifactDeliveryTestOptions())
	require.NoError(t, delivery.Start())
	require.NoError(t, delivery.Start())
	remoteArtifactDeliveryTestFlush(t, delivery)
	require.NoError(t, delivery.Close())
	mutex.Lock()
	require.Equal(t, []string{"a.cast.zst", "b.cast.zst"}, published)
	mutex.Unlock()

	var republished atomic.Int32
	restartedTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, func(context.Context, RemoteArtifact) error {
		republished.Add(1)
		return nil
	}))
	restarted := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, restartedTargets, remoteArtifactDeliveryTestOptions())
	require.NoError(t, restarted.Start())
	remoteArtifactDeliveryTestFlush(t, restarted)
	require.Zero(t, republished.Load())
	require.NoError(t, restarted.Close())
}

func TestRemoteArtifactDeliveryUsesReceiptTargetSnapshot(t *testing.T) {
	identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "snapshot.becast", []byte("snapshot"))
	source.set(artifact)
	originalFingerprint := remoteArtifactDeliveryTestFingerprint("original")
	newFingerprint := remoteArtifactDeliveryTestFingerprint("new")
	receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("original", originalFingerprint, nil))
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, receiptTargets)
	var originalCalls atomic.Int32
	var newCalls atomic.Int32
	deliveryTargets := remoteArtifactDeliveryTestTargets(
		remoteArtifactDeliveryTestEntry("new", newFingerprint, func(context.Context, RemoteArtifact) error {
			newCalls.Add(1)
			return nil
		}),
		remoteArtifactDeliveryTestEntry("original", originalFingerprint, func(context.Context, RemoteArtifact) error {
			originalCalls.Add(1)
			return nil
		}),
	)
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, deliveryTargets, remoteArtifactDeliveryTestOptions())
	require.NoError(t, delivery.Start())
	remoteArtifactDeliveryTestFlush(t, delivery)
	require.Equal(t, int32(1), originalCalls.Load())
	require.Zero(t, newCalls.Load())
	require.NoError(t, delivery.Close())
}

func TestRemoteArtifactDeliveryRejectsPendingRemovedOrChangedTargetAtStartup(t *testing.T) {
	tests := []struct {
		name    string
		targets *RemoteArtifactTargets
		want    string
	}{
		{name: "removed", targets: remoteArtifactDeliveryTestTargets(), want: "unconfigured target"},
		{name: "changed", targets: remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("new"), nil)), want: "different destination"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "destination.cast.zst", []byte("destination"))
			source.set(artifact)
			receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("old"), nil))
			receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, receiptTargets)

			delivery, err := newRemoteArtifactDelivery(t.Context(), sealedDirectory, source, receipts, test.targets, remoteArtifactDeliveryTestOptions())
			require.Nil(t, delivery)
			require.ErrorContains(t, err, test.want)
			require.Zero(t, source.openCalls.Load())
		})
	}
}

func TestRemoteArtifactDeliveryDoesNotOpenAcknowledgedOrUnselectedArtifacts(t *testing.T) {
	tests := []struct {
		name             string
		receiptTarget    *remoteArtifactTargetEntry
		deliveryTarget   remoteArtifactTargetEntry
		acknowledgeFirst bool
	}{
		{
			name:             "acknowledged-old-destination",
			receiptTarget:    remoteArtifactDeliveryTestEntryPointer("archive", remoteArtifactDeliveryTestFingerprint("old")),
			deliveryTarget:   remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("new"), nil),
			acknowledgeFirst: true,
		},
		{
			name:           "not-selected",
			deliveryTarget: remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("current"), nil),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "skip.cast.zst", []byte("skip"))
			source.set(artifact)
			var receiptTargets *RemoteArtifactTargets
			if test.receiptTarget != nil {
				receiptTargets = remoteArtifactDeliveryTestTargets(*test.receiptTarget)
			}
			receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, receiptTargets)
			if test.acknowledgeFirst {
				_, err := receipts.store.acknowledge(t.Context(), artifact, *test.receiptTarget, time.Now().UTC().Add(time.Minute))
				require.NoError(t, err)
			}
			delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, remoteArtifactDeliveryTestTargets(test.deliveryTarget), remoteArtifactDeliveryTestOptions())
			require.NoError(t, delivery.Start())
			require.Eventually(t, func() bool { return source.listCalls.Load() >= 2 }, time.Second, time.Millisecond)
			remoteArtifactDeliveryTestFlush(t, delivery)
			require.Zero(t, source.openCalls.Load())
			require.NoError(t, delivery.Close())
		})
	}
}

func TestRemoteArtifactDeliveryRetriesTargetsIndependentlyWithFreshTimeouts(t *testing.T) {
	identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "retry.cast.zst", []byte("retry"))
	source.set(artifact)
	slowFingerprint := remoteArtifactDeliveryTestFingerprint("slow")
	healthyFingerprint := remoteArtifactDeliveryTestFingerprint("healthy")
	receiptTargets := remoteArtifactDeliveryTestTargets(
		remoteArtifactDeliveryTestEntry("slow", slowFingerprint, nil),
		remoteArtifactDeliveryTestEntry("healthy", healthyFingerprint, nil),
	)
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, receiptTargets)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	deadlines := make(chan time.Time, 2)
	var slowCalls atomic.Int32
	slow := remoteArtifactDeliveryTestEntry("slow", slowFingerprint, func(ctx context.Context, _ RemoteArtifact) error {
		deadline, _ := ctx.Deadline()
		deadlines <- deadline
		if slowCalls.Add(1) == 1 {
			close(firstStarted)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-releaseFirst:
				return goerrors.New("temporary remote failure")
			}
		}
		return nil
	})
	slow.publishAttemptTimeout = 250 * time.Millisecond
	healthyDelivered := make(chan struct{}, 1)
	healthy := remoteArtifactDeliveryTestEntry("healthy", healthyFingerprint, func(context.Context, RemoteArtifact) error {
		healthyDelivered <- struct{}{}
		return nil
	})
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, remoteArtifactDeliveryTestTargets(slow, healthy), remoteArtifactDeliveryTestOptions())
	require.NoError(t, delivery.Start())
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("slow target did not start")
	}
	select {
	case <-healthyDelivered:
	case <-time.After(time.Second):
		t.Fatal("healthy target was blocked by another target")
	}
	close(releaseFirst)
	remoteArtifactDeliveryTestFlush(t, delivery)
	firstDeadline := <-deadlines
	secondDeadline := <-deadlines
	require.Equal(t, int32(2), slowCalls.Load())
	require.True(t, secondDeadline.After(firstDeadline))
	require.NoError(t, delivery.Close())
}

func TestRemoteArtifactDeliveryOpensBeforeStartingFreshPublishTimeout(t *testing.T) {
	identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "slow-open.cast.zst", []byte("slow-open"))
	source.set(artifact)
	attemptTimeout := 80 * time.Millisecond
	source.openDelay = attemptTimeout + attemptTimeout/2
	fingerprint := remoteArtifactDeliveryTestFingerprint("archive")
	receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, nil))
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, receiptTargets)
	remaining := make(chan time.Duration, 1)
	target := remoteArtifactDeliveryTestEntry("archive", fingerprint, func(ctx context.Context, _ RemoteArtifact) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			remaining <- 0
			return nil
		}
		remaining <- time.Until(deadline)
		return nil
	})
	target.publishAttemptTimeout = attemptTimeout
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, remoteArtifactDeliveryTestTargets(target), remoteArtifactDeliveryTestOptions())
	require.NoError(t, delivery.Start())
	remoteArtifactDeliveryTestFlush(t, delivery)
	require.Greater(t, <-remaining, attemptTimeout/2)
	require.Equal(t, int32(1), source.openCalls.Load())
	require.NoError(t, delivery.Close())
}

func TestRemoteArtifactDeliveryPublishTimeoutClosesBlockedArtifactHandle(t *testing.T) {
	identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
	reader := &remoteArtifactDeliveryBlockingReader{started: make(chan struct{}), closed: make(chan struct{})}
	artifact, err := NewRemoteArtifact(identity.ProducerId(), "blocked.cast.zst", ArtifactDigest(sha256.Sum256([]byte("blocked"))), 1, reader)
	require.NoError(t, err)
	source.set(artifact)
	source.newHandle = func(artifact RemoteArtifact) RemoteArtifactHandle {
		return &remoteArtifactDeliveryTestHandle{artifact: artifact, closed: &source.closed, close: reader.Close}
	}
	fingerprint := remoteArtifactDeliveryTestFingerprint("archive")
	receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, nil))
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, receiptTargets)
	target := remoteArtifactDeliveryTestEntry("archive", fingerprint, func(_ context.Context, artifact RemoteArtifact) error {
		return artifact.Validate()
	})
	target.publishAttemptTimeout = 30 * time.Millisecond
	options := remoteArtifactDeliveryTestOptions()
	options.initialBackoff = time.Hour
	options.maximumBackoff = time.Hour
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, remoteArtifactDeliveryTestTargets(target), options)
	require.NoError(t, delivery.Start())
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("target did not start reading the artifact")
	}
	select {
	case <-reader.closed:
	case <-time.After(time.Second):
		t.Fatal("publish timeout did not close the artifact handle")
	}
	require.Eventually(t, func() bool { return source.closed.Load() == 1 }, time.Second, time.Millisecond)
	require.NoError(t, delivery.Close())
	require.Equal(t, int32(1), source.closed.Load())
}

func TestRemoteArtifactDeliveryFlushDeadlineDoesNotWaitForReceiptLock(t *testing.T) {
	identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "locked.cast.zst", []byte("locked"))
	source.set(artifact)
	fingerprint := remoteArtifactDeliveryTestFingerprint("archive")
	receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, nil))
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, receiptTargets)
	targets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, nil))
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, targets, remoteArtifactDeliveryTestOptions())
	require.NoError(t, receipts.store.lock(t.Context()))
	locked := true
	defer func() {
		if locked {
			receipts.store.unlock()
		}
	}()
	require.NoError(t, delivery.Start())
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	err := delivery.Flush(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	receipts.store.unlock()
	locked = false
	remoteArtifactDeliveryTestFlush(t, delivery)
	require.NoError(t, delivery.Close())
}

func TestRemoteArtifactDeliveryRetriesOnlyAckAfterPersistenceFailure(t *testing.T) {
	identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "ack.cast.zst", []byte("ack"))
	source.set(artifact)
	fingerprint := remoteArtifactDeliveryTestFingerprint("archive")
	receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, nil))
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, receiptTargets)
	var publishCalls atomic.Int32
	deliveryTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, func(context.Context, RemoteArtifact) error {
		publishCalls.Add(1)
		return nil
	}))
	options := remoteArtifactDeliveryTestOptions()
	acknowledge := options.acknowledge
	var ackCalls atomic.Int32
	options.acknowledge = func(ctx context.Context, store *remoteArtifactReceiptStore, artifact RemoteArtifact, entry remoteArtifactTargetEntry, acknowledgedAt time.Time) error {
		if ackCalls.Add(1) <= 2 {
			return goerrors.New("injected receipt persistence failure")
		}
		return acknowledge(ctx, store, artifact, entry, acknowledgedAt)
	}
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, deliveryTargets, options)
	require.NoError(t, delivery.Start())
	remoteArtifactDeliveryTestFlush(t, delivery)
	require.Equal(t, int32(1), publishCalls.Load())
	require.Equal(t, int32(3), ackCalls.Load())
	require.NoError(t, delivery.Close())
}

func TestRemoteArtifactDeliveryFlushCapturesVisibleNames(t *testing.T) {
	identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
	first := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "first.cast.zst", []byte("first"))
	second := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "second.cast.zst", []byte("second"))
	source.set(first)
	fingerprint := remoteArtifactDeliveryTestFingerprint("archive")
	receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, nil))
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{first}, receiptTargets)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	target := remoteArtifactDeliveryTestEntry("archive", fingerprint, func(ctx context.Context, artifact RemoteArtifact) error {
		switch artifact.FileName() {
		case first.FileName():
			select {
			case <-firstStarted:
			default:
				close(firstStarted)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-releaseFirst:
				return nil
			}
		case second.FileName():
			select {
			case <-secondStarted:
			default:
				close(secondStarted)
			}
			<-ctx.Done()
			return ctx.Err()
		default:
			return nil
		}
	})
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, remoteArtifactDeliveryTestTargets(target), remoteArtifactDeliveryTestOptions())
	require.NoError(t, delivery.Start())
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first artifact did not start")
	}
	flushed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		flushed <- delivery.Flush(ctx)
	}()
	require.Eventually(t, func() bool { return source.listCalls.Load() >= 2 }, time.Second, time.Millisecond)
	_, err := receipts.store.initialize(second, time.Now().UTC(), receiptTargets)
	require.NoError(t, err)
	source.set(first, second)
	delivery.notifyDiscovery()
	close(releaseFirst)
	select {
	case err := <-flushed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("flush waited for an artifact added after its snapshot")
	}
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("second artifact was not discovered")
	}
	require.NoError(t, delivery.Close())
}

func TestRemoteArtifactDeliveryCloseCancelsHandleAndClosesTargetBeforeWaiting(t *testing.T) {
	identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "close.becast", []byte("close"))
	source.set(artifact)
	fingerprint := remoteArtifactDeliveryTestFingerprint("archive")
	receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, nil))
	receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, receiptTargets)
	started := make(chan struct{})
	release := make(chan struct{})
	var targetClosed atomic.Bool
	instance := &remoteArtifactTargetTestInstance{
		remoteTargetTestInstance: &remoteTargetTestInstance{close: func() error {
			targetClosed.Store(true)
			close(release)
			return nil
		}},
		publishArtifact: func(context.Context, RemoteArtifact) error {
			close(started)
			<-release
			return context.Canceled
		},
	}
	entry := remoteArtifactDeliveryTestEntry("archive", fingerprint, nil)
	entry.target = instance
	targets := &RemoteArtifactTargets{
		targets: &RemoteTargets{entries: []remoteTargetEntry{{scope: entry.scope, target: instance}}},
		entries: []remoteArtifactTargetEntry{entry},
	}
	delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, targets, remoteArtifactDeliveryTestOptions())
	require.NoError(t, delivery.Start())
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("artifact publish did not start")
	}
	require.NoError(t, delivery.Close())
	require.True(t, targetClosed.Load())
	require.Eventually(t, func() bool { return source.closed.Load() > 0 }, time.Second, time.Millisecond)
	require.NoError(t, receipts.Require(t.Context(), artifact))
}

func TestRemoteArtifactDeliveryDiscoversWithWatcherAndSafetyScan(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*remoteArtifactDeliveryOptions)
		discover  func(*RemoteArtifactDelivery, string, string)
	}{
		{
			name: "watcher",
			discover: func(_ *RemoteArtifactDelivery, directory, name string) {
				require.NoError(t, os.WriteFile(directory+string(os.PathSeparator)+name, []byte("notify"), journalFileMode))
			},
		},
		{
			name: "safety-scan",
			configure: func(options *remoteArtifactDeliveryOptions) {
				options.idleDelay = 5 * time.Millisecond
				options.newWatcher = func() (*fsnotify.Watcher, error) { return nil, goerrors.New("unavailable") }
			},
			discover: func(*RemoteArtifactDelivery, string, string) {},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, sealedDirectory, source := newRemoteArtifactDeliveryTestSource(t)
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "discovered.cast.zst", []byte("discovered"))
			fingerprint := remoteArtifactDeliveryTestFingerprint("archive")
			receiptTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, nil))
			receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, nil, receiptTargets)
			delivered := make(chan struct{}, 1)
			deliveryTargets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", fingerprint, func(context.Context, RemoteArtifact) error {
				delivered <- struct{}{}
				return nil
			}))
			options := remoteArtifactDeliveryTestOptions()
			options.idleDelay = time.Hour
			if test.configure != nil {
				test.configure(&options)
			}
			delivery := newRemoteArtifactDeliveryTestCoordinator(t, sealedDirectory, source, receipts, deliveryTargets, options)
			require.NoError(t, delivery.Start())
			require.Eventually(t, func() bool { return source.listCalls.Load() > 0 }, time.Second, time.Millisecond)
			_, err := receipts.store.initialize(artifact, time.Now().UTC(), receiptTargets)
			require.NoError(t, err)
			source.set(artifact)
			test.discover(delivery, sealedDirectory, artifact.FileName())
			select {
			case <-delivered:
			case <-time.After(time.Second):
				t.Fatal("new artifact was not discovered")
			}
			require.NoError(t, delivery.Close())
		})
	}
}

func TestRemoteArtifactDeliveryRejectsInvalidAndDuplicateSourceNames(t *testing.T) {
	source := &remoteArtifactDeliveryTestSource{}
	for _, names := range [][]string{{"valid.cast.zst", "valid.cast.zst"}, {"../invalid"}} {
		source.names = names
		_, err := listRemoteArtifactSourceNames(t.Context(), source)
		require.Error(t, err)
	}
}

func TestRemoteArtifactDeliveryDiscoveryDoesNotInterruptFailureBackoff(t *testing.T) {
	worker := remoteArtifactDeliveryWorker{wake: make(chan struct{}, 1), discoveryWake: make(chan struct{}, 1)}
	worker.notifyDiscovery()
	select {
	case <-worker.wake:
		t.Fatal("discovery notification interrupted the failure-backoff channel")
	default:
	}
	select {
	case <-worker.discoveryWake:
	default:
		t.Fatal("discovery notification did not wake idle discovery")
	}
	worker.notify()
	select {
	case <-worker.wake:
	default:
		t.Fatal("explicit notification did not wake failure backoff")
	}
}

type remoteArtifactDeliveryTestSource struct {
	mutex     sync.Mutex
	names     []string
	artifacts map[string]RemoteArtifact
	listCalls atomic.Int32
	openCalls atomic.Int32
	openDelay time.Duration
	closed    atomic.Int32
	newHandle func(RemoteArtifact) RemoteArtifactHandle
}

func newRemoteArtifactDeliveryTestSource(t *testing.T) (*Identity, string, *remoteArtifactDeliveryTestSource) {
	t.Helper()
	_, identity := newJournalTestIdentity(t)
	return identity, t.TempDir(), &remoteArtifactDeliveryTestSource{artifacts: make(map[string]RemoteArtifact)}
}

func (this *remoteArtifactDeliveryTestSource) set(artifacts ...RemoteArtifact) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.names = this.names[:0]
	this.artifacts = make(map[string]RemoteArtifact, len(artifacts))
	for _, artifact := range artifacts {
		this.names = append(this.names, artifact.FileName())
		this.artifacts[artifact.FileName()] = artifact
	}
}

func (this *remoteArtifactDeliveryTestSource) ListSealedArtifactNames(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	this.listCalls.Add(1)
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return append([]string(nil), this.names...), nil
}

func (this *remoteArtifactDeliveryTestSource) OpenSealedArtifact(ctx context.Context, name string) (RemoteArtifactHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	this.openCalls.Add(1)
	if this.openDelay > 0 {
		timer := time.NewTimer(this.openDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	this.mutex.Lock()
	artifact, exists := this.artifacts[name]
	this.mutex.Unlock()
	if !exists {
		return nil, os.ErrNotExist
	}
	if this.newHandle != nil {
		return this.newHandle(artifact), nil
	}
	return &remoteArtifactDeliveryTestHandle{artifact: artifact, closed: &this.closed}, nil
}

type remoteArtifactDeliveryTestHandle struct {
	artifact RemoteArtifact
	closed   *atomic.Int32
	close    func() error
	once     sync.Once
}

func (this *remoteArtifactDeliveryTestHandle) RemoteArtifact() (RemoteArtifact, error) {
	return this.artifact, nil
}

func (this *remoteArtifactDeliveryTestHandle) Close() error {
	var result error
	this.once.Do(func() {
		this.closed.Add(1)
		if this.close != nil {
			result = this.close()
		}
	})
	return result
}

type remoteArtifactDeliveryBlockingReader struct {
	started     chan struct{}
	closed      chan struct{}
	startedOnce sync.Once
	closedOnce  sync.Once
}

func (this *remoteArtifactDeliveryBlockingReader) ReadAt([]byte, int64) (int, error) {
	this.startedOnce.Do(func() { close(this.started) })
	<-this.closed
	return 0, goerrors.New("artifact handle closed")
}

func (this *remoteArtifactDeliveryBlockingReader) Close() error {
	this.closedOnce.Do(func() { close(this.closed) })
	return nil
}

type remoteArtifactDeliveryTestTarget struct {
	publish func(context.Context, RemoteArtifact) error
}

func (this *remoteArtifactDeliveryTestTarget) PublishArtifact(ctx context.Context, artifact RemoteArtifact) error {
	if this.publish == nil {
		return nil
	}
	return this.publish(ctx, artifact)
}

func remoteArtifactDeliveryTestFingerprint(value string) remoteDeliveryDestinationFingerprint {
	return remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte(value)))
}

func remoteArtifactDeliveryTestEntry(name configuration.AuditlogTargetName, fingerprint remoteDeliveryDestinationFingerprint, publish func(context.Context, RemoteArtifact) error) remoteArtifactTargetEntry {
	return remoteArtifactTargetEntry{
		scope:                  RemoteTargetScope{Auditlog: "security", Target: name},
		target:                 &remoteArtifactDeliveryTestTarget{publish: publish},
		publishAttemptTimeout:  time.Second,
		destinationFingerprint: fingerprint,
	}
}

func remoteArtifactDeliveryTestEntryPointer(name configuration.AuditlogTargetName, fingerprint remoteDeliveryDestinationFingerprint) *remoteArtifactTargetEntry {
	entry := remoteArtifactDeliveryTestEntry(name, fingerprint, nil)
	return &entry
}

func remoteArtifactDeliveryTestTargets(entries ...remoteArtifactTargetEntry) *RemoteArtifactTargets {
	return &RemoteArtifactTargets{entries: entries}
}

func newRemoteArtifactDeliveryTestReceipts(t *testing.T, identity *Identity, artifacts []RemoteArtifact, targets *RemoteArtifactTargets) *RemoteArtifactReceipts {
	t.Helper()
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: targets}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	sealedAt := time.Now().UTC()
	for _, artifact := range artifacts {
		_, err := store.initialize(artifact, sealedAt, targets)
		require.NoError(t, err)
	}
	return receipts
}

func remoteArtifactDeliveryTestOptions() remoteArtifactDeliveryOptions {
	options := defaultRemoteArtifactDeliveryOptions()
	options.idleDelay = time.Hour
	options.initialBackoff = 2 * time.Millisecond
	options.maximumBackoff = 5 * time.Millisecond
	options.jitter = func(value time.Duration) time.Duration { return value }
	return options
}

func newRemoteArtifactDeliveryTestCoordinator(t *testing.T, sealedDirectory string, source RemoteArtifactSource, receipts *RemoteArtifactReceipts, targets *RemoteArtifactTargets, options remoteArtifactDeliveryOptions) *RemoteArtifactDelivery {
	t.Helper()
	delivery, err := newRemoteArtifactDelivery(t.Context(), sealedDirectory, source, receipts, targets, options)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, delivery.Close()) })
	return delivery
}

func remoteArtifactDeliveryTestFlush(t *testing.T, delivery *RemoteArtifactDelivery) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, delivery.Flush(ctx))
}
