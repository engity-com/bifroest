package audit

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestRemoteDeliveryPublishesInOrderAndDoesNotResend(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 3)
	published := make(chan uint64, len(segments))
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(_ context.Context, segment SealedSegment) error {
		published <- segment.Sequence()
		return nil
	})}

	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	require.NoError(t, delivery.Start())
	for expected := uint64(1); expected <= uint64(len(segments)); expected++ {
		select {
		case actual := <-published:
			require.Equal(t, expected, actual)
		case <-time.After(time.Second):
			t.Fatalf("segment %d was not delivered", expected)
		}
	}
	require.Eventually(t, func() bool {
		return remoteDeliveryTestCursorSequence(conf, identity, "archive") == uint64(len(segments))
	}, time.Second, time.Millisecond)
	require.NoError(t, delivery.Close())

	for _, segment := range segments {
		require.FileExists(t, segment.path)
	}
	require.NoError(t, VerifyJournalIntegrity(context.Background(), []JournalSource{{
		Name:               conf.Name.String(),
		Directory:          conf.Journal.Directory,
		ExpectedProducerId: identity.ProducerId(),
	}}))

	var resent atomic.Int32
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(context.Context, SealedSegment) error {
		resent.Add(1)
		return nil
	})}
	restarted, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = restarted.Close() })
	setRemoteDeliveryTestOptions(restarted)
	require.NoError(t, restarted.Start())
	time.Sleep(25 * time.Millisecond)
	require.Zero(t, resent.Load())
	require.NoError(t, restarted.Close())
}

func TestRemoteDeliveryRetriesTargetsIndependentlyAndRetainsSegments(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 1)
	var recoverRemote atomic.Bool
	var failingCalls atomic.Int32
	var failingDelivered atomic.Bool
	var healthyDelivered atomic.Bool
	conf.Targets = configuration.AuditlogTargets{
		remoteDeliveryTestTarget("failing", func(context.Context, SealedSegment) error {
			failingCalls.Add(1)
			if !recoverRemote.Load() {
				return berrors.Network.Newf("remote unavailable")
			}
			failingDelivered.Store(true)
			return nil
		}),
		remoteDeliveryTestTarget("healthy", func(context.Context, SealedSegment) error {
			healthyDelivered.Store(true)
			return nil
		}),
	}

	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	require.NoError(t, delivery.Start())
	require.Eventually(t, healthyDelivered.Load, time.Second, time.Millisecond)
	require.Eventually(t, func() bool {
		return remoteDeliveryTestCursorSequence(conf, identity, "healthy") == 1
	}, time.Second, time.Millisecond)
	require.Eventually(t, func() bool { return failingCalls.Load() >= 2 }, time.Second, time.Millisecond)
	require.FileExists(t, segments[0].path)
	require.Zero(t, remoteDeliveryTestCursorSequence(conf, identity, "failing"))

	recoverRemote.Store(true)
	require.Eventually(t, failingDelivered.Load, time.Second, time.Millisecond)
	require.Eventually(t, func() bool {
		return remoteDeliveryTestCursorSequence(conf, identity, "failing") == 1
	}, time.Second, time.Millisecond)
	require.FileExists(t, segments[0].path)
	require.NoError(t, delivery.Close())
}

func TestRemoteDeliveryDoesNotRepublishAfterCursorWriteFailure(t *testing.T) {
	conf, identity, _ := newRemoteDeliveryTestJournal(t, 1)
	blocker := filepath.Join(conf.Journal.Directory, remoteDeliveryStateDirectoryName, identity.ProducerId().String(), remoteDeliveryTargetStateName("archive"), remoteDeliveryCursorTempFileName)
	var calls atomic.Int32
	published := make(chan struct{}, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(context.Context, SealedSegment) error {
		if calls.Add(1) == 1 {
			require.NoError(t, os.Mkdir(blocker, journalDirectoryMode))
			require.NoError(t, os.WriteFile(filepath.Join(blocker, "keep"), []byte("x"), journalFileMode))
			published <- struct{}{}
		}
		return nil
	})}

	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	require.NoError(t, delivery.Start())
	select {
	case <-published:
	case <-time.After(time.Second):
		t.Fatal("segment was not published")
	}
	time.Sleep(25 * time.Millisecond)
	require.Equal(t, int32(1), calls.Load())
	require.NoError(t, os.RemoveAll(blocker))
	require.Eventually(t, func() bool {
		return remoteDeliveryTestCursorSequence(conf, identity, "archive") == 1
	}, time.Second, time.Millisecond)
	require.Equal(t, int32(1), calls.Load())
	require.NoError(t, delivery.Close())
}

func TestRemoteDeliveryCloseCancelsActivePublish(t *testing.T) {
	conf, identity, _ := newRemoteDeliveryTestJournal(t, 1)
	started := make(chan struct{}, 1)
	var targetClosed atomic.Bool
	conf.Targets = configuration.AuditlogTargets{{
		Name: "archive",
		V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
			return &remoteTargetTestInstance{
				publish: func(ctx context.Context, _ SealedSegment) error {
					started <- struct{}{}
					<-ctx.Done()
					return ctx.Err()
				},
				close: func() error { targetClosed.Store(true); return nil },
			}, nil
		}},
	}}
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	require.NoError(t, delivery.Start())
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("publish did not start")
	}
	require.NoError(t, delivery.Close())
	require.True(t, targetClosed.Load())
}

func TestRemoteDeliveryFlushPublishesCurrentJournalTail(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	conf.Name = "security"
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = recorder.Close() })
	published := make(chan uint64, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(_ context.Context, segment SealedSegment) error {
		published <- segment.Sequence()
		return nil
	})}
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	require.NoError(t, delivery.Start())
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.shutdown-tail"}))
	require.NoError(t, recorder.(SealableRecorder).Seal())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, delivery.Flush(ctx))
	select {
	case sequence := <-published:
		require.Equal(t, uint64(1), sequence)
	default:
		t.Fatal("flush returned before the current segment was published")
	}
	require.Equal(t, uint64(1), remoteDeliveryTestCursorSequence(conf, identity, "archive"))
}

func TestRemoteDeliverySerializesConcurrentFlushes(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	conf.Name = "security"
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = recorder.Close() })
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(ctx context.Context, _ SealedSegment) error {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	})}
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	require.NoError(t, delivery.Start())
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.concurrent-flush"}))
	require.NoError(t, recorder.(SealableRecorder).Seal())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- delivery.Flush(ctx) }()
	go func() { results <- delivery.Flush(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("flush did not start publication")
	}
	close(release)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
}

func TestRemoteDeliveryFlushCanCancelWhileSerialized(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	conf.Name = "security"
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = recorder.Close() })
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(ctx context.Context, _ SealedSegment) error {
		started <- struct{}{}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	})}
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	require.NoError(t, delivery.Start())
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.cancel-flush"}))
	require.NoError(t, recorder.(SealableRecorder).Seal())

	first := make(chan error, 1)
	go func() { first <- delivery.Flush(context.Background()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first flush did not start publication")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, delivery.Flush(canceled), context.Canceled)
	close(release)
	require.NoError(t, <-first)
}

func TestRemoteDeliveryLocksItsCursorState(t *testing.T) {
	conf, identity, _ := newRemoteDeliveryTestJournal(t, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", nil)}
	first, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })
	second, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.Nil(t, second)
	require.ErrorContains(t, err, "cannot lock remote delivery state")
	require.NoError(t, first.Close())
}

func TestRemoteDeliveryBackoffIsBounded(t *testing.T) {
	options := remoteDeliveryOptions{
		initialBackoff: time.Second,
		maximumBackoff: 5 * time.Second,
		jitter:         func(value time.Duration) time.Duration { return value },
	}
	require.Equal(t, time.Second, remoteDeliveryBackoff(1, options))
	require.Equal(t, 2*time.Second, remoteDeliveryBackoff(2, options))
	require.Equal(t, 4*time.Second, remoteDeliveryBackoff(3, options))
	require.Equal(t, 5*time.Second, remoteDeliveryBackoff(4, options))
	require.Equal(t, 5*time.Second, remoteDeliveryBackoff(100, options))
	for range 100 {
		delay := jitterRemoteDeliveryBackoff(time.Second)
		require.GreaterOrEqual(t, delay, 500*time.Millisecond)
		require.LessOrEqual(t, delay, time.Second)
	}
}

func newRemoteDeliveryTestJournal(t *testing.T, count int) (configuration.Auditlog, *Identity, []journalSegmentFile) {
	t.Helper()
	conf, identity := newJournalTestIdentity(t)
	conf.Name = "security"
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	local := recorder.(*localJournalRecorder)
	local.targetSize = local.state.contentBytes + 1
	for index := range count {
		require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.delivery." + leftPadUint(uint64(index+1), 2)}))
	}
	require.NoError(t, recorder.Close())
	segments, _, err := inventoryJournalSegments(producerJournalTestDirectory(conf, identity))
	require.NoError(t, err)
	require.Len(t, segments, count)
	return conf, identity, segments
}

func remoteDeliveryTestTarget(name configuration.AuditlogTargetName, publish func(context.Context, SealedSegment) error) configuration.AuditlogTarget {
	return configuration.AuditlogTarget{
		Name: name,
		V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
			return &remoteTargetTestInstance{publish: publish}, nil
		}},
	}
}

func setRemoteDeliveryTestOptions(delivery *RemoteDelivery) {
	options := remoteDeliveryOptions{
		idleDelay:      2 * time.Millisecond,
		initialBackoff: 2 * time.Millisecond,
		maximumBackoff: 5 * time.Millisecond,
		jitter:         func(value time.Duration) time.Duration { return value },
	}
	for _, worker := range delivery.workers {
		worker.options = options
	}
}

func remoteDeliveryTestCursorSequence(conf configuration.Auditlog, identity *Identity, target configuration.AuditlogTargetName) uint64 {
	path := filepath.Join(conf.Journal.Directory, remoteDeliveryStateDirectoryName, identity.ProducerId().String(), remoteDeliveryTargetStateName(target), remoteDeliveryCursorFileName)
	payload, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	cursor, err := decodeRemoteDeliveryCursor(payload, identity, target)
	if err != nil {
		return 0
	}
	return cursor.Sequence
}
