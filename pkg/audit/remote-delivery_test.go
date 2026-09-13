package audit

import (
	"context"
	goerrors "errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
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

func TestRemoteDeliveryCloseCanUnblockCustomPublish(t *testing.T) {
	conf, identity, _ := newRemoteDeliveryTestJournal(t, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	conf.Targets = configuration.AuditlogTargets{{
		Name: "archive",
		V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
			return &remoteTargetTestInstance{
				publish: func(context.Context, SealedSegment) error {
					close(started)
					<-release
					return context.Canceled
				},
				close: func() error {
					close(release)
					return nil
				},
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

	closed := make(chan error, 1)
	go func() { closed <- delivery.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("target Close did not unblock active Publish")
	}
}

func TestRemoteDeliveryTimesOutEachPublishAttemptIndependently(t *testing.T) {
	conf, identity, _ := newRemoteDeliveryTestJournal(t, 1)
	deadlines := make(chan time.Time, 3)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(ctx context.Context, _ SealedSegment) error {
		deadline, _ := ctx.Deadline()
		deadlines <- deadline
		<-ctx.Done()
		return ctx.Err()
	})}

	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	delivery.workers[0].publishAttemptTimeout = 15 * time.Millisecond
	require.NoError(t, delivery.Start())
	first := <-deadlines
	second := <-deadlines
	require.False(t, first.IsZero())
	require.False(t, second.IsZero())
	require.Greater(t, second.Sub(first), 5*time.Millisecond)

	started := time.Now()
	require.NoError(t, delivery.Close())
	require.Less(t, time.Since(started), time.Second)
}

func TestRemoteDeliveryWakesForNewSegmentWithoutIdlePolling(t *testing.T) {
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
	for _, worker := range delivery.workers {
		worker.options.idleDelay = time.Hour
	}
	require.NoError(t, delivery.Start())
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.watcher-wake"}))
	require.NoError(t, recorder.(SealableRecorder).Seal())
	select {
	case sequence := <-published:
		require.Equal(t, uint64(1), sequence)
	case <-time.After(time.Second):
		t.Fatal("new segment was not delivered from the directory notification")
	}
}

func TestRemoteDeliverySegmentReaderScansLargeBacklogOnceWithBoundedMemory(t *testing.T) {
	directory := t.TempDir()
	tempDirectory := t.TempDir()
	content := []byte("sealed segment")
	hash := hashJournalBytes(journalSegmentHashDomain, content)
	lastSequence := uint64(journalSegmentSortChunkSize + 17)
	for sequence := uint64(1); sequence <= lastSequence; sequence++ {
		name := sealedJournalFileName(sequence, hash)
		segmentPath := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(segmentPath, content, journalFileMode))
		require.NoError(t, os.Chmod(segmentPath, 0o400))
	}
	reader := remoteDeliverySegmentReader{
		directory:     directory,
		producerId:    ProducerId{1},
		tempDirectory: tempDirectory,
	}
	defer reader.Close()
	observed := make(chan journalSegmentFile)
	var force atomic.Bool
	var confirmed uint64
	for confirmed < lastSequence {
		result := reader.Next(context.Background(), confirmed, observed, &force)
		if result.err != nil {
			require.NoError(t, result.err)
		}
		if !result.exists {
			require.True(t, result.more)
			continue
		}
		require.Equal(t, confirmed+1, result.segment.Sequence())
		require.NoError(t, result.file.Close())
		confirmed = result.segment.Sequence()
	}
	require.Equal(t, uint64(1), reader.scanCount)
	require.LessOrEqual(t, reader.maximumScanChunk, journalSegmentSortChunkSize)
	runs, err := os.ReadDir(tempDirectory)
	require.NoError(t, err)
	require.Empty(t, runs)
}

func TestRemoteDeliverySegmentReaderAdvancesThroughBacklog(t *testing.T) {
	directory := t.TempDir()
	content := []byte("sealed segment")
	hash := hashJournalBytes(journalSegmentHashDomain, content)
	lastSequence := uint64(257)
	for sequence := uint64(1); sequence <= lastSequence; sequence++ {
		name := sealedJournalFileName(sequence, hash)
		segmentPath := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(segmentPath, content, journalFileMode))
		require.NoError(t, os.Chmod(segmentPath, 0o400))
	}
	reader := remoteDeliverySegmentReader{
		directory:  directory,
		producerId: ProducerId{1},
	}
	defer reader.Close()
	observed := make(chan journalSegmentFile)
	var force atomic.Bool
	var confirmed uint64
	for confirmed < lastSequence {
		result := reader.Next(context.Background(), confirmed, observed, &force)
		require.NoError(t, result.err)
		if !result.exists {
			require.True(t, result.more)
			continue
		}
		require.Equal(t, confirmed+1, result.segment.Sequence())
		require.NoError(t, result.file.Close())
		confirmed = result.segment.Sequence()
	}
	require.Equal(t, uint64(1), reader.scanCount)
}

func TestRemoteDeliverySegmentReaderTransitionsFromExhaustedToForcedRescan(t *testing.T) {
	directory := t.TempDir()
	reader := remoteDeliverySegmentReader{directory: directory, producerId: ProducerId{1}}
	defer reader.Close()
	observed := make(chan journalSegmentFile)
	var force atomic.Bool

	var result remoteDeliverySegmentResult
	for attempt := 0; attempt < 8; attempt++ {
		result = reader.Next(context.Background(), 0, observed, &force)
		require.NoError(t, result.err)
		if !result.more {
			break
		}
	}
	require.False(t, result.exists)
	require.True(t, reader.exhausted)
	require.Equal(t, uint64(1), reader.scanCount)

	content := []byte("sealed segment")
	hash := hashJournalBytes(journalSegmentHashDomain, content)
	path := filepath.Join(directory, sealedJournalFileName(1, hash))
	require.NoError(t, os.WriteFile(path, content, journalFileMode))
	require.NoError(t, os.Chmod(path, 0o400))

	result = reader.Next(context.Background(), 0, observed, &force)
	require.NoError(t, result.err)
	require.False(t, result.exists)
	require.False(t, result.more)
	require.Equal(t, uint64(1), reader.scanCount)

	force.Store(true)
	for attempt := 0; attempt < 8; attempt++ {
		result = reader.Next(context.Background(), 0, observed, &force)
		require.NoError(t, result.err)
		if result.exists {
			break
		}
		require.True(t, result.more)
	}
	require.True(t, result.exists)
	require.Equal(t, uint64(1), result.segment.Sequence())
	require.NoError(t, result.file.Close())
	require.Equal(t, uint64(2), reader.scanCount)
}

func TestRemoteDeliverySegmentReaderPermanentlyRejectsDuplicatesAcrossBatches(t *testing.T) {
	directory := t.TempDir()
	first := sealedJournalFileName(1, journalHash{1})
	second := sealedJournalFileName(1, journalHash{2})
	require.NoError(t, os.WriteFile(filepath.Join(directory, first), []byte("first"), journalFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(directory, second), []byte("second"), journalFileMode))
	reader := remoteDeliverySegmentReader{
		directory:     directory,
		producerId:    ProducerId{1},
		readBatchSize: 1,
	}
	defer reader.Close()
	observed := make(chan journalSegmentFile)
	var force atomic.Bool

	var result remoteDeliverySegmentResult
	for attempt := 0; attempt < 8; attempt++ {
		result = reader.Next(context.Background(), 0, observed, &force)
		if result.err != nil {
			break
		}
		require.False(t, result.exists)
		require.True(t, result.more)
	}
	require.ErrorContains(t, result.err, "multiple local segments with sequence 1")
	require.Nil(t, result.file)
	require.False(t, result.exists)
	require.False(t, result.more)
	require.Nil(t, reader.scan)
	require.Nil(t, reader.iterator)

	force.Store(true)
	retry := reader.Next(context.Background(), 0, observed, &force)
	require.EqualError(t, retry.err, result.err.Error())
	require.Nil(t, retry.file)
	require.False(t, retry.exists)
	require.False(t, retry.more)
}

func TestRemoteDeliverySegmentReaderPermanentlyRejectsGapBeyondCacheWindow(t *testing.T) {
	directory := t.TempDir()
	sequence := uint64(journalSegmentSortChunkSize + 1)
	name := sealedJournalFileName(sequence, journalHash{1})
	require.NoError(t, os.WriteFile(filepath.Join(directory, name), []byte("later"), journalFileMode))
	reader := remoteDeliverySegmentReader{
		directory:     directory,
		producerId:    ProducerId{1},
		readBatchSize: 1,
	}
	defer reader.Close()
	observed := make(chan journalSegmentFile)
	var force atomic.Bool

	var result remoteDeliverySegmentResult
	for attempt := 0; attempt < 10; attempt++ {
		result = reader.Next(context.Background(), 0, observed, &force)
		if result.err != nil {
			break
		}
		require.Nil(t, result.file)
		require.False(t, result.exists)
		require.True(t, result.more)
	}
	require.ErrorContains(t, result.err, "missing local segment sequence 1")
	require.ErrorContains(t, result.err, "later sequence 1025")
	require.Nil(t, result.file)
	require.False(t, result.exists)
	require.False(t, result.more)

	force.Store(true)
	retry := reader.Next(context.Background(), 0, observed, &force)
	require.EqualError(t, retry.err, result.err.Error())
}

func TestRemoteDeliverySegmentReaderDoesNotConfirmGapAcrossObservedChange(t *testing.T) {
	directory := t.TempDir()
	content := []byte("sealed segment")
	hash := hashJournalBytes(journalSegmentHashDomain, content)
	writeSegment := func(sequence uint64) journalSegmentFile {
		name := sealedJournalFileName(sequence, hash)
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, content, journalFileMode))
		require.NoError(t, os.Chmod(path, 0o400))
		return journalSegmentFile{name: name, path: path, sequence: sequence, hash: hash}
	}
	writeSegment(2)
	observed := make(chan journalSegmentFile, 1)
	reader := remoteDeliverySegmentReader{
		directory:     directory,
		producerId:    ProducerId{1},
		readBatchSize: 1,
	}
	added := false
	reader.scanEntryHook = func(_ context.Context, _ journalSegmentFile) error {
		if reader.scanCount == 2 && !added {
			added = true
			observed <- writeSegment(1)
		}
		return nil
	}
	defer reader.Close()
	var force atomic.Bool
	for attempt := 0; attempt < 16; attempt++ {
		result := reader.Next(context.Background(), 0, observed, &force)
		require.NoError(t, result.err)
		if result.exists {
			require.Equal(t, uint64(1), result.segment.Sequence())
			require.NoError(t, result.file.Close())
			return
		}
	}
	t.Fatal("observed segment did not invalidate the confirming gap scan")
}

func TestRemoteDeliverySegmentReaderPreservesScanProgressAcrossTimeout(t *testing.T) {
	directory := t.TempDir()
	content := []byte("sealed segment")
	hash := hashJournalBytes(journalSegmentHashDomain, content)
	for sequence := uint64(1); sequence <= 2; sequence++ {
		path := filepath.Join(directory, sealedJournalFileName(sequence, hash))
		require.NoError(t, os.WriteFile(path, content, journalFileMode))
		require.NoError(t, os.Chmod(path, 0o400))
	}
	blocked := false
	reader := remoteDeliverySegmentReader{
		directory:     directory,
		producerId:    ProducerId{1},
		readBatchSize: 1,
		scanEntryHook: func(ctx context.Context, _ journalSegmentFile) error {
			if blocked {
				return nil
			}
			blocked = true
			<-ctx.Done()
			return ctx.Err()
		},
	}
	defer reader.Close()
	observed := make(chan journalSegmentFile)
	var force atomic.Bool
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	for {
		result := reader.Next(ctx, 0, observed, &force)
		if result.err != nil {
			require.ErrorIs(t, result.err, context.DeadlineExceeded)
			break
		}
	}
	require.Equal(t, uint64(1), reader.scanCount)

	var result remoteDeliverySegmentResult
	for attempt := 0; attempt < 8; attempt++ {
		result = reader.Next(context.Background(), 0, observed, &force)
		require.NoError(t, result.err)
		if result.exists {
			break
		}
	}
	require.Equal(t, uint64(1), result.segment.Sequence())
	require.NotNil(t, result.file)
	require.NoError(t, result.file.Close())
	require.Equal(t, uint64(1), reader.scanCount)
}

func TestRemoteDeliverySegmentReaderInvalidatesFailedSegmentOpen(t *testing.T) {
	directory := t.TempDir()
	content := []byte("sealed segment")
	hash := hashJournalBytes(journalSegmentHashDomain, content)
	segmentPath := filepath.Join(directory, sealedJournalFileName(1, hash))
	require.NoError(t, os.WriteFile(segmentPath, []byte("broken segment"), journalFileMode))
	require.NoError(t, os.Chmod(segmentPath, 0o400))
	reader := remoteDeliverySegmentReader{directory: directory, producerId: ProducerId{1}}
	defer reader.Close()
	observed := make(chan journalSegmentFile)
	var force atomic.Bool
	for {
		result := reader.Next(context.Background(), 0, observed, &force)
		if result.err != nil {
			require.ErrorContains(t, result.err, "does not match hash")
			break
		}
		require.True(t, result.more)
	}
	require.NoError(t, makeActiveJournalWritable(segmentPath))
	require.NoError(t, os.WriteFile(segmentPath, content, journalFileMode))
	require.NoError(t, os.Chmod(segmentPath, 0o400))

	for {
		result := reader.Next(context.Background(), 0, observed, &force)
		require.NoError(t, result.err)
		if result.exists {
			require.Equal(t, uint64(1), result.segment.Sequence())
			require.NoError(t, result.file.Close())
			break
		}
		require.True(t, result.more)
	}
	require.Equal(t, uint64(2), reader.scanCount)
}

func TestRemoteDeliverySegmentReaderRebuildsAfterLiveAppendAtEOF(t *testing.T) {
	directory := t.TempDir()
	content := []byte("sealed segment")
	hash := hashJournalBytes(journalSegmentHashDomain, content)
	writeSegment := func(sequence uint64) journalSegmentFile {
		name := sealedJournalFileName(sequence, hash)
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, content, journalFileMode))
		require.NoError(t, os.Chmod(path, 0o400))
		return journalSegmentFile{name: name, path: path, sequence: sequence, hash: hash}
	}
	writeSegment(1)
	reader := remoteDeliverySegmentReader{directory: directory, producerId: ProducerId{1}}
	defer reader.Close()
	observed := make(chan journalSegmentFile, 1)
	var force atomic.Bool
	next := func(confirmed uint64) SealedSegment {
		for attempt := 0; attempt < 8; attempt++ {
			result := reader.Next(context.Background(), confirmed, observed, &force)
			require.NoError(t, result.err)
			if result.exists {
				require.NoError(t, result.file.Close())
				return result.segment
			}
		}
		t.Fatal("segment was not discovered")
		return SealedSegment{}
	}
	require.Equal(t, uint64(1), next(0).Sequence())
	require.Equal(t, uint64(1), reader.scanCount)
	observed <- writeSegment(2)
	require.Equal(t, uint64(2), next(1).Sequence())
	require.Equal(t, uint64(2), reader.scanCount)
}

func TestRemoteDeliverySegmentReaderDetectsDuplicateAddedAfterCursorProgress(t *testing.T) {
	directory := t.TempDir()
	content := []byte("sealed segment")
	hash := hashJournalBytes(journalSegmentHashDomain, content)
	firstName := sealedJournalFileName(1, hash)
	firstPath := filepath.Join(directory, firstName)
	require.NoError(t, os.WriteFile(firstPath, content, journalFileMode))
	require.NoError(t, os.Chmod(firstPath, 0o400))
	reader := remoteDeliverySegmentReader{directory: directory, producerId: ProducerId{1}}
	defer reader.Close()
	observed := make(chan journalSegmentFile, 2)
	var force atomic.Bool
	for {
		result := reader.Next(context.Background(), 0, observed, &force)
		require.NoError(t, result.err)
		if result.exists {
			require.Equal(t, uint64(1), result.segment.Sequence())
			require.NoError(t, result.file.Close())
			break
		}
	}
	duplicateName := sealedJournalFileName(1, journalHash{9})
	require.NoError(t, os.WriteFile(filepath.Join(directory, duplicateName), []byte("mutated"), journalFileMode))
	secondName := sealedJournalFileName(2, hash)
	require.NoError(t, os.WriteFile(filepath.Join(directory, secondName), content, journalFileMode))
	observed <- journalSegmentFile{name: duplicateName, sequence: 1, hash: journalHash{9}}
	observed <- journalSegmentFile{name: secondName, sequence: 2, hash: hash}

	var result remoteDeliverySegmentResult
	for attempt := 0; attempt < 8; attempt++ {
		result = reader.Next(context.Background(), 1, observed, &force)
		if result.err != nil {
			break
		}
	}
	require.ErrorContains(t, result.err, "multiple local segments with sequence 1")
}

func TestRemoteDeliveryFsnotifyWakeDoesNotInterruptFailureBackoff(t *testing.T) {
	worker := remoteDeliveryWorker{
		wake:          make(chan struct{}, 1),
		discoveryWake: make(chan struct{}, 1),
		observed:      make(chan journalSegmentFile, 1),
	}
	worker.observe(journalSegmentFile{sequence: 1})

	select {
	case <-worker.wake:
		t.Fatal("filesystem observation woke the failure-backoff channel")
	default:
	}
	select {
	case <-worker.discoveryWake:
	default:
		t.Fatal("filesystem observation did not wake idle discovery")
	}
}

func TestRemoteDeliveryRetriesFailedTailImmediatelyAfterBackoff(t *testing.T) {
	conf, identity, _ := newRemoteDeliveryTestJournal(t, 1)
	attempts := make(chan time.Time, 2)
	var publications atomic.Int32
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(_ context.Context, _ SealedSegment) error {
		attempts <- time.Now()
		if publications.Add(1) == 1 {
			return goerrors.New("temporary tail failure")
		}
		return nil
	})}
	targets, err := NewRemoteTargets(context.Background(), conf.Name, conf.Targets)
	require.NoError(t, err)
	const backoff = 40 * time.Millisecond
	options := defaultRemoteDeliveryOptions()
	options.idleDelay = time.Minute
	options.initialBackoff = backoff
	options.maximumBackoff = backoff
	options.jitter = func(value time.Duration) time.Duration { return value }
	delivery, err := newRemoteDelivery(context.Background(), &conf, identity, targets, options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	require.NoError(t, delivery.Start())
	var first time.Time
	select {
	case first = <-attempts:
	case <-time.After(time.Second):
		t.Fatal("initial tail publication did not start")
	}
	select {
	case second := <-attempts:
		require.GreaterOrEqual(t, second.Sub(first), backoff)
		require.Less(t, second.Sub(first), 500*time.Millisecond)
	case <-time.After(time.Second):
		t.Fatal("failed tail was not retried without a discovery wake")
	}
}

func TestRemoteDeliveryFallsBackToPeriodicPollingWithoutFsnotify(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*remoteDeliveryOptions)
	}{
		{
			name: "new-watcher-failure",
			configure: func(options *remoteDeliveryOptions) {
				options.newWatcher = func() (*fsnotify.Watcher, error) {
					return nil, goerrors.New("watcher unavailable")
				}
			},
		},
		{
			name: "add-watch-failure",
			configure: func(options *remoteDeliveryOptions) {
				options.addWatch = func(*fsnotify.Watcher, string) error {
					return goerrors.New("watch unsupported")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			targets, err := NewRemoteTargets(context.Background(), conf.Name, conf.Targets)
			require.NoError(t, err)
			options := defaultRemoteDeliveryOptions()
			options.idleDelay = 5 * time.Millisecond
			test.configure(&options)
			delivery, err := newRemoteDelivery(context.Background(), &conf, identity, targets, options)
			require.NoError(t, err)
			t.Cleanup(func() { _ = delivery.Close() })
			require.Nil(t, delivery.watcher)
			require.NoError(t, delivery.Start())
			time.Sleep(20 * time.Millisecond)

			require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.polling-fallback"}))
			require.NoError(t, recorder.(SealableRecorder).Seal())
			select {
			case sequence := <-published:
				require.Equal(t, uint64(1), sequence)
			case <-time.After(time.Second):
				t.Fatal("periodic polling did not discover the sealed segment")
			}
			require.NoError(t, delivery.Close())
		})
	}
}

func TestRemoteDeliveryDestinationChangeFailsClosedButCredentialRotationContinues(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 1)
	target := configuration.AuditlogTarget{
		Name: "archive",
		V: &configuration.AuditlogTargetWebdav{
			Endpoint: "https://dav.example.invalid/audit/",
			Username: template.MustNewString("old-user"),
			Password: template.MustNewString("old-secret"),
		},
	}
	conf.Targets = configuration.AuditlogTargets{target}
	_, fingerprint, err := remoteDeliveryTargetSettings(target.V)
	require.NoError(t, err)
	stateDirectory, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
	require.NoError(t, err)
	_, err = loadRemoteDeliveryCursor(stateDirectory, identity, target.Name, fingerprint)
	require.NoError(t, err)
	targetDirectory := filepath.Join(stateDirectory, remoteDeliveryTargetStateName(target.Name))
	_, err = writeRemoteDeliveryCursor(targetDirectory, identity, target.Name, fingerprint, segments[0].sequence, SegmentHash(segments[0].hash))
	require.NoError(t, err)

	rotated := *target.V.(*configuration.AuditlogTargetWebdav)
	rotated.Password = template.MustNewString("new-secret")
	conf.Targets[0].V = &rotated
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	require.NoError(t, delivery.Close())

	moved := rotated
	moved.Username = template.MustNewString("new-user")
	conf.Targets[0].V = &moved
	delivery, err = NewRemoteDelivery(context.Background(), &conf, identity)
	require.Nil(t, delivery)
	require.ErrorContains(t, err, "different destination")
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
	segments, _, err := inventoryJournalTestSegments(producerJournalTestDirectory(conf, identity))
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
	var fingerprint remoteDeliveryDestinationFingerprint
	for _, candidate := range conf.Targets {
		if candidate.Name == target {
			_, fingerprint, err = customRemoteDeliveryTargetSettings(candidate.V, RemoteTargetSettings{
				DestinationIdentity: remoteTargetTestDestinationIdentity, PublishAttemptTimeout: time.Minute,
			})
			if err != nil {
				return 0
			}
			break
		}
	}
	cursor, err := decodeRemoteDeliveryCursor(payload, identity, target, fingerprint)
	if err != nil {
		return 0
	}
	return cursor.Sequence
}
