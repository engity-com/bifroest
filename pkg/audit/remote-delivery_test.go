package audit

import (
	"bytes"
	"context"
	goerrors "errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/nativeformat"
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
	for _, segment := range segments {
		content, err := os.ReadFile(segment.path)
		require.NoError(t, err)
		require.Equal(t, segment.hash, hashNativeAuditSegment(content))
	}

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

func TestRemoteDeliveryPublishesNativeBytesAndEncryptedName(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			conf, identity := nativeRecorderTestConfig(t, encrypted)
			conf.Name = "security"
			recorder := nativeTestOpen(t, &conf, identity)
			require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.native-delivery"}))
			require.NoError(t, recorder.Seal())
			require.NoError(t, recorder.Close())
			entries, _, _, err := nativeInventory(filepath.Join(conf.Journal.Directory, identity.ProducerId().String()),
				map[bool]string{false: nativeActiveClear, true: nativeActiveEncrypted}[encrypted], encrypted)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			original, err := os.ReadFile(entries[0].path)
			require.NoError(t, err)
			conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(_ context.Context, segment SealedSegment) error {
				require.Equal(t, filepath.Base(entries[0].path), segment.FileName())
				require.Equal(t, identity.ProducerId().String()+"/"+segment.FileName(), segment.RemotePath())
				require.Equal(t, SegmentHash(hashNativeAuditSegment(original)), segment.Hash())
				content, err := io.ReadAll(segment.Content())
				require.NoError(t, err)
				require.True(t, bytes.Equal(original, content))
				return nil
			})}
			delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
			require.NoError(t, err)
			t.Cleanup(func() { _ = delivery.Close() })
			setRemoteDeliveryTestOptions(delivery)
			require.NoError(t, delivery.Start())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			require.NoError(t, delivery.Flush(ctx))
			require.Equal(t, uint64(1), remoteDeliveryTestCursorSequence(conf, identity, "archive"))
			require.NoError(t, delivery.Close())
			restarted := nativeTestOpen(t, &conf, identity)
			require.NoError(t, restarted.Close())
		})
	}
}

func TestRemoteDeliveryRejectsOldLocalDataAndMissingConfirmedHistory(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 2)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", nil)}
	state, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
	require.NoError(t, err)
	_, fingerprint, err := customRemoteDeliveryTargetSettings(conf.Targets[0].V, RemoteTargetSettings{
		DestinationIdentity: remoteTargetTestDestinationIdentity, PublishAttemptTimeout: time.Minute,
	})
	require.NoError(t, err)
	_, err = loadRemoteDeliveryCursor(state, identity, "archive", fingerprint)
	require.NoError(t, err)
	_, err = writeRemoteDeliveryCursor(filepath.Join(state, remoteDeliveryTargetStateName("archive")), identity, "archive", fingerprint, 2, SegmentHash(segments[1].hash))
	require.NoError(t, err)
	require.NoError(t, os.Remove(segments[0].path))
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.Nil(t, delivery)
	require.ErrorContains(t, err, "missing or duplicate local segment")

	old := filepath.Join(filepath.Dir(segments[1].path), sealedJournalFileName(1, journalHash{1}))
	require.NoError(t, os.WriteFile(old, []byte("old format"), journalFileMode))
	delivery, err = NewRemoteDelivery(context.Background(), &conf, identity)
	require.Nil(t, delivery)
	require.ErrorContains(t, err, "unsupported delivery entry")
	require.FileExists(t, old)
}

func TestRemoteDeliveryCursorCannotHideGapWithDuplicate(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 3)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", nil)}
	state, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
	require.NoError(t, err)
	_, fingerprint, err := customRemoteDeliveryTargetSettings(conf.Targets[0].V, RemoteTargetSettings{
		DestinationIdentity: remoteTargetTestDestinationIdentity, PublishAttemptTimeout: time.Minute,
	})
	require.NoError(t, err)
	_, err = loadRemoteDeliveryCursor(state, identity, "archive", fingerprint)
	require.NoError(t, err)
	_, err = writeRemoteDeliveryCursor(filepath.Join(state, remoteDeliveryTargetStateName("archive")), identity, "archive", fingerprint, 3, SegmentHash(segments[2].hash))
	require.NoError(t, err)
	require.NoError(t, os.Remove(segments[1].path))
	duplicate := filepath.Join(filepath.Dir(segments[0].path), nativeSegmentName(1, journalHash{9}, false))
	require.NoError(t, os.WriteFile(duplicate, []byte("duplicate"), journalFileMode))
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.Nil(t, delivery)
	require.ErrorContains(t, err, "missing or duplicate local segment")
}

func TestRemoteDeliveryRejectsUnsealedAndAlteredNativeSegment(t *testing.T) {
	_, identity, segments := newRemoteDeliveryTestJournal(t, 1)
	content, err := os.ReadFile(segments[0].path)
	require.NoError(t, err)
	old := segments[0].path
	wrongHash := hashNativeAuditSegment(content[:len(content)-1])
	wrongPath := filepath.Join(filepath.Dir(old), nativeSegmentName(1, wrongHash, false))
	require.NoError(t, os.Rename(old, wrongPath))
	require.NoError(t, os.WriteFile(wrongPath, content[:len(content)-1], journalFileMode))
	candidate := journalSegmentFile{path: wrongPath, sequence: 1, hash: wrongHash}
	_, file, _, err := openRemoteDeliverySegment(context.Background(), identity, identity.ProducerId(), candidate, false, journalHash{}, journalHash{})
	require.Nil(t, file)
	require.ErrorContains(t, err, "invalid sealed native audit segment")

	require.NoError(t, os.Rename(wrongPath, old))
	content[len(content)-1] ^= 1
	require.NoError(t, os.WriteFile(old, content, journalFileMode))
	candidate = segments[0]
	_, file, _, err = openRemoteDeliverySegment(context.Background(), identity, identity.ProducerId(), candidate, false, journalHash{}, journalHash{})
	require.Nil(t, file)
	require.Error(t, err)
	require.FileExists(t, old)
}

func TestRemoteDeliveryRejectsSignedForkBeforePublish(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, sequence := range []uint64{1, 2} {
			for _, broken := range []string{"segment", "record"} {
				name := map[bool]string{false: "clear", true: "encrypted"}[encrypted] + "/seq" + leftPadUint(sequence, 1) + "/" + broken
				t.Run(name, func(t *testing.T) {
					conf, identity, segments, recipient, fingerprint := remoteDeliveryForkJournal(t, encrypted, int(sequence))
					var previousSegment, previousRecord journalHash
					if sequence == 2 {
						previousSegment = segments[0].hash
						file, err := nativeOpenRegular(segments[0].path)
						require.NoError(t, err)
						state, err := nativeScan(file, identity, 1, journalHash{}, journalHash{}, journalHash{}, true, fingerprint, false)
						require.NoError(t, err)
						require.NoError(t, file.Close())
						previousRecord = state.lastRecord
					}
					if broken == "segment" {
						previousSegment = journalHash{99}
					} else {
						previousRecord = journalHash{99}
					}
					fork := remoteDeliverySignedFork(t, identity, segments[sequence-1], previousSegment, previousRecord, fingerprint, recipient, encrypted)
					var calls atomic.Int32
					conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(_ context.Context, segment SealedSegment) error {
						calls.Add(1)
						require.Less(t, segment.Sequence(), sequence)
						return nil
					})}
					delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
					require.NoError(t, err)
					t.Cleanup(func() { _ = delivery.Close() })
					setRemoteDeliveryTestOptions(delivery)
					delivery.workers[0].options.initialBackoff = time.Second
					delivery.workers[0].options.maximumBackoff = time.Second
					require.NoError(t, delivery.Start())
					if sequence == 2 {
						require.Eventually(t, func() bool { return remoteDeliveryTestCursorSequence(conf, identity, "archive") == 1 }, time.Second, time.Millisecond)
					}
					time.Sleep(25 * time.Millisecond)
					require.Equal(t, int32(sequence-1), calls.Load())
					require.Equal(t, sequence-1, remoteDeliveryTestCursorSequence(conf, identity, "archive"))
					actual, err := os.ReadFile(fork.path)
					require.NoError(t, err)
					require.Equal(t, fork.content, actual)
					require.FileExists(t, fork.path)
				})
			}
		}
	}
}

func TestRemoteDeliveryRejectsSignedForkInCursorAndTemporaryRecovery(t *testing.T) {
	for _, temporary := range []bool{false, true} {
		t.Run(map[bool]string{false: "cursor", true: "cursor.tmp"}[temporary], func(t *testing.T) {
			conf, identity, segments, _, fingerprint := remoteDeliveryForkJournal(t, false, 2)
			fork := remoteDeliverySignedFork(t, identity, segments[1], journalHash{99}, journalHash{99}, fingerprint, nil, false)
			conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(context.Context, SealedSegment) error {
				t.Error("invalid local chain was published")
				return nil
			})}
			state, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
			require.NoError(t, err)
			_, destination, err := customRemoteDeliveryTargetSettings(conf.Targets[0].V, RemoteTargetSettings{
				DestinationIdentity: remoteTargetTestDestinationIdentity, PublishAttemptTimeout: time.Minute,
			})
			require.NoError(t, err)
			targetDirectory := filepath.Join(state, remoteDeliveryTargetStateName("archive"))
			_, err = loadRemoteDeliveryCursor(state, identity, "archive", destination)
			require.NoError(t, err)
			if temporary {
				_, err = writeRemoteDeliveryCursor(targetDirectory, identity, "archive", destination, 1, SegmentHash(segments[0].hash))
				require.NoError(t, err)
				_, payload, err := newRemoteDeliveryCursor(identity, "archive", destination, 2, SegmentHash(fork.hash))
				require.NoError(t, err)
				require.NoError(t, writeRemoteDeliveryTestFile(filepath.Join(targetDirectory, remoteDeliveryCursorTempFileName), payload))
			} else {
				_, err = writeRemoteDeliveryCursor(targetDirectory, identity, "archive", destination, 2, SegmentHash(fork.hash))
				require.NoError(t, err)
			}
			cursorPath := filepath.Join(targetDirectory, remoteDeliveryCursorFileName)
			before, err := os.ReadFile(cursorPath)
			require.NoError(t, err)
			delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
			require.Nil(t, delivery)
			require.ErrorContains(t, err, "invalid local segment")
			after, err := os.ReadFile(cursorPath)
			require.NoError(t, err)
			require.Equal(t, before, after)
			if temporary {
				require.FileExists(t, filepath.Join(targetDirectory, remoteDeliveryCursorTempFileName))
			}
			actual, err := os.ReadFile(fork.path)
			require.NoError(t, err)
			require.Equal(t, fork.content, actual)
		})
	}
}

func TestRemoteDeliveryRejectsCursorHashMismatch(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(context.Context, SealedSegment) error {
		t.Error("cursor with mismatched hash was published")
		return nil
	})}
	state, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
	require.NoError(t, err)
	_, destination, err := customRemoteDeliveryTargetSettings(conf.Targets[0].V, RemoteTargetSettings{
		DestinationIdentity: remoteTargetTestDestinationIdentity, PublishAttemptTimeout: time.Minute,
	})
	require.NoError(t, err)
	_, err = loadRemoteDeliveryCursor(state, identity, "archive", destination)
	require.NoError(t, err)
	_, err = writeRemoteDeliveryCursor(filepath.Join(state, remoteDeliveryTargetStateName("archive")), identity, "archive", destination, 1, SegmentHash{99})
	require.NoError(t, err)
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.Nil(t, delivery)
	require.ErrorContains(t, err, "conflicts with or confirms missing local segment")
	require.FileExists(t, segments[0].path)
	require.Equal(t, uint64(1), remoteDeliveryTestCursorSequence(conf, identity, "archive"))
}

func TestRemoteDeliveryValidatesBothCursorsInOneScanAndKeepsSortRunsOutOfProducer(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct-tmpdir", true: "aliased-tmpdir"}[alias], func(t *testing.T) {
			conf, identity, segments := newRemoteDeliveryTestJournal(t, 2)
			producerDirectory := filepath.Dir(segments[0].path)
			temporaryDirectory := producerDirectory
			if alias {
				temporaryDirectory = filepath.Join(t.TempDir(), "producer-alias")
				require.NoError(t, os.Symlink(producerDirectory, temporaryDirectory))
			}
			t.Setenv("TMPDIR", temporaryDirectory)
			for sequence := uint64(3); sequence <= journalSegmentSortChunkSize+1; sequence++ {
				name := nativeSegmentName(sequence, journalHash{byte(sequence)}, false)
				require.NoError(t, os.WriteFile(filepath.Join(producerDirectory, name), []byte("later"), journalFileMode))
			}
			conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", nil)}
			state, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
			require.NoError(t, err)
			_, destination, err := customRemoteDeliveryTargetSettings(conf.Targets[0].V, RemoteTargetSettings{
				DestinationIdentity: remoteTargetTestDestinationIdentity, PublishAttemptTimeout: time.Minute,
			})
			require.NoError(t, err)
			_, err = loadRemoteDeliveryCursor(state, identity, "archive", destination)
			require.NoError(t, err)
			targetDirectory := filepath.Join(state, remoteDeliveryTargetStateName("archive"))
			current, err := writeRemoteDeliveryCursor(targetDirectory, identity, "archive", destination, 1, SegmentHash(segments[0].hash))
			require.NoError(t, err)
			temporary, payload, err := newRemoteDeliveryCursor(identity, "archive", destination, 2, SegmentHash(segments[1].hash))
			require.NoError(t, err)
			require.NoError(t, writeRemoteDeliveryTestFile(filepath.Join(targetDirectory, remoteDeliveryCursorTempFileName), payload))
			var workspaces int
			records, err := validateRemoteDeliveryCursors(context.Background(), [2]remoteDeliveryCursor{current, temporary}, producerDirectory, "archive", false, identity, func() (*journalSegmentWorkspace, error) {
				workspaces++
				return newJournalSegmentWorkspaceInJournal(conf.Journal.Directory)
			})
			require.NoError(t, err)
			require.Equal(t, 1, workspaces)
			require.NotZero(t, records[0])
			require.NotZero(t, records[1])

			watcher, err := fsnotify.NewWatcher()
			require.NoError(t, err)
			require.NoError(t, watcher.Add(producerDirectory))
			t.Cleanup(func() { _ = watcher.Close() })
			delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
			require.NoError(t, err)
			require.NoError(t, delivery.Close())
			require.Equal(t, uint64(2), remoteDeliveryTestCursorSequence(conf, identity, "archive"))
			for {
				select {
				case event := <-watcher.Events:
					require.NotContains(t, filepath.Base(event.Name), ".bifroest-audit-segments-")
				default:
					entries, err := os.ReadDir(producerDirectory)
					require.NoError(t, err)
					for _, entry := range entries {
						require.NotContains(t, entry.Name(), ".bifroest-audit-segments-")
					}
					return
				}
			}
		})
	}
}

func TestRemoteDeliveryStartupUsesCallerContextForCursorScan(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", nil)}
	state, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
	require.NoError(t, err)
	_, destination, err := customRemoteDeliveryTargetSettings(conf.Targets[0].V, RemoteTargetSettings{
		DestinationIdentity: remoteTargetTestDestinationIdentity, PublishAttemptTimeout: time.Minute,
	})
	require.NoError(t, err)
	_, err = loadRemoteDeliveryCursor(state, identity, "archive", destination)
	require.NoError(t, err)
	_, err = writeRemoteDeliveryCursor(filepath.Join(state, remoteDeliveryTargetStateName("archive")), identity, "archive", destination, 1, SegmentHash(segments[0].hash))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	delivery, err := NewRemoteDelivery(ctx, &conf, identity)
	require.Nil(t, delivery)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRemoteDeliveryStartupDiscardsInvalidTemporarySignature(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", nil)}
	state, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
	require.NoError(t, err)
	_, destination, err := customRemoteDeliveryTargetSettings(conf.Targets[0].V, RemoteTargetSettings{
		DestinationIdentity: remoteTargetTestDestinationIdentity, PublishAttemptTimeout: time.Minute,
	})
	require.NoError(t, err)
	_, err = loadRemoteDeliveryCursor(state, identity, "archive", destination)
	require.NoError(t, err)
	directory := filepath.Join(state, remoteDeliveryTargetStateName("archive"))
	_, err = writeRemoteDeliveryCursor(directory, identity, "archive", destination, 1, SegmentHash(segments[0].hash))
	require.NoError(t, err)
	_, payload, err := newRemoteDeliveryCursor(identity, "archive", destination, 1, SegmentHash(segments[0].hash))
	require.NoError(t, err)
	payload[len(payload)-3] ^= 1
	temporary := filepath.Join(directory, remoteDeliveryCursorTempFileName)
	require.NoError(t, writeRemoteDeliveryTestFile(temporary, payload))
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	require.NoError(t, delivery.Close())
	require.NoFileExists(t, temporary)
	require.Equal(t, uint64(1), remoteDeliveryTestCursorSequence(conf, identity, "archive"))
}

func TestRemoteDeliveryUsesReconstructedRecordTipAfterRestart(t *testing.T) {
	conf, identity, segments, recipient, fingerprint := remoteDeliveryForkJournal(t, true, 2)
	fork := remoteDeliverySignedFork(t, identity, segments[1], segments[0].hash, journalHash{99}, fingerprint, recipient, true)
	var calls atomic.Int32
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(context.Context, SealedSegment) error {
		calls.Add(1)
		return nil
	})}
	state, err := prepareRemoteDeliveryState(conf.Journal.Directory, identity.ProducerId())
	require.NoError(t, err)
	_, destination, err := customRemoteDeliveryTargetSettings(conf.Targets[0].V, RemoteTargetSettings{
		DestinationIdentity: remoteTargetTestDestinationIdentity, PublishAttemptTimeout: time.Minute,
	})
	require.NoError(t, err)
	_, err = loadRemoteDeliveryCursor(state, identity, "archive", destination)
	require.NoError(t, err)
	_, err = writeRemoteDeliveryCursor(filepath.Join(state, remoteDeliveryTargetStateName("archive")), identity, "archive", destination, 1, SegmentHash(segments[0].hash))
	require.NoError(t, err)
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	require.NotZero(t, delivery.workers[0].lastRecord)
	setRemoteDeliveryTestOptions(delivery)
	delivery.workers[0].options.initialBackoff = time.Second
	delivery.workers[0].options.maximumBackoff = time.Second
	require.NoError(t, delivery.Start())
	time.Sleep(30 * time.Millisecond)
	require.Zero(t, calls.Load())
	require.Equal(t, uint64(1), remoteDeliveryTestCursorSequence(conf, identity, "archive"))
	actual, err := os.ReadFile(fork.path)
	require.NoError(t, err)
	require.Equal(t, fork.content, actual)
}

type remoteDeliveryForkFixture struct {
	path    string
	hash    journalHash
	content []byte
}

func remoteDeliveryForkJournal(t *testing.T, encrypted bool, count int) (configuration.Auditlog, *Identity, []journalSegmentFile, *bfcrypto.AgeSshRecipient, string) {
	t.Helper()
	conf, identity := nativeRecorderTestConfig(t, encrypted)
	conf.Name = "security"
	recorder := nativeTestOpen(t, &conf, identity)
	recipient, fingerprint := recorder.recipient, recorder.fingerprint
	for range count {
		require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.fork"}))
		require.NoError(t, recorder.Seal())
	}
	require.NoError(t, recorder.Close())
	entries, _, _, err := nativeInventory(filepath.Join(conf.Journal.Directory, identity.ProducerId().String()),
		map[bool]string{false: nativeActiveClear, true: nativeActiveEncrypted}[encrypted], encrypted)
	require.NoError(t, err)
	segments := make([]journalSegmentFile, 0, len(entries))
	for _, entry := range entries {
		segments = append(segments, journalSegmentFile{path: entry.path, sequence: entry.seq, hash: entry.hash})
	}
	require.Len(t, segments, count)
	return conf, identity, segments, recipient, fingerprint
}

func remoteDeliverySignedFork(t *testing.T, identity *Identity, original journalSegmentFile, previousSegment, previousRecord journalHash, fingerprint string, recipient *bfcrypto.AgeSshRecipient, encrypted bool) remoteDeliveryForkFixture {
	t.Helper()
	_, header, err := newNativeAuditHeader(identity, original.sequence, previousSegment, previousRecord, time.Now().UTC(), fingerprint)
	require.NoError(t, err)
	frame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, header, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	content := append([]byte(nativeformat.AuditMagic), frame...)
	_, record, recordHash, err := newNativeAuditRecord(identity, previousRecord, Event{Name: "test.signed-fork"}, uuid.New(), time.Now().UTC(), recipient)
	require.NoError(t, err)
	frame, err = nativeformat.EncodeUnit(nativeformat.ContentUnit, record, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	content = append(content, frame...)
	_, seal, err := newNativeAuditSeal(identity, original.sequence, 1, uint64(len(content)), hashNativeAuditContent(content), recordHash, time.Now().UTC())
	require.NoError(t, err)
	frame, err = nativeformat.EncodeUnit(nativeformat.SealUnit, seal, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	content = append(content, frame...)
	hash := hashNativeAuditSegment(content)
	path := filepath.Join(filepath.Dir(original.path), nativeSegmentName(original.sequence, hash, encrypted))
	require.NoError(t, os.Remove(original.path))
	require.NoError(t, os.WriteFile(path, content, journalFileMode))
	file, err := nativeOpenRegular(path)
	require.NoError(t, err)
	state, err := nativeScan(file, identity, original.sequence, previousSegment, previousRecord, journalHash{}, true, fingerprint, false)
	require.NoError(t, err)
	require.Equal(t, hash, state.segmentHash)
	require.NoError(t, file.Close())
	return remoteDeliveryForkFixture{path: path, hash: hash, content: content}
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
	var calls atomic.Int32
	published := make(chan struct{}, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(context.Context, SealedSegment) error {
		if calls.Add(1) == 1 {
			published <- struct{}{}
		}
		return nil
	})}

	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	var cursorWritable atomic.Bool
	cursorAttempted := make(chan struct{}, 1)
	delivery.workers[0].commitCursorHook = func() error {
		if cursorWritable.Load() {
			return nil
		}
		select {
		case cursorAttempted <- struct{}{}:
		default:
		}
		return goerrors.New("cursor unavailable")
	}
	require.NoError(t, delivery.Start())
	select {
	case <-published:
	case <-time.After(time.Second):
		t.Fatal("segment was not published")
	}
	select {
	case <-cursorAttempted:
	case <-time.After(time.Second):
		t.Fatal("cursor write was not attempted")
	}
	time.Sleep(25 * time.Millisecond)
	require.Equal(t, int32(1), calls.Load())
	cursorWritable.Store(true)
	require.Eventually(t, func() bool {
		return remoteDeliveryTestCursorSequence(conf, identity, "archive") == 1
	}, time.Second, time.Millisecond)
	require.Equal(t, int32(1), calls.Load())
	require.NoError(t, delivery.Close())
}

func TestRemoteDeliveryKeepsRecordTipUntilCursorCommit(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 2)
	var calls atomic.Int32
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(_ context.Context, segment SealedSegment) error {
		calls.Add(1)
		require.LessOrEqual(t, segment.Sequence(), uint64(2))
		return nil
	})}
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	var writable atomic.Bool
	delivery.workers[0].commitCursorHook = func() error {
		if !writable.Load() {
			return goerrors.New("cursor unavailable")
		}
		return nil
	}
	require.NoError(t, delivery.Start())
	require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	require.Zero(t, remoteDeliveryTestCursorSequence(conf, identity, "archive"))
	require.Zero(t, delivery.workers[0].lastRecord)
	require.Zero(t, delivery.workers[0].reader.previousRecord)
	require.Equal(t, int32(1), calls.Load())
	writable.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, delivery.Flush(ctx))
	require.Equal(t, int32(2), calls.Load())
	require.Equal(t, uint64(2), remoteDeliveryTestCursorSequence(conf, identity, "archive"))
	for _, segment := range segments {
		require.FileExists(t, segment.path)
	}
}

func TestRemoteDeliveryDoesNotAdvanceRecordTipOnFailedPublish(t *testing.T) {
	conf, identity, _ := newRemoteDeliveryTestJournal(t, 2)
	var calls atomic.Int32
	failed := make(chan struct{}, 1)
	conf.Targets = configuration.AuditlogTargets{remoteDeliveryTestTarget("archive", func(_ context.Context, segment SealedSegment) error {
		if calls.Add(1) == 1 {
			require.Equal(t, uint64(1), segment.Sequence())
			failed <- struct{}{}
			return goerrors.New("temporary publish failure")
		}
		return nil
	})}
	delivery, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = delivery.Close() })
	setRemoteDeliveryTestOptions(delivery)
	delivery.workers[0].options.initialBackoff = time.Hour
	delivery.workers[0].options.maximumBackoff = time.Hour
	require.NoError(t, delivery.Start())
	select {
	case <-failed:
	case <-time.After(time.Second):
		t.Fatal("first publish was not attempted")
	}
	require.Zero(t, delivery.workers[0].reader.previousRecord)
	require.Zero(t, remoteDeliveryTestCursorSequence(conf, identity, "archive"))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, delivery.Flush(ctx))
	require.Equal(t, int32(3), calls.Load())
	require.Equal(t, uint64(2), remoteDeliveryTestCursorSequence(conf, identity, "archive"))
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
	recorder, err := newNativeRecorder(&conf, identity)
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
	hash := hashNativeAuditSegment(content)
	lastSequence := uint64(journalSegmentSortChunkSize + 17)
	for sequence := uint64(1); sequence <= lastSequence; sequence++ {
		name := nativeSegmentName(sequence, hash, false)
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

func TestRemoteDeliverySegmentReaderDefaultWorkspaceIsOutsideProducer(t *testing.T) {
	journalDirectory := t.TempDir()
	producerDirectory := filepath.Join(journalDirectory, "producer")
	require.NoError(t, os.Mkdir(producerDirectory, 0o700))
	t.Setenv("TMPDIR", producerDirectory)
	content := []byte("sealed segment")
	hash := hashNativeAuditSegment(content)
	for sequence := uint64(1); sequence <= journalSegmentSortChunkSize+1; sequence++ {
		path := filepath.Join(producerDirectory, nativeSegmentName(sequence, hash, false))
		require.NoError(t, os.WriteFile(path, content, journalFileMode))
	}
	reader := remoteDeliverySegmentReader{directory: producerDirectory, producerId: ProducerId{1}}
	defer reader.Close()
	var inspected bool
	reader.scanEntryHook = func(_ context.Context, _ journalSegmentFile) error {
		if reader.scan.sorter.workspace != nil {
			inspected = true
			require.Equal(t, filepath.Join(journalDirectory, journalWorkDirectoryName), filepath.Dir(reader.scan.sorter.workspace.path))
			entries, err := os.ReadDir(producerDirectory)
			require.NoError(t, err)
			for _, entry := range entries {
				require.NotContains(t, entry.Name(), ".bifroest-audit-segments-")
			}
		}
		return nil
	}
	for {
		result := reader.Next(context.Background(), 0, nil, nil)
		require.NoError(t, result.err)
		if result.exists {
			require.NoError(t, result.file.Close())
			break
		}
		require.True(t, result.more)
	}
	require.True(t, inspected)
	require.Equal(t, uint64(1), reader.scanCount)
	require.NoError(t, reader.Close())
	entries, err := os.ReadDir(filepath.Join(journalDirectory, journalWorkDirectoryName))
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestRemoteDeliverySegmentReaderAdvancesThroughBacklog(t *testing.T) {
	directory := t.TempDir()
	content := []byte("sealed segment")
	hash := hashNativeAuditSegment(content)
	lastSequence := uint64(257)
	for sequence := uint64(1); sequence <= lastSequence; sequence++ {
		name := nativeSegmentName(sequence, hash, false)
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
	hash := hashNativeAuditSegment(content)
	path := filepath.Join(directory, nativeSegmentName(1, hash, false))
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
	first := nativeSegmentName(1, journalHash{1}, false)
	second := nativeSegmentName(1, journalHash{2}, false)
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
	name := nativeSegmentName(sequence, journalHash{1}, false)
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
	hash := hashNativeAuditSegment(content)
	writeSegment := func(sequence uint64) journalSegmentFile {
		name := nativeSegmentName(sequence, hash, false)
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
	hash := hashNativeAuditSegment(content)
	for sequence := uint64(1); sequence <= 2; sequence++ {
		path := filepath.Join(directory, nativeSegmentName(sequence, hash, false))
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
	hash := hashNativeAuditSegment(content)
	segmentPath := filepath.Join(directory, nativeSegmentName(1, hash, false))
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
	require.NoError(t, os.Chmod(segmentPath, journalFileMode))
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
	hash := hashNativeAuditSegment(content)
	writeSegment := func(sequence uint64) journalSegmentFile {
		name := nativeSegmentName(sequence, hash, false)
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
	hash := hashNativeAuditSegment(content)
	firstName := nativeSegmentName(1, hash, false)
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
	duplicateName := nativeSegmentName(1, journalHash{9}, false)
	require.NoError(t, os.WriteFile(filepath.Join(directory, duplicateName), []byte("mutated"), journalFileMode))
	secondName := nativeSegmentName(2, hash, false)
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
			recorder, err := newNativeRecorder(&conf, identity)
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
	recorder, err := newNativeRecorder(&conf, identity)
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
	recorder, err := newNativeRecorder(&conf, identity)
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
	recorder, err := newNativeRecorder(&conf, identity)
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
	lockPath := filepath.Join(conf.Journal.Directory, remoteDeliveryStateDirectoryName, journalLockFileName)
	first, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })
	require.FileExists(t, lockPath)
	require.NoDirExists(t, conf.Journal.Directory+remoteDeliveryStateDirectoryName)
	second, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.Nil(t, second)
	require.ErrorContains(t, err, "cannot lock remote delivery state")
	require.NoError(t, first.Close())
	require.NoFileExists(t, lockPath)

	reopened, err := NewRemoteDelivery(context.Background(), &conf, identity)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	require.NoFileExists(t, lockPath)
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
	recorder, err := newNativeRecorder(&conf, identity)
	require.NoError(t, err)
	for index := range count {
		require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.delivery." + leftPadUint(uint64(index+1), 2)}))
		require.NoError(t, recorder.(SealableRecorder).Seal())
	}
	require.NoError(t, recorder.Close())
	directory := filepath.Join(conf.Journal.Directory, identity.ProducerId().String())
	entries, _, _, err := nativeInventory(directory, nativeActiveClear, false)
	require.NoError(t, err)
	segments := make([]journalSegmentFile, 0, len(entries))
	for _, entry := range entries {
		segments = append(segments, journalSegmentFile{path: entry.path, sequence: entry.seq, hash: entry.hash})
	}
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
