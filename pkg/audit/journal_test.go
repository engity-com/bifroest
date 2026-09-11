package audit

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestNewRecorderDoesNothingWhenDisabled(t *testing.T) {
	directory := t.TempDir()
	conf := auditIdentityTestConfiguration(filepath.Join(directory, "missing"), false)

	recorder, err := NewRecorder(&conf, nil)

	require.NoError(t, err)
	require.IsType(t, noopRecorder{}, recorder)
	require.NoError(t, recorder.Record(context.Background(), Event{}))
	require.NoError(t, recorder.Close())
	require.NoFileExists(t, conf.IdentityFile)
	require.NoDirExists(t, conf.Journal.Directory)
}

func TestNewRecorderRejectsMissingInputs(t *testing.T) {
	_, err := NewRecorder(nil, nil)
	require.ErrorContains(t, err, "nil auditlog configuration")
	require.True(t, berrors.Config.IsErr(err))

	conf := auditIdentityTestConfiguration(t.TempDir(), true)
	_, err = NewRecorder(&conf, nil)
	require.ErrorContains(t, err, "nil audit identity")
	require.True(t, berrors.Config.IsErr(err))
}

func TestLocalJournalRecordsAndReopens(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.IsType(t, &localJournalRecorder{}, recorder)

	before := time.Now().UTC()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, recorder.Record(ctx, Event{Name: "test.first"}))
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.second"}))
	after := time.Now().UTC()
	require.NoError(t, recorder.Close())
	require.NoError(t, recorder.Close())

	records := readJournalTestRecords(t, conf, identity)
	require.Len(t, records, 2)
	for i, record := range records {
		require.Equal(t, journalRecordSchema, record.Schema)
		require.Equal(t, identity.ProducerId(), record.ProducerId)
		require.Equal(t, 4, int(record.Id.Version()))
		require.False(t, record.RecordedAt.Before(before))
		require.False(t, record.RecordedAt.After(after))
		require.Equal(t, fmt.Sprintf("test.%s", []string{"first", "second"}[i]), record.Event.Name)
	}

	reopened, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, reopened.Record(context.Background(), Event{Name: "test.third"}))
	require.NoError(t, reopened.Close())
	require.Len(t, readJournalTestRecords(t, conf, identity), 3)
}

func TestLocalJournalSerializesConcurrentRecords(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)

	const count = 64
	errs := make(chan error, count)
	var wait sync.WaitGroup
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errs <- recorder.Record(context.Background(), Event{Name: fmt.Sprintf("test.concurrent.%d", index)})
		}(i)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.NoError(t, recorder.Close())

	records := readJournalTestRecords(t, conf, identity)
	require.Len(t, records, count)
	ids := make(map[string]struct{}, count)
	names := make(map[string]struct{}, count)
	for _, record := range records {
		ids[record.Id.String()] = struct{}{}
		names[record.Event.Name] = struct{}{}
	}
	require.Len(t, ids, count)
	require.Len(t, names, count)
}

func TestLocalJournalRecoversIncompleteTail(t *testing.T) {
	for _, tc := range []struct {
		name string
		tail func([]byte) []byte
	}{
		{"length", func(frame []byte) []byte { return frame[:journalFrameLengthSize-1] }},
		{"payload", func(frame []byte) []byte { return frame[:journalFrameLengthSize+10] }},
		{"checksum", func(frame []byte) []byte { return frame[:len(frame)-1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, identity := newJournalTestIdentity(t)
			recorder, err := NewRecorder(&conf, identity)
			require.NoError(t, err)
			require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.before-crash"}))
			require.NoError(t, recorder.Close())
			activePath := journalTestActivePath(conf, identity)
			original, err := os.ReadFile(activePath)
			require.NoError(t, err)

			file, err := os.OpenFile(activePath, os.O_WRONLY|os.O_APPEND, journalFileMode)
			require.NoError(t, err)
			_, err = file.Write(tc.tail(original))
			require.NoError(t, err)
			require.NoError(t, file.Sync())
			require.NoError(t, file.Close())

			recovered, err := NewRecorder(&conf, identity)
			require.NoError(t, err)
			after, err := os.Stat(activePath)
			require.NoError(t, err)
			require.Equal(t, int64(len(original)), after.Size())
			require.NoError(t, recovered.Record(context.Background(), Event{Name: "test.after-crash"}))
			require.NoError(t, recovered.Close())
			require.Len(t, readJournalTestRecords(t, conf, identity), 2)
		})
	}
}

func TestLocalJournalRejectsCompleteCorruption(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.corrupt"}))
	require.NoError(t, recorder.Close())
	activePath := journalTestActivePath(conf, identity)
	raw, err := os.ReadFile(activePath)
	require.NoError(t, err)
	raw[journalFrameLengthSize] ^= 1
	require.NoError(t, os.WriteFile(activePath, raw, journalFileMode))

	failed, err := NewRecorder(&conf, identity)

	require.Nil(t, failed)
	require.ErrorContains(t, err, "checksum mismatch")
	require.True(t, berrors.System.IsErr(err))
	actual, readErr := os.ReadFile(activePath)
	require.NoError(t, readErr)
	require.Equal(t, raw, actual)
}

func TestLocalJournalRejectsCommittedRecordWithCorruptedSize(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.corrupt-size"}))
	require.NoError(t, recorder.Close())
	activePath := journalTestActivePath(conf, identity)
	raw, err := os.ReadFile(activePath)
	require.NoError(t, err)
	payloadSize := binary.BigEndian.Uint32(raw[:journalFrameLengthSize])
	binary.BigEndian.PutUint32(raw[:journalFrameLengthSize], payloadSize+1)
	require.NoError(t, os.WriteFile(activePath, raw, journalFileMode))

	failed, err := NewRecorder(&conf, identity)

	require.Nil(t, failed)
	require.ErrorContains(t, err, "corrupted size")
	actual, readErr := os.ReadFile(activePath)
	require.NoError(t, readErr)
	require.Equal(t, raw, actual)
}

func TestLocalJournalRejectsCorruptedCommitMarker(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.corrupt-commit"}))
	require.NoError(t, recorder.Close())
	activePath := journalTestActivePath(conf, identity)
	raw, err := os.ReadFile(activePath)
	require.NoError(t, err)
	raw[len(raw)-1] ^= 1
	require.NoError(t, os.WriteFile(activePath, raw, journalFileMode))

	failed, err := NewRecorder(&conf, identity)

	require.Nil(t, failed)
	require.ErrorContains(t, err, "commit marker mismatch")
	actual, readErr := os.ReadFile(activePath)
	require.NoError(t, readErr)
	require.Equal(t, raw, actual)
}

func TestLocalJournalRejectsDifferentProducer(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.original"}))
	require.NoError(t, recorder.Close())

	otherKey, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).GenerateKey(nil)
	require.NoError(t, err)
	otherIdentity, err := NewIdentity(otherKey)
	require.NoError(t, err)
	failed, err := NewRecorder(&conf, otherIdentity)

	require.Nil(t, failed)
	require.ErrorContains(t, err, "contains unsupported entry")
	require.NoDirExists(t, filepath.Join(conf.Journal.Directory, otherIdentity.ProducerId().String()))
}

func TestLocalJournalLocksExclusiveWriter(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	first, err := NewRecorder(&conf, identity)
	require.NoError(t, err)

	second, err := NewRecorder(&conf, identity)
	require.Nil(t, second)
	require.ErrorContains(t, err, "already locked")
	require.True(t, berrors.System.IsErr(err))

	require.NoError(t, first.Close())
	third, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, third.Close())
}

func TestLocalJournalRejectsInvalidEventsWithoutWriting(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	activePath := journalTestActivePath(conf, identity)
	before, err := os.Stat(activePath)
	require.NoError(t, err)

	err = recorder.Record(context.Background(), Event{})
	require.Error(t, err)
	require.True(t, berrors.System.IsErr(err))
	require.Error(t, recorder.Record(context.Background(), Event{Name: " whitespace"}))
	require.Error(t, recorder.Record(context.Background(), Event{Name: strings.Repeat("x", maxAuditEventNameSize+1)}))
	after, err := os.Stat(activePath)
	require.NoError(t, err)
	require.Equal(t, before.Size(), after.Size())
	require.NoError(t, recorder.Close())
}

func TestLocalJournalRejectsRecordsAfterClose(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Close())

	require.ErrorIs(t, recorder.Record(context.Background(), Event{Name: "test.closed"}), errJournalClosed)
}

func TestLocalJournalPoisonsRecorderAfterWriteFailure(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	local := recorder.(*localJournalRecorder)
	readOnly, err := os.Open(local.activePath)
	require.NoError(t, err)
	require.NoError(t, local.file.Close())
	local.file = readOnly

	firstErr := recorder.Record(context.Background(), Event{Name: "test.write-fails"})
	require.ErrorContains(t, firstErr, "cannot append audit record")
	secondErr := recorder.Record(context.Background(), Event{Name: "test.not-appended"})
	require.EqualError(t, secondErr, firstErr.Error())
	require.Error(t, recorder.Close())
}

func newJournalTestIdentity(t *testing.T) (configuration.Auditlog, *Identity) {
	t.Helper()
	conf := auditIdentityTestConfiguration(t.TempDir(), true)
	identity, err := EnsureIdentity(&conf)
	require.NoError(t, err)
	return conf, identity
}

func journalTestActivePath(conf configuration.Auditlog, identity *Identity) string {
	return filepath.Join(conf.Journal.Directory, identity.ProducerId().String(), journalActiveFileName)
}

func readJournalTestRecords(t *testing.T, conf configuration.Auditlog, identity *Identity) []journalRecord {
	t.Helper()
	raw, err := os.ReadFile(journalTestActivePath(conf, identity))
	require.NoError(t, err)
	var records []journalRecord
	for len(raw) > 0 {
		require.GreaterOrEqual(t, len(raw), journalFrameLengthSize+journalFrameChecksumSize+len(journalFrameCommitMarker))
		payloadSize := int(binary.BigEndian.Uint32(raw[:journalFrameLengthSize]))
		frameSize := journalFrameLengthSize + payloadSize + journalFrameChecksumSize + len(journalFrameCommitMarker)
		require.GreaterOrEqual(t, len(raw), frameSize)
		payload := raw[journalFrameLengthSize : journalFrameLengthSize+payloadSize]
		checksumOffset := journalFrameLengthSize + payloadSize
		expectedChecksum := binary.BigEndian.Uint32(raw[checksumOffset : checksumOffset+journalFrameChecksumSize])
		require.Equal(t, expectedChecksum, crc32.Checksum(payload, journalChecksumTable))
		require.Equal(t, journalFrameCommitMarker, string(raw[checksumOffset+journalFrameChecksumSize:frameSize]))
		record, err := decodeJournalRecord(payload, identity.ProducerId())
		require.NoError(t, err)
		records = append(records, record)
		raw = raw[frameSize:]
	}
	return records
}
