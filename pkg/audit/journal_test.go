package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/nativeformat"
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

func TestNativeJournalRecordsAndReopens(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.IsType(t, &nativeRecorder{}, recorder)

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

func TestNativeJournalSerializesConcurrentRecords(t *testing.T) {
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

func TestNativeJournalReserveOnlySuppressesSuppressibleRecords(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	local := recorder.(*nativeRecorder)
	local.availableBytes = func(string) (uint64, error) { return 0, nil }

	recorded, err := local.RecordSuppressible(context.Background(), Event{Name: "test.suppressed"})
	require.NoError(t, err)
	require.False(t, recorded)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.required"}))
	require.NoError(t, recorder.Close())

	records := readJournalTestRecords(t, conf, identity)
	require.Len(t, records, 1)
	require.Equal(t, "test.required", records[0].Event.Name)
}

func TestNativeJournalFreeSpaceFailureFailsClosedWithoutPoisoning(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	local := recorder.(*nativeRecorder)
	local.availableBytes = func(string) (uint64, error) { return 0, fmt.Errorf("space unavailable") }

	recorded, err := local.RecordSuppressible(context.Background(), Event{Name: "test.failed"})
	require.False(t, recorded)
	require.ErrorContains(t, err, "space unavailable")
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.required"}))
	require.NoError(t, recorder.Close())
}

func TestNativeJournalRecoversIncompleteTail(t *testing.T) {
	for _, tc := range []struct {
		name string
		tail func([]byte) []byte
	}{
		{"prefix", func(frame []byte) []byte { return frame[:5] }},
		{"uncommitted frame", func(frame []byte) []byte { frame[5] = 0; return frame }},
		{"uncommitted payload", func(frame []byte) []byte { frame[5] = 0; return frame[:16] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, identity := newJournalTestIdentity(t)
			recorder, err := NewRecorder(&conf, identity)
			require.NoError(t, err)
			require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.before-crash"}))
			crashCloseJournalTestRecorder(t, recorder)
			activePath := journalTestActivePath(conf, identity)
			_, payload, _, err := newNativeAuditRecord(identity, recorder.(*nativeRecorder).state.lastRecord, Event{Name: "test.tail"}, uuid.New(), time.Now().UTC(), nil)
			require.NoError(t, err)
			incompleteFrame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
			require.NoError(t, err)

			file, err := os.OpenFile(activePath, os.O_WRONLY|os.O_APPEND, journalFileMode)
			require.NoError(t, err)
			_, err = file.Write(tc.tail(incompleteFrame))
			require.NoError(t, err)
			require.NoError(t, file.Sync())
			require.NoError(t, file.Close())

			recovered, err := NewRecorder(&conf, identity)
			require.NoError(t, err)
			require.Len(t, readJournalTestRecords(t, conf, identity), 1)
			require.NoError(t, recovered.Record(context.Background(), Event{Name: "test.after-crash"}))
			require.NoError(t, recovered.Close())
			require.Len(t, readJournalTestRecords(t, conf, identity), 2)
		})
	}
}

func TestNativeJournalRejectsCompleteCorruption(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.corrupt"}))
	crashCloseJournalTestRecorder(t, recorder)
	activePath := journalTestActivePath(conf, identity)
	raw, err := os.ReadFile(activePath)
	require.NoError(t, err)
	recordOffset := nativeTestRecordOffset(t, raw)
	raw[recordOffset+6] ^= 1
	require.NoError(t, os.WriteFile(activePath, raw, journalFileMode))

	failed, err := NewRecorder(&conf, identity)

	require.Nil(t, failed)
	require.ErrorContains(t, err, "checksum mismatch")
	actual, readErr := os.ReadFile(activePath)
	require.NoError(t, readErr)
	require.Equal(t, raw, actual)
}

func TestNativeJournalRejectsCommittedRecordWithCorruptedSize(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.corrupt-size"}))
	crashCloseJournalTestRecorder(t, recorder)
	activePath := journalTestActivePath(conf, identity)
	raw, err := os.ReadFile(activePath)
	require.NoError(t, err)
	recordOffset := nativeTestRecordOffset(t, raw)
	payloadSize := binary.BigEndian.Uint32(raw[recordOffset+1 : recordOffset+5])
	binary.BigEndian.PutUint32(raw[recordOffset+1:recordOffset+5], payloadSize+1)
	require.NoError(t, os.WriteFile(activePath, raw, journalFileMode))

	failed, err := NewRecorder(&conf, identity)

	require.Nil(t, failed)
	require.ErrorContains(t, err, "physically incomplete")
	actual, readErr := os.ReadFile(activePath)
	require.NoError(t, readErr)
	require.Equal(t, raw, actual)
}

func TestNativeJournalDoesNotTruncateCorruptedCommittedRecordBeforePartialTail(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.committed"}))
	crashCloseJournalTestRecorder(t, recorder)
	activePath := journalTestActivePath(conf, identity)
	raw, err := os.ReadFile(activePath)
	require.NoError(t, err)
	recordOffset := nativeTestRecordOffset(t, raw)
	binary.BigEndian.PutUint32(raw[recordOffset+1:recordOffset+5], nativeformat.MaxAuditRecordPayload+1)
	raw = append(raw, 0, 0, 1)
	require.NoError(t, os.WriteFile(activePath, raw, journalFileMode))

	failed, err := NewRecorder(&conf, identity)

	require.Nil(t, failed)
	require.ErrorContains(t, err, "invalid native container unit type or payload size")
	actual, readErr := os.ReadFile(activePath)
	require.NoError(t, readErr)
	require.Equal(t, raw, actual)
}

func TestNativeJournalRejectsCorruptedCommitMarker(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.corrupt-commit"}))
	crashCloseJournalTestRecorder(t, recorder)
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

func TestNativeJournalRejectsDifferentProducer(t *testing.T) {
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
	require.ErrorContains(t, err, "invalid native audit root entry")
	require.NoDirExists(t, filepath.Join(conf.Journal.Directory, otherIdentity.ProducerId().String()))
}

func TestNativeJournalLocksExclusiveWriter(t *testing.T) {
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

func TestNativeJournalRejectsInvalidEventsWithoutWriting(t *testing.T) {
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
	require.Error(t, recorder.Record(context.Background(), Event{Name: "test.invalid-domain", Domain: "invalid"}))
	after, err := os.Stat(activePath)
	require.NoError(t, err)
	require.Equal(t, before.Size(), after.Size())
	require.NoError(t, recorder.Close())
}

func TestNativeJournalRejectsRecordsAfterClose(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Close())

	require.ErrorIs(t, recorder.Record(context.Background(), Event{Name: "test.closed"}), errJournalClosed)
}

func TestNativeJournalPoisonsRecorderAfterWriteFailure(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	local := recorder.(*nativeRecorder)
	readOnly, err := os.Open(local.activePath)
	require.NoError(t, err)
	require.NoError(t, local.file.Close())
	local.file = readOnly

	firstErr := recorder.Record(context.Background(), Event{Name: "test.write-fails"})
	require.Error(t, firstErr)
	secondErr := recorder.Record(context.Background(), Event{Name: "test.not-appended"})
	require.EqualError(t, secondErr, firstErr.Error())
	require.Error(t, recorder.Close())
}

func TestNativeJournalCloseAfterAcceptedFailureOmitsOnlyExistingPoison(t *testing.T) {
	t.Run("existing poison", func(t *testing.T) {
		conf, identity := newJournalTestIdentity(t)
		recorder, err := NewRecorder(&conf, identity)
		require.NoError(t, err)
		local := recorder.(*nativeRecorder)
		readOnly, err := os.Open(local.activePath)
		require.NoError(t, err)
		require.NoError(t, local.file.Close())
		local.file = readOnly

		accepted := recorder.Record(context.Background(), Event{Name: "test.write-fails"})
		require.Error(t, accepted)
		closeErr := local.CloseAfterAcceptedFailure()
		require.NotErrorIs(t, closeErr, accepted)
	})

	t.Run("new cleanup failure", func(t *testing.T) {
		conf, identity := newJournalTestIdentity(t)
		recorder, err := NewRecorder(&conf, identity)
		require.NoError(t, err)
		local := recorder.(*nativeRecorder)
		require.NoError(t, local.file.Close())

		accepted := recorder.Record(context.Background(), Event{Name: "test.write-fails"})
		require.Error(t, accepted)
		require.NoError(t, local.lock.file.Close())
		closeErr := local.CloseAfterAcceptedFailure()
		require.Error(t, closeErr)
		require.NotErrorIs(t, closeErr, accepted)
	})
}

func newJournalTestIdentity(t *testing.T) (configuration.Auditlog, *Identity) {
	t.Helper()
	conf := auditIdentityTestConfiguration(t.TempDir(), true)
	identity, err := EnsureIdentity(&conf)
	require.NoError(t, err)
	return conf, identity
}

func journalTestActivePath(conf configuration.Auditlog, identity *Identity) string {
	return filepath.Join(conf.Journal.Directory, identity.ProducerId().String(), nativeActiveClear)
}

func readJournalTestRecords(t *testing.T, conf configuration.Auditlog, identity *Identity) []VerifiedRecord {
	t.Helper()
	source := JournalSource{Name: "test", Directory: conf.Journal.Directory, ExpectedProducerId: identity.ProducerId(), WithSensitive: true}
	if !conf.EncryptionPublicKey.IsZero() || conf.EncryptionPublicKeyFile != "" {
		t.Fatal("encrypted test records need explicit decryption identities")
	}
	verified, err := VerifyJournals(context.Background(), []JournalSource{source})
	require.NoError(t, err)
	return verified.Records()
}

func crashCloseJournalTestRecorder(t *testing.T, recorder Recorder) {
	t.Helper()
	local := recorder.(*nativeRecorder)
	local.mutex.Lock()
	defer local.mutex.Unlock()
	require.NoError(t, local.file.Sync())
	require.NoError(t, local.file.Close())
	require.NoError(t, local.lock.Close())
	local.closed = true
}

func nativeTestRecordOffset(t *testing.T, raw []byte) int {
	t.Helper()
	_, offset, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(raw), int64(len(nativeformat.AuditMagic)), int64(len(raw)), nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	require.False(t, tail)
	return int(offset)
}
