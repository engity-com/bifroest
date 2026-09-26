package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func nativeRecorderTestConfig(t *testing.T, encrypted bool) (configuration.Auditlog, *Identity) {
	t.Helper()
	id := nativeTestIdentity(t)
	conf := auditIdentityTestConfiguration(filepath.Join(t.TempDir(), "audit"), true)
	if encrypted {
		key, err := auditIdentityKeyRequirement.GenerateKey(nil)
		require.NoError(t, err)
		conf.EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(key.PublicKey().ToSsh())))
	}
	return conf, id
}

func nativeTestOpen(t *testing.T, conf *configuration.Auditlog, id *Identity) *nativeRecorder {
	t.Helper()
	r, err := newNativeRecorder(conf, id)
	require.NoError(t, err)
	return r.(*nativeRecorder)
}

func TestNativeRecorderRoundTripRestartAndSeal(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{true: "age", false: "clear"}[encrypted], func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, encrypted)
			r := nativeTestOpen(t, &conf, id)
			first := r.state.seq
			require.NoError(t, r.Record(context.Background(), Event{Name: "test.one", Flow: "private"}))
			checkpoint := r.state.lastRecord
			require.NoError(t, r.Seal())
			require.Equal(t, first+1, r.state.seq)
			sealed := filepath.Join(r.headDirectory, nativeSegmentName(first, r.state.prevSegment, encrypted))
			require.FileExists(t, sealed)
			require.NoError(t, r.Close())
			r = nativeTestOpen(t, &conf, id)
			require.Equal(t, checkpoint, r.state.lastRecord)
			require.NoError(t, r.Record(context.Background(), Event{Name: "test.two"}))
			require.NoError(t, r.Close())
			r = nativeTestOpen(t, &conf, id)
			require.EqualValues(t, first+2, r.state.seq)
			require.NoError(t, r.Close())
		})
	}
}

func TestNativeRecorderRecoversTailAndAdoptsCommittedAfterOldHead(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.first"}))
	oldHead, err := os.ReadFile(filepath.Join(r.headDirectory, nativeHeadFileName))
	require.NoError(t, err)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.second"}))
	second := r.state.lastRecord
	require.NoError(t, os.WriteFile(filepath.Join(r.headDirectory, nativeHeadFileName), oldHead, journalFileMode))
	_, payload, _, err := newNativeAuditRecord(id, second, Event{Name: "test.tail"}, uuid.New(), time.Now(), nil)
	require.NoError(t, err)
	frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	frame[5] = 0
	offset := r.state.fileBytes
	_, err = r.file.WriteAt(frame, offset)
	require.NoError(t, err)
	require.NoError(t, r.file.Sync())
	require.NoError(t, r.file.Close())
	require.NoError(t, r.lock.Close())
	r = nativeTestOpen(t, &conf, id)
	require.Equal(t, second, r.state.lastRecord)
	require.Equal(t, offset, r.state.fileBytes)
	info, err := r.file.Stat()
	require.NoError(t, err)
	require.Equal(t, offset, info.Size())
	head, err := readNativeHead(r.headDirectory, id)
	require.NoError(t, err)
	require.Equal(t, second, head)
	require.NoError(t, r.Close())
}

func TestNativeRecorderRejectsCompleteStateZeroRecordBeforeCommittedRecord(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed"}))
	path := r.activePath
	checkpoint := r.state.lastRecord
	_, payload, nextHash, err := newNativeAuditRecord(id, checkpoint, Event{Name: "test.uncommitted"}, uuid.New(), time.Now(), nil)
	require.NoError(t, err)
	stateZero, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	stateZero[5] = 0
	_, payload, _, err = newNativeAuditRecord(id, nextHash, Event{Name: "test.later"}, uuid.New(), time.Now(), nil)
	require.NoError(t, err)
	committed, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	data, err := nativeReadFile(r.file)
	require.NoError(t, err)
	data = append(data, stateZero...)
	data = append(data, committed...)
	require.NoError(t, r.file.Close())
	require.NoError(t, os.WriteFile(path, data, journalFileMode))
	require.NoError(t, r.lock.Close())
	_, err = newNativeRecorder(&conf, id)
	require.Error(t, err)
	preserved, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, preserved, "rejected records must not be truncated")
	head, err := readNativeHead(r.headDirectory, id)
	require.NoError(t, err)
	require.Equal(t, checkpoint, head)
}

func TestNativeRecorderRejectsStateZeroLengthSwallowingCommittedRecord(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed"}))
	path := r.activePath
	checkpoint := r.state.lastRecord
	_, payload, nextHash, err := newNativeAuditRecord(id, checkpoint, Event{Name: "test.uncommitted"}, uuid.New(), time.Now(), nil)
	require.NoError(t, err)
	first, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	first[5] = 0
	_, payload, _, err = newNativeAuditRecord(id, nextHash, Event{Name: "test.later"}, uuid.New(), time.Now(), nil)
	require.NoError(t, err)
	second, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	data, err := nativeReadFile(r.file)
	require.NoError(t, err)
	offset := len(data)
	data = append(data, first...)
	data = append(data, second...)
	binary.BigEndian.PutUint32(data[offset+1:offset+5], uint32(len(first)+len(second)))
	require.NoError(t, r.file.Close())
	require.NoError(t, os.WriteFile(path, data, journalFileMode))
	require.NoError(t, r.lock.Close())
	_, err = newNativeRecorder(&conf, id)
	require.Error(t, err)
	preserved, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, preserved)
	head, err := readNativeHead(r.headDirectory, id)
	require.NoError(t, err)
	require.Equal(t, checkpoint, head)
}

func TestNativeRecorderRejectsCorruptCommittedRecordAfterShortHeader(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed"}))
	require.NoError(t, r.Seal())
	path := r.activePath
	data, err := nativeReadFile(r.file)
	require.NoError(t, err)
	offset := len(nativeformat.AuditMagic)
	data = data[:offset+6]
	data[offset+5] = 0
	binary.BigEndian.PutUint32(data[offset+1:offset+5], 4096)
	_, payload, _, err := newNativeAuditRecord(id, r.state.lastRecord, Event{Name: "test.corrupt"}, uuid.New(), time.Now(), nil)
	require.NoError(t, err)
	frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	frame[6] ^= 1 // CRC is invalid, but the state-1 prefix and trailer survive.
	data = append(data, frame...)
	require.NoError(t, r.file.Close())
	require.NoError(t, os.WriteFile(path, data, journalFileMode))
	require.NoError(t, r.lock.Close())
	_, err = newNativeRecorder(&conf, id)
	require.Error(t, err)
	preserved, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, preserved)
}

func TestNativeRecorderPoisonAndAcceptedCleanup(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.first"}))
	// A replaced head must poison the writer without overwriting that path.
	headPath := filepath.Join(r.headDirectory, nativeHeadFileName)
	require.NoError(t, os.Remove(headPath))
	require.NoError(t, os.Mkdir(headPath, journalDirectoryMode))
	err := r.Record(context.Background(), Event{Name: "test.second"})
	require.Error(t, err)
	require.ErrorIs(t, r.Record(context.Background(), Event{Name: "test.third"}), err)
	require.ErrorIs(t, r.Seal(), err)
	require.NoError(t, r.CloseAfterAcceptedFailure())
	_, err = newNativeRecorder(&conf, id)
	require.Error(t, err, "unrecognized head path cannot be removed during recovery")
}

func TestNativeRecorderRecoversInterruptedHeader(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.file.Truncate(int64(len(nativeformat.AuditMagic))))
	require.NoError(t, r.Close())
	r = nativeTestOpen(t, &conf, id)
	require.Greater(t, r.state.fileBytes, int64(len(nativeformat.AuditMagic)))
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.after-interrupted-header"}))
	require.NoError(t, r.Close())
}

func TestNativeRecorderRecoversInterruptedHeadTemp(t *testing.T) {
	for _, size := range []string{"complete", "partial", "empty"} {
		t.Run(size, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			r := nativeTestOpen(t, &conf, id)
			require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed"}))
			oldHead, err := os.ReadFile(filepath.Join(r.headDirectory, nativeHeadFileName))
			require.NoError(t, err)
			first := r.state.lastRecord
			require.NoError(t, r.Record(context.Background(), Event{Name: "test.after-old-head"}))
			second := r.state.lastRecord
			require.NoError(t, os.WriteFile(filepath.Join(r.headDirectory, nativeHeadFileName), oldHead, journalFileMode))
			_, payload, err := newNativeAuditHead(id, second)
			require.NoError(t, err)
			switch size {
			case "partial":
				payload = payload[:len(payload)/2]
			case "empty":
				payload = nil
			}
			temp, err := os.CreateTemp(r.headDirectory, ".head-cbor-*")
			require.NoError(t, err)
			_, err = temp.Write(payload)
			require.NoError(t, err)
			require.NoError(t, temp.Sync())
			require.NoError(t, temp.Close())
			require.NoError(t, r.file.Close())
			require.NoError(t, r.lock.Close())
			r = nativeTestOpen(t, &conf, id)
			require.NoFileExists(t, temp.Name())
			require.Equal(t, second, r.state.lastRecord)
			require.EqualValues(t, 2, r.state.count)
			_, reopened, err := newNativeAuditHead(id, first)
			require.NoError(t, err)
			require.Equal(t, oldHead, reopened)
			require.NoError(t, r.Record(context.Background(), Event{Name: "test.after-recovery"}))
			require.NoError(t, r.Close())
		})
	}
}

func TestNativeRecorderRejectsUntrustedHeadTemp(t *testing.T) {
	for _, contents := range []string{"foreign", "unrelated-signed"} {
		t.Run(contents, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			r := nativeTestOpen(t, &conf, id)
			require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed"}))
			original := r.state.lastRecord
			temp, err := os.CreateTemp(r.headDirectory, ".head-cbor-*")
			require.NoError(t, err)
			payload := []byte("foreign user data")
			if contents == "unrelated-signed" {
				_, payload, err = newNativeAuditHead(id, journalHash{99})
				require.NoError(t, err)
			}
			_, err = temp.Write(payload)
			require.NoError(t, err)
			require.NoError(t, temp.Close())
			require.NoError(t, r.file.Close())
			require.NoError(t, r.lock.Close())
			_, err = newNativeRecorder(&conf, id)
			require.Error(t, err)
			remaining, err := os.ReadFile(temp.Name())
			require.NoError(t, err)
			require.Equal(t, payload, remaining)
			head, err := readNativeHead(r.headDirectory, id)
			require.NoError(t, err)
			require.Equal(t, original, head)
		})
	}
}

func TestNativeRecorderDoesNotCleanHeadTempIfHistoryIsCorrupt(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed"}))
	require.NoError(t, r.Close())
	temp, err := os.CreateTemp(r.headDirectory, ".head-cbor-*")
	require.NoError(t, err)
	_, payload, err := newNativeAuditHead(id, r.state.lastRecord)
	require.NoError(t, err)
	_, err = temp.Write(payload)
	require.NoError(t, err)
	require.NoError(t, temp.Close())
	segments, _, _, err := nativeInventorySkippingTemps(r.headDirectory, nativeActiveClear, false, map[string]struct{}{filepath.Base(temp.Name()): {}})
	require.NoError(t, err)
	require.Len(t, segments, 1)
	data, err := os.ReadFile(segments[0].path)
	require.NoError(t, err)
	data[len(data)/2] ^= 1
	require.NoError(t, os.WriteFile(segments[0].path, data, journalFileMode))
	_, err = newNativeRecorder(&conf, id)
	require.Error(t, err)
	remaining, err := os.ReadFile(temp.Name())
	require.NoError(t, err)
	require.Equal(t, payload, remaining)
}

func TestNativeRecorderDoesNotRemoveAliasedHeadTemp(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed"}))
	headPath := filepath.Join(r.headDirectory, nativeHeadFileName)
	tempPath := filepath.Join(r.headDirectory, ".head-cbor-123456789")
	if err := os.Link(headPath, tempPath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	require.NoError(t, r.file.Close())
	require.NoError(t, r.lock.Close())
	_, err := newNativeRecorder(&conf, id)
	require.Error(t, err)
	require.FileExists(t, tempPath)
	checkpoint, err := readNativeHead(r.headDirectory, id)
	require.NoError(t, err)
	require.Equal(t, r.state.lastRecord, checkpoint)
}

func TestNativeRecorderRecoversInterruptedActiveCreation(t *testing.T) {
	for _, afterRotation := range []bool{false, true} {
		for _, stage := range []string{"empty", "partial-magic", "magic", "header-prefix-1", "header-prefix-3", "header-prefix-5", "header-prefix-5-zero", "header-prefix-6-zero", "header-state0", "header-body", "header-before-last-body-byte", "header-before-crc", "header-before-last-crc-byte", "header-before-last-commit-byte", "state0-header"} {
			t.Run(map[bool]string{true: "rotated/", false: "initial/"}[afterRotation]+stage, func(t *testing.T) {
				conf, id := nativeRecorderTestConfig(t, false)
				r := nativeTestOpen(t, &conf, id)
				if afterRotation {
					require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed"}))
					require.NoError(t, r.Seal())
				}
				seq, previous, path := r.state.seq, r.state.lastRecord, r.activePath
				data, err := nativeReadFile(r.file)
				require.NoError(t, err)
				switch stage {
				case "empty":
					data = nil
				case "partial-magic":
					data = data[:3]
				case "magic":
					data = data[:len(nativeformat.AuditMagic)]
				case "header-prefix-1", "header-prefix-3", "header-prefix-5":
					prefix := map[string]int{"header-prefix-1": 1, "header-prefix-3": 3, "header-prefix-5": 5}[stage]
					data = data[:len(nativeformat.AuditMagic)+prefix]
				case "header-prefix-5-zero":
					data = data[:len(nativeformat.AuditMagic)+5]
					clear(data[len(nativeformat.AuditMagic)+1:])
				case "header-prefix-6-zero":
					data = data[:len(nativeformat.AuditMagic)+6]
					clear(data[len(nativeformat.AuditMagic)+1:])
				case "header-state0", "header-body", "header-before-last-body-byte", "header-before-crc", "header-before-last-crc-byte", "header-before-last-commit-byte":
					offset := len(nativeformat.AuditMagic)
					bodyEnd := offset + 6 + int(binary.BigEndian.Uint32(data[offset+1:offset+5]))
					data[offset+5] = 0
					switch stage {
					case "header-state0":
						data = data[:offset+6]
					case "header-body":
						data = data[:offset+16]
					case "header-before-last-body-byte":
						data = data[:bodyEnd-1]
					case "header-before-crc":
						data = data[:bodyEnd]
					case "header-before-last-crc-byte":
						data = data[:bodyEnd+3]
					case "header-before-last-commit-byte":
						data = data[:len(data)-1]
					}
				case "state0-header":
					data[len(nativeformat.AuditMagic)+5] = 0
				}
				require.NoError(t, r.file.Close())
				require.NoError(t, os.WriteFile(path, data, journalFileMode))
				require.NoError(t, r.lock.Close())
				r = nativeTestOpen(t, &conf, id)
				require.Equal(t, seq, r.state.seq)
				require.Equal(t, previous, r.state.lastRecord)
				require.Zero(t, r.state.count)
				require.NoError(t, r.Record(context.Background(), Event{Name: "test.after-recovery"}))
				require.NoError(t, r.Close())
				r = nativeTestOpen(t, &conf, id)
				require.Equal(t, seq+1, r.state.seq)
				require.NoError(t, r.Close())
			})
		}
	}
}

func TestNativeRecorderDoesNotDiscardUnverifiedActiveStart(t *testing.T) {
	for _, stage := range []string{"foreign", "invalid-header-prefix", "invalid-length", "state0-with-record", "short-header-with-record", "invalid-signed-state0", "invalid-committed-header"} {
		t.Run(stage, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			r := nativeTestOpen(t, &conf, id)
			require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed"}))
			require.NoError(t, r.Seal())
			data, err := nativeReadFile(r.file)
			require.NoError(t, err)
			switch stage {
			case "foreign":
				data = []byte("user content")
			case "invalid-header-prefix":
				data[len(nativeformat.AuditMagic)] = byte(nativeformat.ContentUnit)
				data = data[:len(nativeformat.AuditMagic)+3]
			case "invalid-length":
				data[len(nativeformat.AuditMagic)+5] = 0
				binary.BigEndian.PutUint32(data[len(nativeformat.AuditMagic)+1:], nativeformat.MaxMetadataPayload+1)
				data = data[:len(nativeformat.AuditMagic)+6]
			case "state0-with-record":
				data[len(nativeformat.AuditMagic)+5] = 0
				_, payload, _, err := newNativeAuditRecord(id, r.state.lastRecord, Event{Name: "test.extra"}, uuid.New(), time.Now(), nil)
				require.NoError(t, err)
				frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
				require.NoError(t, err)
				data = append(data, frame...)
			case "short-header-with-record":
				offset := len(nativeformat.AuditMagic)
				data[offset+5] = 0
				binary.BigEndian.PutUint32(data[offset+1:offset+5], nativeformat.MaxMetadataPayload)
				data = data[:offset+6]
				_, payload, _, err := newNativeAuditRecord(id, r.state.lastRecord, Event{Name: "test.extra"}, uuid.New(), time.Now(), nil)
				require.NoError(t, err)
				frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
				require.NoError(t, err)
				data = append(data, frame...)
			case "invalid-signed-state0", "invalid-committed-header":
				h, _, err := newNativeAuditHeader(id, r.state.seq, r.state.prevSegment, r.state.lastRecord, time.Now(), r.fingerprint)
				require.NoError(t, err)
				h.Signature[0] ^= 1
				payload, err := nativeformat.Marshal(h, nativeformat.MaxMetadataPayload)
				require.NoError(t, err)
				frame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, payload, nativeformat.MaxMetadataPayload)
				require.NoError(t, err)
				if stage == "invalid-signed-state0" {
					frame[5] = 0
				}
				data = append(data[:len(nativeformat.AuditMagic)], frame...)
			}
			path := r.activePath
			require.NoError(t, r.file.Close())
			require.NoError(t, os.WriteFile(path, data, journalFileMode))
			require.NoError(t, r.lock.Close())
			_, err = newNativeRecorder(&conf, id)
			require.Error(t, err)
			preserved, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, data, preserved)
		})
	}
}

func TestNativeRecorderRecoversInterruptedHeaderWithMarkerInPayload(t *testing.T) {
	id := nativeTestIdentity(t)
	fingerprint := "SHA256:" + strings.Repeat("BFCOMMIT", 5) + "AAA"
	_, payload, err := newNativeAuditHeader(id, 1, journalHash{}, journalHash{}, time.Now().UTC(), fingerprint)
	require.NoError(t, err)
	frame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	marker := bytes.Index(frame[:len(frame)-len(nativeformat.CommitMarker)], []byte(nativeformat.CommitMarker))
	require.Greater(t, marker, 6)
	data := append([]byte(nativeformat.AuditMagic), frame[:marker+len(nativeformat.CommitMarker)]...)
	data[len(nativeformat.AuditMagic)+5] = 0
	directory := t.TempDir()
	file, err := os.OpenFile(filepath.Join(directory, "active.beaudit"), os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	_, err = file.Write(data)
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	require.NoError(t, nativeRecoverActiveStart(file, directory, id, 1, journalHash{}, journalHash{}, fingerprint))
	actual, err := os.ReadFile(file.Name())
	require.NoError(t, err)
	require.Equal(t, []byte(nativeformat.AuditMagic), actual)
}

func TestNativeRecorderDoesNotDiscardHeaderBeforeActiveCheckpoint(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.confirmed-in-active"}))
	path := r.activePath
	data, err := nativeReadFile(r.file)
	require.NoError(t, err)
	data = data[:len(nativeformat.AuditMagic)+3]
	require.NoError(t, r.file.Close())
	require.NoError(t, os.WriteFile(path, data, journalFileMode))
	require.NoError(t, r.lock.Close())
	_, err = newNativeRecorder(&conf, id)
	require.Error(t, err)
	preserved, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, preserved)
}

func TestNativeRecorderRejectsCommittedCorruptionAndMissingCheckpoint(t *testing.T) {
	for _, scenario := range []string{"committed", "checkpoint"} {
		t.Run(scenario, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, false)
			r := nativeTestOpen(t, &conf, id)
			require.NoError(t, r.Record(context.Background(), Event{Name: "test.first"}))
			path, end := r.activePath, r.state.fileBytes
			_, payload, _, err := newNativeAuditRecord(id, r.state.lastRecord, Event{Name: "test.second"}, uuid.New(), time.Now(), nil)
			require.NoError(t, err)
			frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
			require.NoError(t, err)
			if scenario == "committed" {
				frame[6] ^= 1
			} else {
				_, replacement, err := newNativeAuditHead(id, journalHash{99})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(r.headDirectory, nativeHeadFileName), replacement, journalFileMode))
				frame[5] = 0
			}
			_, err = r.file.WriteAt(frame, end)
			require.NoError(t, err)
			require.NoError(t, r.file.Sync())
			require.NoError(t, r.file.Close())
			require.NoError(t, r.lock.Close())
			_, err = newNativeRecorder(&conf, id)
			require.Error(t, err)
			info, err := os.Stat(path)
			require.NoError(t, err)
			require.Equal(t, end+int64(len(frame)), info.Size(), "rejected data must not be truncated")
		})
	}
}

func TestNativeRecorderPublishesInterruptedSeal(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.first"}))
	seq, last, path := r.state.seq, r.state.lastRecord, r.activePath
	data, err := nativeReadFile(r.file)
	require.NoError(t, err)
	_, payload, err := newNativeAuditSeal(id, seq, r.state.count, uint64(len(data)), hashNativeAuditContent(data), last, time.Now())
	require.NoError(t, err)
	_, err = nativeWriteUnit(r.file, int64(len(data)), nativeformat.SealUnit, payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.NoError(t, r.file.Close())
	require.NoError(t, r.lock.Close())
	r = nativeTestOpen(t, &conf, id)
	require.Equal(t, seq+1, r.state.seq)
	require.Equal(t, last, r.state.lastRecord)
	require.FileExists(t, filepath.Join(r.headDirectory, nativeSegmentName(seq, r.state.prevSegment, false)))
	require.FileExists(t, path)
	require.NoError(t, r.Close())
}

func TestNativeRecorderRejectsDifferentAgeRecipient(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, true)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.first"}))
	require.NoError(t, r.Close())
	key, err := auditIdentityKeyRequirement.GenerateKey(nil)
	require.NoError(t, err)
	conf.EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(key.PublicKey().ToSsh())))
	_, err = newNativeRecorder(&conf, id)
	require.Error(t, err)
}

func TestNativeRecorderSuppressibleAndLegacyEntry(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	r.availableBytes = func(string) (uint64, error) { return 0, nil }
	ok, err := r.RecordSuppressible(context.Background(), Event{Name: "test.optional"})
	require.NoError(t, err)
	require.False(t, ok)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.required"}))
	require.NoError(t, os.WriteFile(filepath.Join(r.headDirectory, "head.json"), []byte("legacy"), journalFileMode))
	// A legacy entry remains untouched and prevents the next startup.
	require.NoError(t, r.Close())
	_, err = newNativeRecorder(&conf, id)
	require.Error(t, err)
	require.FileExists(t, filepath.Join(filepath.Join(conf.Directory, id.ProducerId().String()), "head.json"))
}

func TestNativeRecorderStrictCloseReportsPoison(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	require.NoError(t, r.Record(context.Background(), Event{Name: "test.first"}))
	require.NoError(t, os.Remove(filepath.Join(r.headDirectory, nativeHeadFileName)))
	err := r.Record(context.Background(), Event{Name: "test.second"})
	require.Error(t, err)
	require.ErrorIs(t, r.Close(), err)
	require.ErrorIs(t, r.Close(), err)
	require.NoError(t, r.CloseAfterAcceptedFailure())
}

func TestNativeRecorderTamperingAndUnknownEntries(t *testing.T) {
	for _, what := range []string{"record", "head", "unknown", "recipient"} {
		t.Run(what, func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, what == "recipient")
			r := nativeTestOpen(t, &conf, id)
			require.NoError(t, r.Record(context.Background(), Event{Name: "test.first"}))
			directory := r.headDirectory
			require.NoError(t, r.Close())
			switch what {
			case "record":
				entries, err := os.ReadDir(directory)
				require.NoError(t, err)
				for _, entry := range entries {
					if len(entry.Name()) >= 8 && entry.Name()[:8] == "segment-" {
						path := filepath.Join(directory, entry.Name())
						data, err := os.ReadFile(path)
						require.NoError(t, err)
						data[len(data)/2] ^= 1
						require.NoError(t, os.WriteFile(path, data, journalFileMode))
					}
				}
			case "head":
				path := filepath.Join(directory, nativeHeadFileName)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				data[len(data)-1] ^= 1
				require.NoError(t, os.WriteFile(path, data, journalFileMode))
			case "unknown":
				require.NoError(t, os.WriteFile(filepath.Join(directory, "user.txt"), []byte("keep"), journalFileMode))
			case "recipient":
				conf.EncryptionPublicKey = ""
			}
			_, err := newNativeRecorder(&conf, id)
			require.Error(t, err)
			if what == "unknown" {
				data, err := os.ReadFile(filepath.Join(directory, "user.txt"))
				require.NoError(t, err)
				require.True(t, bytes.Equal(data, []byte("keep")))
			}
		})
	}
}

func nativeTestWriteSealedChain(t *testing.T, r *nativeRecorder, count int) {
	t.Helper()
	directory, activePath, identity := r.headDirectory, r.activePath, r.identity
	encrypted, recipient := r.recipient != nil, r.recipient
	fingerprint := r.fingerprint
	require.NoError(t, r.Close())
	require.NoError(t, os.Remove(activePath))
	var previousSegment, previousRecord journalHash
	for seq := 1; seq <= count; seq++ {
		_, header, err := newNativeAuditHeader(identity, uint64(seq), previousSegment, previousRecord, time.Now().UTC(), fingerprint)
		require.NoError(t, err)
		frame, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, header, nativeformat.MaxMetadataPayload)
		require.NoError(t, err)
		data := append([]byte(nativeformat.AuditMagic), frame...)
		_, record, hash, err := newNativeAuditRecord(identity, previousRecord, Event{Name: "test.spill"}, uuid.New(), time.Now().UTC(), recipient)
		require.NoError(t, err)
		frame, err = nativeformat.EncodeUnit(nativeformat.ContentUnit, record, nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		data = append(data, frame...)
		_, seal, err := newNativeAuditSeal(identity, uint64(seq), 1, uint64(len(data)), hashNativeAuditContent(data), hash, time.Now().UTC())
		require.NoError(t, err)
		frame, err = nativeformat.EncodeUnit(nativeformat.SealUnit, seal, nativeformat.MaxMetadataPayload)
		require.NoError(t, err)
		data = append(data, frame...)
		previousSegment, previousRecord = hashNativeAuditSegment(data), hash
		require.NoError(t, os.WriteFile(filepath.Join(directory, nativeSegmentName(uint64(seq), previousSegment, encrypted)), data, journalFileMode))
	}
	var zero journalHash
	require.NoError(t, writeNativeHead(directory, identity, &zero, previousRecord))
}

func TestNativeRecorderRecoveryAcrossSortedRuns(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			conf, id := nativeRecorderTestConfig(t, encrypted)
			r := nativeTestOpen(t, &conf, id)
			nativeTestWriteSealedChain(t, r, journalSegmentSortChunkSize+1)
			if encrypted {
				unusable := filepath.Join(t.TempDir(), "not-a-directory")
				require.NoError(t, os.WriteFile(unusable, nil, 0600))
				for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
					t.Setenv(variable, unusable)
				}
			}
			r = nativeTestOpen(t, &conf, id)
			require.EqualValues(t, journalSegmentSortChunkSize+2, r.state.seq)
			require.NoError(t, r.Close())
			work := filepath.Join(conf.Directory, journalWorkDirectoryName)
			entries, err := os.ReadDir(work)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}

func TestNativeRecorderRejectsAliasedPublishedSegmentBeforeTruncation(t *testing.T) {
	conf, id := nativeRecorderTestConfig(t, false)
	r := nativeTestOpen(t, &conf, id)
	nativeTestWriteSealedChain(t, r, 2)
	active := filepath.Join(r.headDirectory, nativeActiveClear)
	entries, _, _, err := nativeInventory(r.headDirectory, nativeActiveClear, false)
	require.NoError(t, err)
	first := entries[0].path
	if err := os.Link(first, active); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	_, err = newNativeRecorder(&conf, id)
	require.ErrorContains(t, err, "aliases a published segment")
	require.FileExists(t, first)
}
