package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestJournalRecordSignaturesAndHashChain(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	first, firstPayload, firstHash, err := newJournalRecord(
		identity,
		journalHash{},
		Event{Name: "test.first"},
		uuid.New(),
		time.Now().UTC(),
	)
	require.NoError(t, err)
	require.NotEmpty(t, first.Signature)

	decoded, decodedHash, err := decodeJournalRecord(firstPayload, identity, journalHash{})
	require.NoError(t, err)
	require.Equal(t, first, decoded)
	require.Equal(t, firstHash, decodedHash)

	_, secondPayload, _, err := newJournalRecord(
		identity,
		firstHash,
		Event{Name: "test.second"},
		uuid.New(),
		time.Now().UTC(),
	)
	require.NoError(t, err)
	_, _, err = decodeJournalRecord(secondPayload, identity, journalHash{})
	require.ErrorContains(t, err, "record chain does not continue")

	tampered := bytes.Replace(firstPayload, []byte("test.first"), []byte("test.other"), 1)
	require.NotEqual(t, firstPayload, tampered)
	_, _, err = decodeJournalRecord(tampered, identity, journalHash{})
	require.ErrorContains(t, err, "illegal audit signature")
}

func TestEncryptedJournalRecordIsIndependentAndAuthenticated(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	decryptionIdentity, publicKey := newJournalTestEncryptionKey(t)
	encryptor, err := newJournalEventEncryptor(publicKey)
	require.NoError(t, err)
	decrypter, err := newJournalEventDecrypter([]crypto.PrivateKey{decryptionIdentity})
	require.NoError(t, err)
	id := uuid.New()
	recordedAt := time.Now().UTC()

	first, firstPayload, firstHash, err := newJournalRecord(identity, journalHash{}, Event{Name: "test.secret"}, id, recordedAt, encryptor)
	require.NoError(t, err)
	require.Equal(t, journalEncryptedRecordSchema, first.Schema)
	require.NotContains(t, string(firstPayload), "test.secret")
	decoded, decodedHash, err := decodeJournalRecord(firstPayload, identity, journalHash{}, decrypter)
	require.NoError(t, err)
	require.Equal(t, "test.secret", decoded.Event.Name)
	require.Equal(t, firstHash, decodedHash)

	_, secondPayload, _, err := newJournalRecord(identity, journalHash{}, Event{Name: "test.secret"}, uuid.New(), recordedAt, encryptor)
	require.NoError(t, err)
	require.NotEqual(t, firstPayload, secondPayload)
	var firstEncrypted, secondEncrypted journalEncryptedRecord
	require.NoError(t, json.Unmarshal(firstPayload, &firstEncrypted))
	require.NoError(t, json.Unmarshal(secondPayload, &secondEncrypted))
	require.NotEqual(t, firstEncrypted.EncryptedEvent.Ciphertext, secondEncrypted.EncryptedEvent.Ciphertext)

	var tampered journalEncryptedRecord
	require.NoError(t, json.Unmarshal(firstPayload, &tampered))
	tampered.EncryptedEvent.Ciphertext[len(tampered.EncryptedEvent.Ciphertext)-1] ^= 1
	tamperedPayload, err := json.Marshal(tampered)
	require.NoError(t, err)
	_, _, err = decodeJournalRecord(tamperedPayload, identity, journalHash{}, decrypter)
	require.ErrorContains(t, err, "illegal audit signature")

	unsigned, err := json.Marshal(tampered.journalEncryptedRecordContent)
	require.NoError(t, err)
	tampered.Signature, err = identity.sign(append([]byte(journalEncryptedRecordSignatureDomain), unsigned...))
	require.NoError(t, err)
	tamperedPayload, err = json.Marshal(tampered)
	require.NoError(t, err)
	_, _, err = decodeJournalRecord(tamperedPayload, identity, journalHash{}, decrypter)
	require.Error(t, err)
}

func TestAuditEventEncryptionSupportsSshRsa(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key, err := crypto.PrivateKeyFromSdk(private)
	require.NoError(t, err)
	publicKey := crypto.PublicKeys(strings.TrimSpace(string(crypto.MarshalPublicKey(key.PublicKey()))))
	encryptor, err := newJournalEventEncryptor(publicKey)
	require.NoError(t, err)
	decrypter, err := newJournalEventDecrypter([]crypto.PrivateKey{key})
	require.NoError(t, err)

	encrypted, err := encryptor.encrypt(Event{Name: "test.rsa"})
	require.NoError(t, err)
	decrypted, err := decrypter.decrypt(encrypted)
	require.NoError(t, err)
	require.Equal(t, "test.rsa", decrypted.Name)
}

func TestResolveEncryptionPublicKeyFile(t *testing.T) {
	_, publicKey := newJournalTestEncryptionKey(t)
	path := filepath.Join(t.TempDir(), "encryption.pub")
	require.NoError(t, os.WriteFile(path, []byte(publicKey+"\n"), 0600))
	resolved, err := ResolveEncryptionPublicKey("", crypto.PublicKeysFile(path))
	require.NoError(t, err)
	require.Equal(t, publicKey, resolved)

	_, err = ResolveEncryptionPublicKey(publicKey, crypto.PublicKeysFile(path))
	require.ErrorContains(t, err, "cannot be combined")
	require.NoError(t, os.WriteFile(path, []byte(publicKey+"\n"+publicKey+"\n"), 0600))
	_, err = ResolveEncryptionPublicKey("", crypto.PublicKeysFile(path))
	require.ErrorContains(t, err, "exactly one SSH public key")
	_, err = ResolveEncryptionPublicKey("", crypto.PublicKeysFile(filepath.Join(t.TempDir(), "missing.pub")))
	require.ErrorContains(t, err, "cannot load")

	oversized := filepath.Join(t.TempDir(), "oversized.pub")
	file, err := os.Create(oversized)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(maxEncryptionPublicKeyFileSize+1))
	require.NoError(t, file.Close())
	_, err = ResolveEncryptionPublicKey("", crypto.PublicKeysFile(oversized))
	require.ErrorContains(t, err, "exceeds")
}

func TestJournalSegmentMetadataSignatures(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	createdAt := time.Now().UTC()
	header, headerPayload, err := newJournalSegmentHeader(identity, 1, journalHash{}, journalHash{}, createdAt)
	require.NoError(t, err)
	decodedHeader, err := decodeJournalSegmentHeader(headerPayload, identity, 1, journalHash{}, journalHash{})
	require.NoError(t, err)
	require.Equal(t, header, decodedHeader)

	header.CreatedAt = header.CreatedAt.Add(time.Second)
	tamperedHeader, err := json.Marshal(header)
	require.NoError(t, err)
	_, err = decodeJournalSegmentHeader(tamperedHeader, identity, 1, journalHash{}, journalHash{})
	require.ErrorContains(t, err, "illegal audit signature")

	contentHash := hashJournalBytes(journalSegmentContentHashDomain, []byte("content"))
	lastRecordHash := hashJournalBytes(journalRecordHashDomain, []byte("record"))
	state := journalSegmentState{
		sequence:           1,
		previousRecordHash: lastRecordHash,
		recordCount:        1,
		contentBytes:       123,
	}
	seal, sealPayload, err := newJournalSegmentSeal(identity, state.sequence, state.recordCount, uint64(state.contentBytes), contentHash, lastRecordHash, createdAt)
	require.NoError(t, err)
	decodedSeal, err := decodeJournalSegmentSeal(sealPayload, identity, state, contentHash)
	require.NoError(t, err)
	require.Equal(t, seal, decodedSeal)

	seal.SealedAt = seal.SealedAt.Add(time.Second)
	tamperedSeal, err := json.Marshal(seal)
	require.NoError(t, err)
	_, err = decodeJournalSegmentSeal(tamperedSeal, identity, state, contentHash)
	require.ErrorContains(t, err, "illegal audit signature")
}

func TestJournalSegmentScannerTransitionsThroughHeaderRecordAndSeal(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	recordedAt := time.Now().UTC()
	_, headerPayload, err := newJournalSegmentHeader(identity, 1, journalHash{}, journalHash{}, recordedAt)
	require.NoError(t, err)
	headerFrame, err := encodeJournalFrame(headerPayload)
	require.NoError(t, err)
	_, recordPayload, recordHash, err := newJournalRecord(identity, journalHash{}, Event{Name: "test.transition"}, uuid.New(), recordedAt)
	require.NoError(t, err)
	recordFrame, err := encodeJournalFrame(recordPayload)
	require.NoError(t, err)
	content := append(append([]byte(nil), headerFrame...), recordFrame...)
	_, sealPayload, err := newJournalSegmentSeal(
		identity,
		1,
		1,
		uint64(len(content)),
		hashJournalBytes(journalSegmentContentHashDomain, content),
		recordHash,
		recordedAt,
	)
	require.NoError(t, err)
	sealFrame, err := encodeJournalFrame(sealPayload)
	require.NoError(t, err)
	segment := append(append([]byte(nil), content...), sealFrame...)
	path := filepath.Join(t.TempDir(), "scanner.journal")
	require.NoError(t, os.WriteFile(path, segment, journalFileMode))
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	var digest bytes.Buffer
	scanner, err := newJournalSegmentScanner(file, journalSegmentScanOptions{
		identity:       identity,
		sequence:       1,
		checkpointHash: recordHash,
		digest:         &digest,
	})
	require.NoError(t, err)

	complete, err := scanner.scanNextFrame()
	require.NoError(t, err)
	require.True(t, complete)
	require.True(t, scanner.state.header)
	require.False(t, scanner.state.sealed)
	require.Zero(t, scanner.state.recordCount)
	require.False(t, scanner.state.checkpointSeen)
	require.Equal(t, int64(len(headerFrame)), scanner.state.contentBytes)

	complete, err = scanner.scanNextFrame()
	require.NoError(t, err)
	require.True(t, complete)
	require.Equal(t, uint64(1), scanner.state.recordCount)
	require.Equal(t, recordHash, scanner.state.previousRecordHash)
	require.True(t, scanner.state.checkpointSeen)
	require.Equal(t, int64(len(content)), scanner.state.contentBytes)

	complete, err = scanner.scanNextFrame()
	require.NoError(t, err)
	require.True(t, complete)
	require.True(t, scanner.state.sealed)
	require.Equal(t, int64(len(segment)), scanner.state.fileBytes)
	require.Equal(t, hashJournalBytes(journalSegmentHashDomain, segment), scanner.state.segmentHash)
	require.Equal(t, segment, digest.Bytes())
}

func TestJournalHeadSignature(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	lastRecordHash := hashJournalBytes(journalRecordHashDomain, []byte("record"))
	head, payload, err := newJournalHead(identity, lastRecordHash)
	require.NoError(t, err)
	decoded, err := decodeJournalHead(payload, identity)
	require.NoError(t, err)
	require.Equal(t, head, decoded)

	head.LastRecordHash = hashJournalBytes(journalRecordHashDomain, []byte("other"))
	tampered, err := json.Marshal(head)
	require.NoError(t, err)
	_, err = decodeJournalHead(tampered, identity)
	require.ErrorContains(t, err, "illegal audit signature")
}

func TestSealedJournalFileNameIsCanonical(t *testing.T) {
	hash := hashJournalBytes(journalSegmentHashDomain, []byte("segment"))
	name := sealedJournalFileName(42, hash)
	sequence, decodedHash, ok := parseSealedJournalFileName(name)
	require.True(t, ok)
	require.Equal(t, uint64(42), sequence)
	require.Equal(t, hash, decodedHash)

	uppercaseHashName := strings.Replace(name, hash.String(), strings.ToUpper(hash.String()), 1)
	require.NotEqual(t, name, uppercaseHashName)
	_, _, ok = parseSealedJournalFileName(uppercaseHashName)
	require.False(t, ok)
}

func TestLocalJournalRotatesAndRecoversSegmentChain(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	local := recorder.(*localJournalRecorder)
	local.targetSize = local.state.contentBytes + 1

	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.first"}))
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.second"}))
	require.NoError(t, recorder.Close())

	directory := producerJournalTestDirectory(conf, identity)
	segments, hasActive, err := inventoryJournalTestSegments(directory)
	require.NoError(t, err)
	require.True(t, hasActive)
	require.Len(t, segments, 2)
	require.Equal(t, uint64(1), segments[0].sequence)
	require.Equal(t, uint64(2), segments[1].sequence)
	require.NotEqual(t, segments[0].hash, segments[1].hash)
	require.Len(t, readJournalTestRecords(t, conf, identity), 2)

	reopened, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	reopenedLocal := reopened.(*localJournalRecorder)
	require.Equal(t, uint64(3), reopenedLocal.state.sequence)
	require.Equal(t, segments[1].hash, reopenedLocal.state.previousSegmentHash)
	require.False(t, reopenedLocal.state.previousRecordHash.IsZero())
	require.NoError(t, reopened.Close())
}

func TestLocalJournalPublishesCommittedSealDuringRecovery(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.before-crash"}))
	appendSealAndCrashCloseJournalTestRecorder(t, recorder)

	recovered, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	segments, hasActive, err := inventoryJournalTestSegments(producerJournalTestDirectory(conf, identity))
	require.NoError(t, err)
	require.True(t, hasActive)
	require.Len(t, segments, 1)
	require.Equal(t, uint64(2), recovered.(*localJournalRecorder).state.sequence)
	require.Len(t, readJournalTestRecords(t, conf, identity), 1)
	require.NoError(t, recovered.Close())
}

func TestLocalJournalRejectsDeletedLatestSegment(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.must-not-disappear"}))
	require.NoError(t, recorder.Close())

	segments, hasActive, err := inventoryJournalTestSegments(producerJournalTestDirectory(conf, identity))
	require.NoError(t, err)
	require.True(t, hasActive)
	require.Len(t, segments, 1)
	require.NoError(t, makeActiveJournalWritable(segments[0].path))
	require.NoError(t, os.Remove(segments[0].path))

	failed, err := NewRecorder(&conf, identity)
	require.Nil(t, failed)
	require.ErrorContains(t, err, "schema or sequence")
}

func TestLocalJournalHeadDetectsActiveTailLoss(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove func(*testing.T, string)
	}{
		{"deleted", func(t *testing.T, path string) {
			require.NoError(t, os.Remove(path))
		}},
		{"truncated", func(t *testing.T, path string) {
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			headerPayloadSize := int(binary.BigEndian.Uint32(raw[:journalFrameLengthSize]))
			headerFrameSize := journalFrameLengthSize + headerPayloadSize + journalFrameChecksumSize + len(journalFrameCommitMarker)
			require.NoError(t, os.Truncate(path, int64(headerFrameSize)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, identity := newJournalTestIdentity(t)
			recorder, err := NewRecorder(&conf, identity)
			require.NoError(t, err)
			require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.must-not-disappear"}))
			crashCloseJournalTestRecorder(t, recorder)
			tc.remove(t, journalTestActivePath(conf, identity))

			failed, err := NewRecorder(&conf, identity)
			require.Nil(t, failed)
			require.ErrorContains(t, err, "does not contain its committed head")
		})
	}
}

func TestLocalJournalRecoversHeadBehindValidRecords(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.committed"}))
	committedHash := recorder.(*localJournalRecorder).state.previousRecordHash
	crashCloseJournalTestRecorder(t, recorder)

	directory := producerJournalTestDirectory(conf, identity)
	require.NoError(t, writeJournalHead(directory, identity, journalHash{}))
	recovered, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	head, err := loadOrCreateJournalHead(directory, identity)
	require.NoError(t, err)
	require.Equal(t, committedHash, head.LastRecordHash)
	require.NoError(t, recovered.Close())
}

func TestLocalJournalRejectsTamperingWithValidFrameChecksum(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.original"}))
	crashCloseJournalTestRecorder(t, recorder)

	activePath := journalTestActivePath(conf, identity)
	raw, err := os.ReadFile(activePath)
	require.NoError(t, err)
	headerPayloadSize := int(binary.BigEndian.Uint32(raw[:journalFrameLengthSize]))
	recordOffset := journalFrameLengthSize + headerPayloadSize + journalFrameChecksumSize + len(journalFrameCommitMarker)
	recordPayloadSize := int(binary.BigEndian.Uint32(raw[recordOffset : recordOffset+journalFrameLengthSize]))
	payloadOffset := recordOffset + journalFrameLengthSize
	payload := raw[payloadOffset : payloadOffset+recordPayloadSize]
	tamperedPayload := bytes.Replace(payload, []byte("test.original"), []byte("test.tampered"), 1)
	require.NotEqual(t, payload, tamperedPayload)
	copy(payload, tamperedPayload)
	checksumOffset := payloadOffset + recordPayloadSize
	binary.BigEndian.PutUint32(raw[checksumOffset:checksumOffset+journalFrameChecksumSize], crc32.Checksum(payload, journalChecksumTable))
	require.NoError(t, os.WriteFile(activePath, raw, journalFileMode))

	failed, err := NewRecorder(&conf, identity)
	require.Nil(t, failed)
	require.ErrorContains(t, err, "illegal audit signature")
}

func appendSealAndCrashCloseJournalTestRecorder(t *testing.T, recorder Recorder) journalSegmentState {
	t.Helper()
	local := recorder.(*localJournalRecorder)
	local.mutex.Lock()
	defer local.mutex.Unlock()

	content, err := readJournalFilePrefix(local.file, local.state.contentBytes)
	require.NoError(t, err)
	_, payload, err := newJournalSegmentSeal(
		local.identity,
		local.state.sequence,
		local.state.recordCount,
		uint64(local.state.contentBytes),
		hashJournalBytes(journalSegmentContentHashDomain, content),
		local.state.previousRecordHash,
		time.Now().UTC(),
	)
	require.NoError(t, err)
	frame, err := encodeJournalFrame(payload)
	require.NoError(t, err)
	require.NoError(t, writeCommittedJournalFrame(local.file, frame))

	state := local.state
	state.fileBytes += int64(len(frame))
	full, err := readJournalFilePrefix(local.file, state.fileBytes)
	require.NoError(t, err)
	state.segmentHash = hashJournalBytes(journalSegmentHashDomain, full)
	state.sealed = true
	require.NoError(t, local.file.Close())
	require.NoError(t, local.processLock.Close())
	local.closed = true
	return state
}

func producerJournalTestDirectory(conf configuration.Auditlog, identity *Identity) string {
	return filepath.Join(conf.Journal.Directory, identity.ProducerId().String())
}
