package audit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
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

func TestResolveEncryptionPublicKeyFileEnforcesRecipientPolicyBeforeJournalWrites(t *testing.T) {
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	strongRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		key       any
		wantError string
	}{
		{"rsa-1024", &weakRSA.PublicKey, "at least 2048 bits"},
		{"ecdsa", &ecdsaKey.PublicKey, "cannot be used for encryption"},
		{"rsa-2048", &strongRSA.PublicKey, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sshKey, err := ssh.NewPublicKey(tc.key)
			require.NoError(t, err)
			publicKey := crypto.PublicKeys(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey))))
			path := filepath.Join(t.TempDir(), "encryption.pub")
			require.NoError(t, os.WriteFile(path, []byte(publicKey+"\n"), 0600))

			resolved, err := ResolveEncryptionPublicKey("", crypto.PublicKeysFile(path))
			if tc.wantError == "" {
				require.NoError(t, err)
				require.Equal(t, publicKey, resolved)
				return
			}
			require.Empty(t, resolved)
			require.ErrorContains(t, err, tc.wantError)

			conf, identity := newJournalTestIdentity(t)
			conf.EncryptionPublicKeyFile = crypto.PublicKeysFile(path)
			require.NoDirExists(t, conf.Directory)
			recorder, err := NewRecorder(&conf, identity)
			require.Nil(t, recorder)
			require.ErrorContains(t, err, tc.wantError)
			require.NoDirExists(t, conf.Directory)
		})
	}
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

func TestNativeJournalRotatesAndRecoversSegmentChain(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	local := recorder.(*nativeRecorder)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.first"}))
	require.NoError(t, local.Seal())
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.second"}))
	require.NoError(t, recorder.Close())

	directory := producerJournalTestDirectory(conf, identity)
	segments, hasActive, hasHead, err := nativeInventory(directory, nativeActiveClear, false)
	require.NoError(t, err)
	require.True(t, hasActive)
	require.True(t, hasHead)
	require.Len(t, segments, 2)
	require.Equal(t, uint64(1), segments[0].seq)
	require.Equal(t, uint64(2), segments[1].seq)
	require.NotEqual(t, segments[0].hash, segments[1].hash)
	require.Len(t, readJournalTestRecords(t, conf, identity), 2)

	reopened, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	reopenedLocal := reopened.(*nativeRecorder)
	require.Equal(t, uint64(3), reopenedLocal.state.seq)
	require.Equal(t, segments[1].hash, reopenedLocal.state.prevSegment)
	require.False(t, reopenedLocal.state.lastRecord.IsZero())
	require.NoError(t, reopened.Close())
}

func TestNativeJournalPublishesCommittedSealDuringRecovery(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.before-crash"}))
	sealed := appendSealAndCrashCloseJournalTestRecorder(t, recorder)

	recovered, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	segments, hasActive, _, err := nativeInventory(producerJournalTestDirectory(conf, identity), nativeActiveClear, false)
	require.NoError(t, err)
	require.True(t, hasActive)
	require.Len(t, segments, 1)
	require.Equal(t, sealed.seq+1, recovered.(*nativeRecorder).state.seq)
	require.Len(t, readJournalTestRecords(t, conf, identity), 1)
	require.NoError(t, recovered.Close())
}

func TestNativeJournalRejectsDeletedLatestSegment(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.must-not-disappear"}))
	require.NoError(t, recorder.Close())

	segments, hasActive, _, err := nativeInventory(producerJournalTestDirectory(conf, identity), nativeActiveClear, false)
	require.NoError(t, err)
	require.True(t, hasActive)
	require.Len(t, segments, 1)
	require.NoError(t, os.Remove(segments[0].path))

	failed, err := NewRecorder(&conf, identity)
	require.Nil(t, failed)
	require.ErrorContains(t, err, "chain mismatch")
}

func TestNativeJournalHeadDetectsActiveTailLoss(t *testing.T) {
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
			require.NoError(t, os.Truncate(path, int64(nativeTestRecordOffset(t, raw))))
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
			require.ErrorContains(t, err, "checkpoint not in chain")
		})
	}
}

func TestNativeJournalRejectsMissingHeadWithHistory(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.committed"}))
	crashCloseJournalTestRecorder(t, recorder)
	headPath := filepath.Join(producerJournalTestDirectory(conf, identity), nativeHeadFileName)
	require.NoError(t, os.Remove(headPath))
	before, err := os.ReadFile(journalTestActivePath(conf, identity))
	require.NoError(t, err)

	failed, err := NewRecorder(&conf, identity)
	require.Nil(t, failed)
	require.ErrorContains(t, err, "head missing with existing history")
	require.NoFileExists(t, headPath)
	after, err := os.ReadFile(journalTestActivePath(conf, identity))
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestNativeJournalRecoversHeadBehindValidRecords(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.committed"}))
	committedHash := recorder.(*nativeRecorder).state.lastRecord
	crashCloseJournalTestRecorder(t, recorder)

	directory := producerJournalTestDirectory(conf, identity)
	_, payload, err := newNativeAuditHead(identity, journalHash{})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, nativeHeadFileName), payload, journalFileMode))
	recovered, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	head, err := readNativeHead(directory, identity)
	require.NoError(t, err)
	require.Equal(t, committedHash, head)
	require.NoError(t, recovered.Close())
}

func TestNativeJournalRejectsTamperingWithValidFrameChecksum(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.original"}))
	crashCloseJournalTestRecorder(t, recorder)

	activePath := journalTestActivePath(conf, identity)
	raw, err := os.ReadFile(activePath)
	require.NoError(t, err)
	recordOffset := nativeTestRecordOffset(t, raw)
	unit, _, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(raw), int64(recordOffset), int64(len(raw)), nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	require.False(t, tail)
	record, err := nativeformat.Unmarshal[nativeAuditRecord](unit.Payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	record.PublicEvent.Name = "test.tampered"
	payload, err := nativeformat.Marshal(record, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
	require.NoError(t, err)
	raw = append(raw[:recordOffset], frame...)
	require.NoError(t, os.WriteFile(activePath, raw, journalFileMode))

	failed, err := NewRecorder(&conf, identity)
	require.Nil(t, failed)
	require.ErrorContains(t, err, "illegal audit signature")
	actual, readErr := os.ReadFile(activePath)
	require.NoError(t, readErr)
	require.Equal(t, raw, actual)
}

func appendSealAndCrashCloseJournalTestRecorder(t *testing.T, recorder Recorder) nativeSegmentState {
	t.Helper()
	local := recorder.(*nativeRecorder)
	local.mutex.Lock()
	defer local.mutex.Unlock()

	content, err := nativeReadFile(local.file)
	require.NoError(t, err)
	_, payload, err := newNativeAuditSeal(
		local.identity,
		local.state.seq,
		local.state.count,
		uint64(len(content)),
		hashNativeAuditContent(content),
		local.state.lastRecord,
		time.Now().UTC(),
	)
	require.NoError(t, err)
	_, err = nativeWriteUnit(local.file, int64(len(content)), nativeformat.SealUnit, payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)

	state := local.state
	require.NoError(t, local.file.Close())
	require.NoError(t, local.lock.Close())
	local.closed = true
	return state
}

func producerJournalTestDirectory(conf configuration.Auditlog, identity *Identity) string {
	return filepath.Join(conf.Directory, identity.ProducerId().String())
}
