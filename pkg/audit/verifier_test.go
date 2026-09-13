package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestVerifyJournalsUsesOnlyPublicJournalDataAndDoesNotMutate(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.first"}))
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.second"}))
	require.NoError(t, recorder.Close())
	require.NoError(t, os.Remove(conf.IdentityFile))
	before := snapshotJournalTestTree(t, conf.Journal.Directory)

	verification, err := VerifyJournals(context.Background(), []JournalSource{{Name: "default", Directory: conf.Journal.Directory}})
	require.NoError(t, err)
	require.Equal(t, before, snapshotJournalTestTree(t, conf.Journal.Directory))
	canonicalDirectory, err := filepath.EvalSymlinks(conf.Journal.Directory)
	require.NoError(t, err)
	require.Equal(t, []VerifiedJournal{{
		Name:          "default",
		Directory:     canonicalDirectory,
		ProducerCount: 1,
		SegmentCount:  2,
		RecordCount:   2,
	}}, verification.Journals)
	records := verification.Records()
	require.Len(t, records, 2)
	require.Equal(t, "test.first", records[0].Event.Name)
	require.Equal(t, "test.second", records[1].Event.Name)
	require.Equal(t, records[0].Hash, records[1].PreviousHash)
	require.NoError(t, VerifyJournalIntegrity(context.Background(), []JournalSource{{Name: "default", Directory: conf.Journal.Directory}}))
}

func TestVerifierBudgetBoundsOnlyMaterializedRecords(t *testing.T) {
	budget := verifierBudget{records: maxMaterializedVerifiedRecords - 1}
	require.NoError(t, budget.consume(1, true))
	require.ErrorContains(t, budget.consume(1, true), "materialization limit")

	budget = verifierBudget{bytes: maxMaterializedVerifiedBytes - 1}
	require.NoError(t, budget.consume(1, true))
	require.ErrorContains(t, budget.consume(1, true), "materialization limit")

	budget = verifierBudget{records: maxMaterializedVerifiedRecords, bytes: maxMaterializedVerifiedBytes}
	require.NoError(t, budget.consume(maxJournalRecordPayloadSize, false))
	require.Equal(t, int64(maxMaterializedVerifiedBytes), budget.bytes)
}

func TestVerifierSnapshotsDetectMetadataPreservingProducerReplacementAndContentChange(t *testing.T) {
	root := t.TempDir()
	producer := filepath.Join(root, "producer")
	require.NoError(t, os.Mkdir(producer, 0700))
	rootInfo, err := os.Stat(root)
	require.NoError(t, err)
	producerInfo, err := os.Stat(producer)
	require.NoError(t, err)
	producerIdentity, err := snapshotVerifierPath(producer)
	require.NoError(t, err)
	before, err := snapshotVerifierDirectory(context.Background(), root)
	require.NoError(t, err)
	replacement := filepath.Join(root, "replacement")
	require.NoError(t, os.Mkdir(replacement, 0700))
	require.NoError(t, os.Chtimes(replacement, producerInfo.ModTime(), producerInfo.ModTime()))
	require.NoError(t, os.Remove(producer))
	require.NoError(t, os.Rename(replacement, producer))
	require.NoError(t, os.Chtimes(root, rootInfo.ModTime(), rootInfo.ModTime()))
	replacementInfo, err := os.Stat(producer)
	require.NoError(t, err)
	require.Equal(t, producerInfo.Mode(), replacementInfo.Mode())
	require.Equal(t, producerInfo.Size(), replacementInfo.Size())
	require.True(t, producerInfo.ModTime().Equal(replacementInfo.ModTime()))
	replacementIdentity, err := snapshotVerifierPath(producer)
	require.NoError(t, err)
	require.NotEqual(t, producerIdentity.identity, replacementIdentity.identity)
	after, err := snapshotVerifierDirectory(context.Background(), root)
	require.NoError(t, err)
	require.False(t, equalVerifierDirectorySnapshots(before, after))

	file := filepath.Join(root, "segment")
	require.NoError(t, os.WriteFile(file, []byte("first"), 0600))
	info, err := os.Stat(file)
	require.NoError(t, err)
	left := []verifierSegmentFile{{name: "segment", size: info.Size(), info: info, digest: sha256.Sum256([]byte("first"))}}
	right := []verifierSegmentFile{{name: "segment", size: info.Size(), info: info, digest: sha256.Sum256([]byte("other"))}}
	require.False(t, equalVerifierSegments(left, right))
}

func TestVerifyJournalsFallsBackToJournalWorkspace(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.workspace"}))
	require.NoError(t, recorder.Close())
	unusableTemporaryDirectory := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(unusableTemporaryDirectory, nil, 0600))
	for _, variable := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(variable, unusableTemporaryDirectory)
	}

	verification, err := VerifyJournals(context.Background(), []JournalSource{{Name: "fallback", Directory: conf.Journal.Directory}})
	require.NoError(t, err)
	require.Len(t, verification.Records(), 1)
	workRoot := filepath.Join(conf.Journal.Directory, journalWorkDirectoryName)
	info, err := os.Stat(workRoot)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	}
	entries, err := os.ReadDir(workRoot)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestVerifierSegmentInventoryIsBoundedAndCancellable(t *testing.T) {
	directory := t.TempDir()
	workspace := t.TempDir()
	active := filepath.Join(directory, journalActiveFileName)
	file, err := os.Create(active)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(int64(defaultJournalSegmentTargetSize+maxJournalRecordPayloadSize*2)+1))
	require.NoError(t, file.Close())
	_, _, err = newVerifierSegmentInventory(context.Background(), directory, workspace)
	require.ErrorContains(t, err, "exceeds")

	require.NoError(t, os.WriteFile(active, []byte("small"), 0600))
	segments, activeSegment, err := newVerifierSegmentInventory(context.Background(), directory, workspace)
	require.NoError(t, err)
	require.NotNil(t, activeSegment)
	_, found, err := segments.Next(context.Background())
	require.NoError(t, err)
	require.False(t, found)
	require.NoError(t, segments.Close())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = newVerifierSegmentInventory(ctx, directory, workspace)
	require.ErrorContains(t, err, "canceled")
}

func TestVerifyJournalsAcceptsMoreThanFormerSegmentLimit(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	producerDirectory := producerJournalTestDirectory(conf, identity)
	require.NoError(t, os.MkdirAll(producerDirectory, journalDirectoryMode))
	const segmentCount = uint64(4_097)
	lastRecordHash := writeVerifierTestSegments(t, producerDirectory, identity, segmentCount)
	require.NoError(t, writeJournalHead(producerDirectory, identity, lastRecordHash))

	verification, err := VerifyJournals(context.Background(), []JournalSource{{Name: "long-lived", Directory: conf.Journal.Directory}})
	require.NoError(t, err)
	canonicalDirectory, err := filepath.EvalSymlinks(conf.Journal.Directory)
	require.NoError(t, err)
	require.Equal(t, []VerifiedJournal{{
		Name:          "long-lived",
		Directory:     canonicalDirectory,
		ProducerCount: 1,
		SegmentCount:  segmentCount,
		RecordCount:   segmentCount,
	}}, verification.Journals)
	recovered, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.Equal(t, segmentCount+1, recovered.(*localJournalRecorder).state.sequence)
	require.NoError(t, recovered.Close())
}

func TestVerifyJournalSourceDetectsMutationAfterProducerVerification(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.snapshot"}))
	require.NoError(t, recorder.Close())
	producerDirectory := producerJournalTestDirectory(conf, identity)
	segments, _, err := inventoryJournalTestSegments(producerDirectory)
	require.NoError(t, err)
	require.NotEmpty(t, segments)
	_, _, err = verifyJournalSourceWithProducerObserver(context.Background(), JournalSource{
		Name:      "mutating",
		Directory: conf.Journal.Directory,
	}, false, &verifierBudget{}, func(string) error {
		require.NoError(t, makeActiveJournalWritable(segments[0].path))
		file, err := os.OpenFile(segments[0].path, os.O_WRONLY|os.O_APPEND, journalFileMode)
		require.NoError(t, err)
		_, err = file.Write([]byte("changed"))
		require.NoError(t, err)
		return file.Close()
	})
	require.ErrorContains(t, err, "changed during verification")
}

func TestVerifyJournalsReadsStableActiveSegment(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.active"}))
	crashCloseJournalTestRecorder(t, recorder)

	verification, err := VerifyJournals(context.Background(), []JournalSource{{Name: "active", Directory: conf.Journal.Directory}})
	require.NoError(t, err)
	require.Len(t, verification.Records(), 1)
	require.Equal(t, "test.active", verification.Records()[0].Event.Name)
}

func TestEncryptedJournalKeepsEventsConfidentialAndRecoversWithoutPrivateKey(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	decryptionIdentity, publicKey := newJournalTestEncryptionKey(t)
	publicKeyFile := filepath.Join(filepath.Dir(conf.IdentityFile), "audit-encryption.pub")
	require.NoError(t, os.WriteFile(publicKeyFile, []byte(publicKey+"\n"), 0600))
	conf.EncryptionPublicKeyFile = crypto.PublicKeysFile(publicKeyFile)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	recorder.(*localJournalRecorder).targetSize = 1
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "secret.audit.event"}))
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "secret.audit.second"}))
	crashCloseJournalTestRecorder(t, recorder)

	tree := snapshotJournalTestTree(t, conf.Journal.Directory)
	for _, entry := range tree {
		require.NotContains(t, entry.Data, "secret.audit.event")
		require.NotContains(t, entry.Data, "secret.audit.second")
	}
	recipient, err := EncryptionRecipientFingerprint(publicKey)
	require.NoError(t, err)
	source := JournalSource{
		Name:                        "encrypted",
		Directory:                   conf.Journal.Directory,
		ExpectedEncryptionRecipient: recipient,
	}
	verification, err := VerifyJournals(context.Background(), []JournalSource{source})
	require.Nil(t, verification)
	require.ErrorContains(t, err, "decryption identity")

	wrongIdentity, _ := newJournalTestEncryptionKey(t)
	source.DecryptionIdentities = []crypto.PrivateKey{wrongIdentity}
	verification, err = VerifyJournals(context.Background(), []JournalSource{source})
	require.Nil(t, verification)
	require.ErrorContains(t, err, "cannot decrypt")

	source.DecryptionIdentities = []crypto.PrivateKey{decryptionIdentity}
	verification, err = VerifyJournals(context.Background(), []JournalSource{source})
	require.NoError(t, err)
	require.Len(t, verification.Records(), 2)
	require.Equal(t, "secret.audit.event", verification.Records()[0].Event.Name)
	require.Equal(t, "secret.audit.second", verification.Records()[1].Event.Name)
	require.NoError(t, VerifyJournalIntegrity(context.Background(), []JournalSource{source}))

	reopened, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())

	_, replacementPublicKey := newJournalTestEncryptionKey(t)
	conf.EncryptionPublicKeyFile = ""
	conf.EncryptionPublicKey = replacementPublicKey
	reopened, err = NewRecorder(&conf, identity)
	require.Nil(t, reopened)
	require.ErrorContains(t, err, "does not match configured recipient")

	conf.EncryptionPublicKey = ""
	reopened, err = NewRecorder(&conf, identity)
	require.Nil(t, reopened)
	require.ErrorContains(t, err, "does not match configured recipient")
}

func TestAuditEncryptionRejectsServerPrivateKeyReuse(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	conf.EncryptionPublicKey = crypto.PublicKeys(strings.TrimSpace(string(crypto.MarshalPublicKey(identity.PublicKey()))))
	recorder, err := NewRecorder(&conf, identity)
	require.Nil(t, recorder)
	require.ErrorContains(t, err, "reuses a private key")

	_, otherIdentity := newJournalTestIdentity(t)
	require.ErrorContains(t,
		ValidateEncryptionRecipientDedicatedFromAuditIdentities(conf.EncryptionPublicKey, []*Identity{otherIdentity, identity}),
		"reuses an audit signing identity",
	)
}

func TestAuditEncryptionCannotBeEnabledForPlaintextHistory(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.plain"}))
	require.NoError(t, recorder.Close())
	_, publicKey := newJournalTestEncryptionKey(t)
	conf.EncryptionPublicKey = publicKey

	recorder, err = NewRecorder(&conf, identity)
	require.Nil(t, recorder)
	require.ErrorContains(t, err, "does not match configured recipient")
}

func TestVerifyJournalsRejectsUnexpectedProducer(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.record"}))
	require.NoError(t, recorder.Close())

	expected := identity.ProducerId()
	expected[0] ^= 1
	verification, err := VerifyJournals(context.Background(), []JournalSource{{
		Name:               "default",
		Directory:          conf.Journal.Directory,
		ExpectedProducerId: expected,
	}})
	require.Nil(t, verification)
	require.ErrorContains(t, err, "instead of expected producer")
}

func TestVerifyJournalsRejectsIncompleteTailWithoutTruncating(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.active"}))
	crashCloseJournalTestRecorder(t, recorder)
	activePath := journalTestActivePath(conf, identity)
	file, err := os.OpenFile(activePath, os.O_WRONLY|os.O_APPEND, journalFileMode)
	require.NoError(t, err)
	_, err = file.Write([]byte{0, 0, 1})
	require.NoError(t, err)
	require.NoError(t, file.Close())
	before, err := os.ReadFile(activePath)
	require.NoError(t, err)

	verification, err := VerifyJournals(context.Background(), []JournalSource{{Name: "default", Directory: conf.Journal.Directory}})
	require.Nil(t, verification)
	require.ErrorContains(t, err, "incomplete frame")
	after, readErr := os.ReadFile(activePath)
	require.NoError(t, readErr)
	require.Equal(t, before, after)
}

func TestVerifyJournalsRequiresHeadAtChainTip(t *testing.T) {
	conf, identity := newJournalTestIdentity(t)
	recorder, err := NewRecorder(&conf, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(context.Background(), Event{Name: "test.active"}))
	crashCloseJournalTestRecorder(t, recorder)
	require.NoError(t, writeJournalHead(producerJournalTestDirectory(conf, identity), identity, journalHash{}))

	verification, err := VerifyJournals(context.Background(), []JournalSource{{Name: "default", Directory: conf.Journal.Directory}})
	require.Nil(t, verification)
	require.ErrorContains(t, err, "does not end at its signed journal head")
}

func TestVerificationExportsDeterministicJSONLines(t *testing.T) {
	earlier := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	later := earlier.Add(time.Second)
	firstId := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	secondId := uuid.MustParse("00000000-0000-4000-8000-000000000002")
	verification := Verification{records: []VerifiedRecord{
		{Auditlog: "z", RecordedAt: later, Id: secondId, Event: Event{Name: "later"}},
		{Auditlog: "a", RecordedAt: earlier, Id: firstId, Event: Event{Name: "earlier"}},
	}}

	var output bytes.Buffer
	require.NoError(t, verification.ExportJSONLines(&output, RecordOrderChronological))
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, 2)
	var first, second VerifiedRecord
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &first))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &second))
	require.Equal(t, "earlier", first.Event.Name)
	require.Equal(t, "later", second.Event.Name)

	output.Reset()
	require.NoError(t, verification.ExportJSONLines(&output, RecordOrderChain))
	require.Contains(t, strings.Split(output.String(), "\n")[0], `"name":"later"`)
}

type journalTestSnapshot struct {
	Mode os.FileMode
	Data string
}

func snapshotJournalTestTree(t *testing.T, root string) map[string]journalTestSnapshot {
	t.Helper()
	result := make(map[string]journalTestSnapshot)
	require.NoError(t, filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		snapshot := journalTestSnapshot{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			snapshot.Data = string(raw)
		}
		result[relative] = snapshot
		return nil
	}))
	return result
}

func newJournalTestEncryptionKey(t *testing.T) (crypto.PrivateKey, crypto.PublicKeys) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := crypto.PrivateKeyFromSdk(private)
	require.NoError(t, err)
	public := strings.TrimSpace(string(crypto.MarshalPublicKey(key.PublicKey())))
	return key, crypto.PublicKeys(public)
}

func writeVerifierTestSegments(t *testing.T, directory string, identity *Identity, count uint64) journalHash {
	t.Helper()
	var previousSegmentHash journalHash
	var previousRecordHash journalHash
	createdAt := time.Now().UTC()
	for sequence := uint64(1); sequence <= count; sequence++ {
		_, headerPayload, err := newJournalSegmentHeader(identity, sequence, previousSegmentHash, previousRecordHash, createdAt)
		require.NoError(t, err)
		headerFrame, err := encodeJournalFrame(headerPayload)
		require.NoError(t, err)
		id, err := uuid.NewRandom()
		require.NoError(t, err)
		_, recordPayload, recordHash, err := newJournalRecord(identity, previousRecordHash, Event{Name: "test.long-lived"}, id, createdAt)
		require.NoError(t, err)
		recordFrame, err := encodeJournalFrame(recordPayload)
		require.NoError(t, err)
		content := append(append([]byte(nil), headerFrame...), recordFrame...)
		contentHash := hashJournalBytes(journalSegmentContentHashDomain, content)
		_, sealPayload, err := newJournalSegmentSeal(identity, sequence, 1, uint64(len(content)), contentHash, recordHash, createdAt)
		require.NoError(t, err)
		sealFrame, err := encodeJournalFrame(sealPayload)
		require.NoError(t, err)
		segment := append(content, sealFrame...)
		segmentHash := hashJournalBytes(journalSegmentHashDomain, segment)
		path := filepath.Join(directory, sealedJournalFileName(sequence, segmentHash))
		require.NoError(t, os.WriteFile(path, segment, 0400))
		previousSegmentHash = segmentHash
		previousRecordHash = recordHash
	}
	return previousRecordHash
}
