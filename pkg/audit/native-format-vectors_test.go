package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

var (
	generateNativeAuditVectors   = flag.Bool("audit-generate-vectors", false, "regenerate clear audit vectors and excerpts of the existing frozen age vector")
	generateNativeAuditAgeVector = flag.Bool("audit-generate-age-vector", false, "with -audit-generate-vectors, explicitly replace randomized age ciphertext, head and exports")
)

const (
	auditVectorDirectory = "../../docs/assets/audit-format-vectors/v1"
	// PUBLIC TEST SEEDS. Never use these keys for production data.
	auditVectorSigningSeed   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	auditVectorRecipientSeed = "4242424242424242424242424242424242424242424242424242424242424242"
)

type auditVectorArtifact struct {
	Path         string `json:"path"`
	Format       string `json:"format"`
	Description  string `json:"description"`
	Bytes        int    `json:"bytes"`
	SHA256       string `json:"sha256"`
	Reproducible bool   `json:"reproducible"`
}

type auditVectorHashes struct {
	RecordHashes []string `json:"recordHashes"`
	ContentHash  string   `json:"contentHash"`
	SegmentHash  string   `json:"segmentHash"`
}

type auditVectorManifest struct {
	Schema               string                `json:"schema"`
	SigningSeedHex       string                `json:"signingSeedHex"`
	AgeRecipientSeedHex  string                `json:"ageRecipientSeedHex"`
	ProducerId           string                `json:"producerId"`
	RecipientFingerprint string                `json:"recipientFingerprint"`
	Clear                auditVectorHashes     `json:"clear"`
	Encrypted            auditVectorHashes     `json:"encrypted"`
	Artifacts            []auditVectorArtifact `json:"artifacts"`
}

type auditVectorSet struct {
	segment, head         []byte
	header, records, seal []byte
	hashes                auditVectorHashes
}

func auditVectorKey(t *testing.T, seedHex string) bfcrypto.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	require.NoError(t, err)
	require.Len(t, seed, ed25519.SeedSize)
	key, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	return key
}

func auditVectorInputs() ([]Event, []uuid.UUID, []time.Time) {
	return []Event{
		{Name: "custom.authentication", Domain: EventDomainAuthentication, Outcome: EventOutcomeSuccess,
			Flow: "fixture-flow", ConnectionId: "34e34ab8-7457-4d88-a5e4-c57791775c3a",
			AuthenticationMethod: AuthenticationMethodPublicKey, AuthenticationPhase: AuthenticationPhaseVerified},
		{Name: "custom.session", Domain: EventDomainSession, Outcome: EventOutcomeDenied,
			Flow: "fixture-flow", SessionId: "82d8fdda-4730-43b7-bfde-72733c217bde",
			Reason: EventReasonAuthorizedKeyPolicy, SessionTask: SessionTaskExec},
	}, []uuid.UUID{
		uuid.MustParse("34e34ab8-7457-4d88-a5e4-c57791775c3a"),
		uuid.MustParse("6d05798f-b877-4191-8aa0-4576a30411ad"),
	}, []time.Time{
		time.Date(2026, 9, 13, 12, 34, 56, 123456789, time.UTC),
		time.Date(2026, 9, 13, 12, 35, 1, 987654321, time.UTC),
	}
}

func makeAuditVector(t *testing.T, identity *Identity, recipient *bfcrypto.AgeSshRecipient, fingerprint string) auditVectorSet {
	t.Helper()
	created := time.Date(2026, 9, 13, 12, 34, 50, 0, time.UTC)
	_, headerPayload, err := newNativeAuditHeader(identity, 1, journalHash{}, journalHash{}, created, fingerprint)
	require.NoError(t, err)
	header, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, headerPayload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	result := auditVectorSet{header: header, segment: append([]byte(nativeformat.AuditMagic), header...)}
	events, ids, times := auditVectorInputs()
	var previous journalHash
	for i, event := range events {
		_, payload, hash, err := newNativeAuditRecord(identity, previous, event, ids[i], times[i], recipient)
		require.NoError(t, err)
		unit, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		result.segment = append(result.segment, unit...)
		result.records = append(result.records, unit...)
		result.hashes.RecordHashes = append(result.hashes.RecordHashes, hash.String())
		previous = hash
	}
	result.hashes.ContentHash = hashNativeAuditContent(result.segment).String()
	_, sealPayload, err := newNativeAuditSeal(identity, 1, uint64(len(events)), uint64(len(result.segment)), hashNativeAuditContent(result.segment), previous, times[len(times)-1].Add(time.Second))
	require.NoError(t, err)
	result.seal, err = nativeformat.EncodeUnit(nativeformat.SealUnit, sealPayload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	result.segment = append(result.segment, result.seal...)
	result.hashes.SegmentHash = hashNativeAuditSegment(result.segment).String()
	_, result.head, err = newNativeAuditHead(identity, previous)
	require.NoError(t, err)
	return result
}

func readAuditVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(auditVectorDirectory, name))
	require.NoError(t, err)
	return data
}

func checkFrozenAuditAssets(t *testing.T, identity *Identity, fingerprint string) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(readAuditVector(t, "manifest.json")))
	decoder.DisallowUnknownFields()
	var manifest auditVectorManifest
	require.NoError(t, decoder.Decode(&manifest))
	require.ErrorIs(t, decoder.Decode(new(any)), io.EOF)
	require.Equal(t, "bifroest.audit-format-vectors/v1", manifest.Schema)
	require.Equal(t, auditVectorSigningSeed, manifest.SigningSeedHex)
	require.Equal(t, auditVectorRecipientSeed, manifest.AgeRecipientSeedHex)
	require.Equal(t, identity.ProducerId().String(), manifest.ProducerId)
	require.Equal(t, fingerprint, manifest.RecipientFingerprint)
	protected := map[string]bool{
		"beaudit-v1.beaudit": true, "beaudit-v1-head.cbor": true,
		"beaudit-v1-redacted.jsonl": true, "beaudit-v1-with-sensitive.jsonl": true,
	}
	for _, artifact := range manifest.Artifacts {
		if !protected[artifact.Path] {
			continue
		}
		data := readAuditVector(t, artifact.Path)
		digest := sha256.Sum256(data)
		require.Equal(t, len(data), artifact.Bytes, artifact.Path)
		require.Equal(t, hex.EncodeToString(digest[:]), artifact.SHA256, artifact.Path)
		require.False(t, artifact.Reproducible, artifact.Path)
		delete(protected, artifact.Path)
	}
	require.Empty(t, protected, "missing frozen age assets in the old manifest")
}

func checkAuditVectorAgeHeader(t *testing.T, identity *Identity, fingerprint string, vector auditVectorSet) {
	t.Helper()
	unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(vector.header), 0, int64(len(vector.header)), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.False(t, tail)
	require.EqualValues(t, len(vector.header), next)
	require.Equal(t, nativeformat.HeaderUnit, unit.Type)
	header, err := nativeformat.Unmarshal[nativeAuditHeader](unit.Payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.EqualValues(t, 1, header.Encryption)
	require.Equal(t, fingerprint, header.Recipient)
	_, err = decodeNativeAuditHeader(unit.Payload, identity, 1, journalHash{}, journalHash{}, fingerprint)
	require.NoError(t, err)
	_, payload, err := newNativeAuditHeader(identity, 1, journalHash{}, journalHash{}, time.Date(2026, 9, 13, 12, 34, 50, 0, time.UTC), fingerprint)
	require.NoError(t, err)
	regenerated, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, regenerated, vector.header, "age header must be deterministic without regenerating ciphertext")
}

// Extract exact framed units from the frozen file; never re-encrypt in an ordinary test.
func frozenAuditVector(t *testing.T, encrypted bool) auditVectorSet {
	t.Helper()
	prefix := "baudit-v1"
	if encrypted {
		prefix = "beaudit-v1"
	}
	data := readAuditVector(t, prefix+map[bool]string{false: ".baudit", true: ".beaudit"}[encrypted])
	require.True(t, bytes.HasPrefix(data, []byte(nativeformat.AuditMagic)))
	result := auditVectorSet{segment: data, head: readAuditVector(t, prefix+"-head.cbor")}
	offset := int64(len(nativeformat.AuditMagic))
	for i := 0; i < 4; i++ {
		unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(data), offset, int64(len(data)), nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		require.False(t, tail)
		frame := data[offset:next]
		switch i {
		case 0:
			require.Equal(t, nativeformat.HeaderUnit, unit.Type)
			result.header = frame
		case 1, 2:
			require.Equal(t, nativeformat.ContentUnit, unit.Type)
			result.records = append(result.records, frame...)
			result.hashes.RecordHashes = append(result.hashes.RecordHashes, hashJournalBytes(nativeAuditRecordHashDomain, unit.Payload).String())
		case 3:
			require.Equal(t, nativeformat.SealUnit, unit.Type)
			result.seal = frame
			result.hashes.ContentHash = hashNativeAuditContent(data[:offset]).String()
		}
		offset = next
	}
	require.EqualValues(t, len(data), offset)
	result.hashes.SegmentHash = hashNativeAuditSegment(data).String()
	return result
}

func verifyAuditVector(t *testing.T, identity *Identity, key bfcrypto.PrivateKey, fingerprint string, vector auditVectorSet, redacted, full []byte) {
	t.Helper()
	root := t.TempDir()
	producer := filepath.Join(root, identity.ProducerId().String())
	require.NoError(t, os.Mkdir(producer, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(producer, nativeHeadFileName), vector.head, 0600))
	name := nativeSegmentName(1, hashNativeAuditSegment(vector.segment), fingerprint != "")
	require.NoError(t, os.WriteFile(filepath.Join(producer, name), vector.segment, 0600))
	source := JournalSource{Name: "vector", Directory: root, ExpectedProducerId: identity.ProducerId(), ExpectedEncryptionRecipient: fingerprint}
	ctx := context.Background()
	require.NoError(t, VerifyJournalIntegrity(ctx, []JournalSource{source}))
	verified, err := VerifyJournals(ctx, []JournalSource{source})
	require.NoError(t, err)
	require.EqualValues(t, 1, verified.Journals[0].SegmentCount)
	require.EqualValues(t, 2, verified.Journals[0].RecordCount)
	events, ids, times := auditVectorInputs()
	for i, record := range verified.Records() {
		require.Equal(t, ids[i], record.Id)
		require.Equal(t, times[i], record.RecordedAt)
		require.Equal(t, Event{Name: events[i].Name, Domain: events[i].Domain, Outcome: events[i].Outcome}, record.Event)
		require.Equal(t, vector.hashes.RecordHashes[i], record.Hash)
	}
	var output bytes.Buffer
	require.NoError(t, verified.ExportJSONLines(&output, RecordOrderChain))
	require.Equal(t, redacted, output.Bytes())
	if fingerprint != "" {
		source.WithSensitive = true
		require.Error(t, VerifyJournalIntegrity(ctx, []JournalSource{source}))
		_, err = VerifyJournals(ctx, []JournalSource{source})
		require.Error(t, err)
		source.DecryptionIdentities = []bfcrypto.PrivateKey{auditVectorKey(t, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}
		require.Error(t, VerifyJournalIntegrity(ctx, []JournalSource{source}))
		_, err = VerifyJournals(ctx, []JournalSource{source})
		require.Error(t, err)
		source.DecryptionIdentities = []bfcrypto.PrivateKey{key}
	}
	source.WithSensitive = true
	require.NoError(t, VerifyJournalIntegrity(ctx, []JournalSource{source}))
	verified, err = VerifyJournals(ctx, []JournalSource{source})
	require.NoError(t, err)
	for i, record := range verified.Records() {
		require.Equal(t, events[i], record.Event)
	}
	output.Reset()
	require.NoError(t, verified.ExportJSONLines(&output, RecordOrderChain))
	require.Equal(t, full, output.Bytes())
}

func auditVectorFiles(clear, encrypted auditVectorSet, clearRedacted, clearFull, encryptedRedacted, encryptedFull []byte) []struct {
	auditVectorArtifact
	data []byte
} {
	files := []struct {
		auditVectorArtifact
		data []byte
	}{}
	add := func(path, format, description string, reproducible bool, data []byte) {
		digest := sha256.Sum256(data)
		files = append(files, struct {
			auditVectorArtifact
			data []byte
		}{auditVectorArtifact{path, format, description, len(data), hex.EncodeToString(digest[:]), reproducible}, data})
	}
	add("baudit-v1.baudit", "baudit/v1", "Complete deterministic signed clear audit segment", true, clear.segment)
	add("baudit-v1-head.cbor", "baudit/v1-head", "Signed clear journal checkpoint (raw CBOR)", true, clear.head)
	add("baudit-header.unit", "baudit/v1-header-unit", "Framed signed clear header excerpt", true, clear.header)
	add("baudit-records.unit", "baudit/v1-record-units", "Two consecutive framed signed clear record excerpts", true, clear.records)
	add("baudit-seal.unit", "baudit/v1-seal-unit", "Framed signed clear seal excerpt", true, clear.seal)
	add("baudit-v1-redacted.jsonl", "audit-jsonl/v1", "Verified clear export without sensitive fields", true, clearRedacted)
	add("baudit-v1-with-sensitive.jsonl", "audit-jsonl/v1", "Verified clear export with sensitive fields", true, clearFull)
	add("beaudit-v1.beaudit", "beaudit/v1", "Frozen signed age-encrypted audit segment", false, encrypted.segment)
	add("beaudit-v1-head.cbor", "beaudit/v1-head", "Signed encrypted journal checkpoint (raw CBOR)", false, encrypted.head)
	add("beaudit-header.unit", "beaudit/v1-header-unit", "Framed signed age header excerpt, deterministic with public seed", true, encrypted.header)
	add("beaudit-records.unit", "beaudit/v1-record-units", "Two frozen framed signed age record excerpts", false, encrypted.records)
	add("beaudit-seal.unit", "beaudit/v1-seal-unit", "Frozen framed signed age seal excerpt", false, encrypted.seal)
	add("beaudit-v1-redacted.jsonl", "audit-jsonl/v1", "Verified encrypted outer-only export", false, encryptedRedacted)
	add("beaudit-v1-with-sensitive.jsonl", "audit-jsonl/v1", "Verified decrypted export with sensitive fields", false, encryptedFull)
	return files
}

func auditVectorExport(t *testing.T, identity *Identity, key bfcrypto.PrivateKey, fingerprint string, vector auditVectorSet, sensitive bool) []byte {
	t.Helper()
	root := t.TempDir()
	producer := filepath.Join(root, identity.ProducerId().String())
	require.NoError(t, os.Mkdir(producer, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(producer, nativeHeadFileName), vector.head, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(producer, nativeSegmentName(1, hashNativeAuditSegment(vector.segment), fingerprint != "")), vector.segment, 0600))
	source := JournalSource{Name: "vector", Directory: root, ExpectedProducerId: identity.ProducerId(), ExpectedEncryptionRecipient: fingerprint, WithSensitive: sensitive}
	if sensitive && fingerprint != "" {
		source.DecryptionIdentities = []bfcrypto.PrivateKey{key}
	}
	verification, err := VerifyJournals(context.Background(), []JournalSource{source})
	require.NoError(t, err)
	var output bytes.Buffer
	require.NoError(t, verification.ExportJSONLines(&output, RecordOrderChain))
	return output.Bytes()
}

func TestGenerateNativeAuditFormatVectors(t *testing.T) {
	if *generateNativeAuditAgeVector && !*generateNativeAuditVectors {
		t.Fatal("-audit-generate-age-vector requires -audit-generate-vectors")
	}
	if !*generateNativeAuditVectors {
		t.Skip("requires -args -audit-generate-vectors; never rewrite fixtures in normal tests")
	}
	identity, err := NewIdentity(auditVectorKey(t, auditVectorSigningSeed))
	require.NoError(t, err)
	key := auditVectorKey(t, auditVectorRecipientSeed)
	recipient, err := bfcrypto.NewAgeSshRecipient(key.PublicKey().ToSsh())
	require.NoError(t, err)
	clear := makeAuditVector(t, identity, nil, "")
	var encrypted auditVectorSet
	if *generateNativeAuditAgeVector {
		encrypted = makeAuditVector(t, identity, recipient, recipient.Fingerprint())
	} else {
		checkFrozenAuditAssets(t, identity, recipient.Fingerprint())
		encrypted = frozenAuditVector(t, true)
	}
	checkAuditVectorAgeHeader(t, identity, recipient.Fingerprint(), encrypted)
	clearRedacted := auditVectorExport(t, identity, nil, "", clear, false)
	clearFull := auditVectorExport(t, identity, nil, "", clear, true)
	var encryptedRedacted, encryptedFull []byte
	if *generateNativeAuditAgeVector {
		encryptedRedacted = auditVectorExport(t, identity, key, recipient.Fingerprint(), encrypted, false)
		encryptedFull = auditVectorExport(t, identity, key, recipient.Fingerprint(), encrypted, true)
	} else {
		encryptedRedacted = readAuditVector(t, "beaudit-v1-redacted.jsonl")
		encryptedFull = readAuditVector(t, "beaudit-v1-with-sensitive.jsonl")
		verifyAuditVector(t, identity, key, recipient.Fingerprint(), encrypted, encryptedRedacted, encryptedFull)
	}
	files := auditVectorFiles(clear, encrypted,
		clearRedacted, clearFull, encryptedRedacted, encryptedFull)
	manifest := auditVectorManifest{Schema: "bifroest.audit-format-vectors/v1", SigningSeedHex: auditVectorSigningSeed,
		AgeRecipientSeedHex: auditVectorRecipientSeed, ProducerId: identity.ProducerId().String(), RecipientFingerprint: recipient.Fingerprint(),
		Clear: clear.hashes, Encrypted: encrypted.hashes}
	for _, file := range files {
		manifest.Artifacts = append(manifest.Artifacts, file.auditVectorArtifact)
	}
	// Directory creation and all writes are limited to the explicitly owned asset subtree.
	require.NoError(t, os.MkdirAll(auditVectorDirectory, 0755))
	for _, file := range files {
		if !*generateNativeAuditAgeVector && strings.HasPrefix(file.Path, "beaudit-v1") {
			continue // Never rewrite the four frozen age inputs in clear-only mode.
		}
		require.NoError(t, os.WriteFile(filepath.Join(auditVectorDirectory, file.Path), file.data, 0644))
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(auditVectorDirectory, "manifest.json"), append(encoded, '\n'), 0644))
}

func TestNativeAuditFormatVectorsV1(t *testing.T) {
	identity, err := NewIdentity(auditVectorKey(t, auditVectorSigningSeed))
	require.NoError(t, err)
	key := auditVectorKey(t, auditVectorRecipientSeed)
	recipient, err := bfcrypto.NewAgeSshRecipient(key.PublicKey().ToSsh())
	require.NoError(t, err)
	clear := frozenAuditVector(t, false)
	encrypted := frozenAuditVector(t, true)
	checkAuditVectorAgeHeader(t, identity, recipient.Fingerprint(), encrypted)
	regenerated := makeAuditVector(t, identity, nil, "")
	require.True(t, reflect.DeepEqual(regenerated, clear), "clear vector differs byte-for-byte from production encoder")
	require.Equal(t, clear.header, readAuditVector(t, "baudit-header.unit"))
	require.Equal(t, clear.records, readAuditVector(t, "baudit-records.unit"))
	require.Equal(t, clear.seal, readAuditVector(t, "baudit-seal.unit"))
	require.Equal(t, encrypted.header, readAuditVector(t, "beaudit-header.unit"))
	require.Equal(t, encrypted.records, readAuditVector(t, "beaudit-records.unit"))
	require.Equal(t, encrypted.seal, readAuditVector(t, "beaudit-seal.unit"))
	offset := int64(0)
	var previous journalHash
	for i := 0; i < 2; i++ {
		unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(encrypted.records), offset, int64(len(encrypted.records)), nativeformat.MaxAuditRecordPayload)
		require.NoError(t, err)
		require.False(t, tail)
		require.Equal(t, nativeformat.ContentUnit, unit.Type)
		_, _, previous, err = decodeNativeAuditRecord(unit.Payload, identity, previous, recipient.Fingerprint(), nil, false)
		require.NoError(t, err)
		offset = next
	}
	require.EqualValues(t, len(encrypted.records), offset)
	unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(encrypted.seal), 0, int64(len(encrypted.seal)), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.False(t, tail)
	require.EqualValues(t, len(encrypted.seal), next)
	require.Equal(t, nativeformat.SealUnit, unit.Type)
	_, err = decodeNativeAuditSeal(unit.Payload, identity, 1, 2, uint64(len(nativeformat.AuditMagic)+len(encrypted.header)+len(encrypted.records)), hashNativeAuditContent(encrypted.segment[:len(encrypted.segment)-len(encrypted.seal)]), previous)
	require.NoError(t, err)
	clearRedacted := readAuditVector(t, "baudit-v1-redacted.jsonl")
	clearFull := readAuditVector(t, "baudit-v1-with-sensitive.jsonl")
	encryptedRedacted := readAuditVector(t, "beaudit-v1-redacted.jsonl")
	encryptedFull := readAuditVector(t, "beaudit-v1-with-sensitive.jsonl")
	verifyAuditVector(t, identity, nil, "", clear, clearRedacted, clearFull)
	verifyAuditVector(t, identity, key, recipient.Fingerprint(), encrypted, encryptedRedacted, encryptedFull)
	files := auditVectorFiles(clear, encrypted, clearRedacted, clearFull, encryptedRedacted, encryptedFull)
	expected := auditVectorManifest{Schema: "bifroest.audit-format-vectors/v1", SigningSeedHex: auditVectorSigningSeed,
		AgeRecipientSeedHex: auditVectorRecipientSeed, ProducerId: identity.ProducerId().String(), RecipientFingerprint: recipient.Fingerprint(),
		Clear: clear.hashes, Encrypted: encrypted.hashes}
	for _, file := range files {
		expected.Artifacts = append(expected.Artifacts, file.auditVectorArtifact)
	}
	manifestBytes := readAuditVector(t, "manifest.json")
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var actual auditVectorManifest
	require.NoError(t, decoder.Decode(&actual))
	require.ErrorIs(t, decoder.Decode(new(any)), io.EOF)
	require.Equal(t, expected, actual, "manifest must describe the actual bytes, formats and public test seeds")
	canonical, err := json.MarshalIndent(expected, "", "  ")
	require.NoError(t, err)
	require.Equal(t, append(canonical, '\n'), manifestBytes)
	entries, err := os.ReadDir(auditVectorDirectory)
	require.NoError(t, err)
	want := map[string]bool{"manifest.json": true}
	for _, file := range files {
		want[file.Path] = true
		require.Equal(t, file.data, readAuditVector(t, file.Path), fmt.Sprintf("incorrect fixture %s", file.Path))
	}
	require.Len(t, entries, len(want))
	for _, entry := range entries {
		require.Zero(t, entry.Type()&os.ModeSymlink, entry.Name())
		require.False(t, entry.IsDir())
		info, err := entry.Info()
		require.NoError(t, err)
		require.True(t, info.Mode().IsRegular(), entry.Name())
		require.True(t, want[entry.Name()], "unexpected asset: %s", entry.Name())
	}
}
