package recording

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

var generateNativeRecordingVectors = flag.Bool("generate-native-recording-vectors", false, "write deterministic native recording vectors and manifest")
var generateNativeRecordingAgeVector = flag.Bool("generate-native-recording-age-vector", false, "also replace the randomized native age decoder snapshot")

const nativeRecordingVectorSchema = "bifroest.native-recording-format-vectors/v1"

var nativeRecordingAgeUnitNames = [...]string{"becast-header.unit", "becast-continuation.unit", "becast-final.unit", "becast-seal.unit"}

func newBECastTestEncryption(t *testing.T) (*bfcrypto.AgeSshRecipient, *bfcrypto.AgeSshIdentities) {
	t.Helper()
	return newBECastTestEncryptionWithByte(t, recordingFormatVectorBECastRecipientSeedByte)
}

func newBECastTestEncryptionWithByte(t *testing.T, value byte) (*bfcrypto.AgeSshRecipient, *bfcrypto.AgeSshIdentities) {
	t.Helper()
	seed := bytes.Repeat([]byte{value}, ed25519.SeedSize)
	privateKey, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(privateKey.PublicKey().ToSsh())
	require.NoError(t, err)
	identities, err := bfcrypto.NewAgeSshIdentities([]bfcrypto.PrivateKey{privateKey})
	require.NoError(t, err)
	return recipient, identities
}

type nativeRecordingVectorManifest struct {
	Schema                 string                          `json:"schema"`
	SigningSeedHex         string                          `json:"signingSeedHex"`
	BECastRecipientSeedHex string                          `json:"becastRecipientSeedHex"`
	Artifacts              []recordingFormatVectorArtifact `json:"artifacts"`
}

var nativeRecordingVectorArtifacts = []recordingFormatVectorArtifact{
	{Path: "bcast-v1.bcast", Format: "bcast/v1", Description: "Deterministic signed clear native CBOR recording", Reproducible: true},
	{Path: "bcast-v1.cast", Format: "asciicast/v3", Description: "Signed Cast exported from the clear native recording", Reproducible: true},
	{Path: "bcast-head.cbor", Format: "bcast/v1-head", Description: "Deterministic signed clear checkpoint", Reproducible: true},
	{Path: "bcast-header.unit", Format: "bcast/v1-header-unit", Description: "Complete signed clear header frame", Reproducible: true},
	{Path: "bcast-continuation.unit", Format: "bcast/v1-continuation-unit", Description: "Complete signed clear continuation frame", Reproducible: true},
	{Path: "bcast-final.unit", Format: "bcast/v1-final-unit", Description: "Complete signed clear final chunk frame", Reproducible: true},
	{Path: "bcast-seal.unit", Format: "bcast/v1-seal-unit", Description: "Complete signed clear seal frame", Reproducible: true},
	{Path: "becast-v1.becast", Format: "becast-cbor/v1", Description: "Frozen signed age-encrypted native CBOR decoder vector", Reproducible: false},
	{Path: "becast-v1.cast", Format: "asciicast/v3", Description: "Signed Cast exported from the frozen native age recording", Reproducible: true},
	{Path: "becast-head.cbor", Format: "becast-cbor/v1-head", Description: "Frozen signed age recording checkpoint", Reproducible: false},
	{Path: "becast-header.unit", Format: "becast-cbor/v1-header-unit", Description: "Complete signed deterministic age header frame", Reproducible: true},
	{Path: "becast-continuation.unit", Format: "becast-cbor/v1-continuation-unit", Description: "Complete signed frozen age continuation frame", Reproducible: false},
	{Path: "becast-final.unit", Format: "becast-cbor/v1-final-unit", Description: "Complete signed frozen age final chunk frame", Reproducible: false},
	{Path: "becast-seal.unit", Format: "becast-cbor/v1-seal-unit", Description: "Complete signed frozen age seal frame", Reproducible: false},
}

func nativeRecordingVectorDirectory() string {
	return filepath.Join("..", "..", "docs", "assets", "recording-format-vectors", "native-v1")
}

func nativeRecordingVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(nativeRecordingVectorDirectory(), name))
	require.NoError(t, err)
	return data
}

type nativeRecordingVectorFixture struct {
	container []byte
	head      []byte
	cast      []byte
	frames    [][]byte
	groups    [][]byte
}

func buildNativeRecordingVector(t *testing.T, recipient *bfcrypto.AgeSshRecipient, identities *bfcrypto.AgeSshIdentities) nativeRecordingVectorFixture {
	t.Helper()
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewNativeRecordingWriter(&output, identity, recipient, header, metadata, 0, NativeRecordingWriterLimits{})
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(248*time.Millisecond, OutputStreamTerminal, []byte{'W', 'e', 'l', 'c', 'o', 'm', 'e', '\r', '\n', 0xff}))
	require.NoError(t, writer.WriteResize(1001*time.Millisecond, 132, 43))
	require.NoError(t, writer.WriteMarker(1020*time.Millisecond, "ready"))
	head, err := writer.Checkpoint()
	require.NoError(t, err)
	exit := uint32(7)
	result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2104 * time.Millisecond)}
	summary, err := writer.Seal(2104*time.Millisecond, result, &exit)
	require.NoError(t, err)
	require.Equal(t, uint64(2), summary.ChunkCount)
	container := bytes.Clone(output.Bytes())
	options := NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()}
	var cast bytes.Buffer
	_, err = ExportNativeRecordingCast(bytes.NewReader(container), int64(len(container)), identities, &cast, options)
	require.NoError(t, err)
	frames, groups := inspectNativeRecordingVector(t, container, head, identities, options, recipient != nil)
	return nativeRecordingVectorFixture{container, head, bytes.Clone(cast.Bytes()), frames, groups}
}

func inspectNativeRecordingVector(t *testing.T, container, headPayload []byte, identities *bfcrypto.AgeSshIdentities, options NativeRecordingVerifyOptions, encrypted bool) ([][]byte, [][]byte) {
	t.Helper()
	require.True(t, bytes.HasPrefix(container, []byte(nativeformat.RecordingMagic)))
	reader := bytes.NewReader(container)
	offset := int64(len(nativeformat.RecordingMagic))
	var frames, groups [][]byte
	var headerPayload []byte
	var checkpointEnd int64
	for index, kind := range []nativeformat.UnitType{nativeformat.HeaderUnit, nativeformat.ContentUnit, nativeformat.ContentUnit, nativeformat.SealUnit} {
		maximum := nativeformat.MaxMetadataPayload
		if kind == nativeformat.ContentUnit {
			maximum = nativeformat.MaxRecordingChunkPayload
		}
		unit, next, tail, err := nativeformat.ReadUnitAt(reader, offset, int64(len(container)), maximum)
		require.NoError(t, err)
		require.False(t, tail)
		require.Equal(t, kind, unit.Type)
		frame := bytes.Clone(container[offset:next])
		require.Equal(t, byte(kind), frame[0])
		encoded, err := nativeformat.EncodeUnit(kind, unit.Payload, maximum)
		require.NoError(t, err)
		require.Equal(t, frame, encoded)
		frames = append(frames, frame)
		switch index {
		case 0:
			headerPayload = unit.Payload
			h, err := nativeformat.Unmarshal[nativeRecordingHeader](unit.Payload, maximum)
			require.NoError(t, err)
			if encrypted {
				require.Equal(t, uint8(1), h.Encryption)
				require.NotEmpty(t, h.Recipient)
			} else {
				require.Zero(t, h.Encryption)
				require.Empty(t, h.Recipient)
			}
		case 1, 2:
			chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, maximum)
			require.NoError(t, err)
			require.Equal(t, uint64(index), chunk.Sequence)
			if index == 1 {
				require.NotZero(t, chunk.CastHashBytes)
				checkpointEnd = next
			} else {
				require.Zero(t, chunk.CastHashBytes)
				require.Equal(t, uint8(1), chunk.FinalStatus)
			}
			decoded, err := nativeformat.DecodeStoredPayload(chunk.StoredPayload, identities, optionsRecipient(t, headerPayload), nativeRecordingPayloadLimits)
			require.NoError(t, err)
			require.Equal(t, int(chunk.DecodedLength), len(decoded))
			events, err := decodeNativeRecordingEvents(decoded)
			require.NoError(t, err)
			if index == 1 {
				require.Equal(t, []uint8{NativeEventSetup, NativeEventOutput, NativeEventResize, NativeEventMarker, NativeEventPaddingCheckpoint}, nativeVectorKinds(events))
				require.Equal(t, []byte{'W', 'e', 'l', 'c', 'o', 'm', 'e', '\r', '\n', 0xff}, events[1].Data)
				require.Equal(t, 248*time.Millisecond, events[1].Elapsed)
				require.Equal(t, 1001*time.Millisecond, events[2].Elapsed)
				require.Equal(t, 1020*time.Millisecond, events[3].Elapsed)
			} else {
				require.Equal(t, []uint8{NativeEventResult}, nativeVectorKinds(events))
				require.Equal(t, 2104*time.Millisecond, events[0].Elapsed)
				require.Equal(t, uint32(7), *events[0].ExitStatus)
			}
			canonical, err := EncodeNativeRecordingEvents(events)
			require.NoError(t, err)
			require.Equal(t, decoded, canonical)
			groups = append(groups, decoded)
		case 3:
			_, err := nativeformat.Unmarshal[nativeRecordingSeal](unit.Payload, maximum)
			require.NoError(t, err)
		}
		offset = next
	}
	require.Equal(t, int64(len(container)), offset)
	head, err := VerifyNativeRecordingHead(headPayload, headerPayload)
	require.NoError(t, err)
	canonicalHead, err := nativeformat.Marshal(head, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, headPayload, canonicalHead)
	require.Equal(t, uint64(checkpointEnd), head.PrefixBytes)
	require.Equal(t, uint64(1), head.ChunkCount)
	require.NoError(t, VerifyNativeRecordingCheckpoint(reader, int64(len(container)), headPayload, nativeVectorIdentity(t), options))
	return frames, groups
}

func nativeVectorKinds(events []NativeCastEvent) []uint8 {
	kinds := make([]uint8, len(events))
	for i, event := range events {
		kinds[i] = event.Kind
	}
	return kinds
}

func optionsRecipient(t *testing.T, payload []byte) string {
	t.Helper()
	header, err := nativeformat.Unmarshal[nativeRecordingHeader](payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	return header.Recipient
}

func nativeVectorIdentity(t *testing.T) *audit.Identity {
	t.Helper()
	identity, _, _ := castTestValues(t, true)
	return identity
}

func TestNativeRecordingFormatVectors(t *testing.T) {
	if *generateNativeRecordingAgeVector && !*generateNativeRecordingVectors {
		t.Fatal("-generate-native-recording-age-vector requires -generate-native-recording-vectors")
	}
	recipient, identities := newBECastTestEncryption(t)
	clear := buildNativeRecordingVector(t, nil, nil)
	freshAge := buildNativeRecordingVector(t, recipient, identities)
	require.Equal(t, clear.groups, freshAge.groups)
	require.Equal(t, clear.cast, freshAge.cast)
	if *generateNativeRecordingVectors {
		if !*generateNativeRecordingAgeVector {
			verifyNativeRecordingVectorManifest(t)
			frozen := nativeRecordingVector(t, "becast-v1.becast")
			frozenHead := nativeRecordingVector(t, "becast-head.cbor")
			options := NativeRecordingVerifyOptions{ExpectedProducerId: nativeVectorIdentity(t).ProducerId()}
			frames, groups := inspectNativeRecordingVector(t, frozen, frozenHead, identities, options, true)
			require.Equal(t, freshAge.frames[0], frames[0], "frozen age header must match before writing clear fixtures")
			require.Equal(t, clear.groups, groups)
			var cast bytes.Buffer
			_, err := ExportNativeRecordingCast(bytes.NewReader(frozen), int64(len(frozen)), identities, &cast, options)
			require.NoError(t, err)
			require.Equal(t, nativeRecordingVector(t, "becast-v1.cast"), cast.Bytes())
			require.Equal(t, clear.cast, cast.Bytes())
		}
		writeNativeRecordingVectors(t, clear, freshAge, identities)
	}
	require.Equal(t, nativeRecordingVector(t, "bcast-v1.bcast"), clear.container)
	require.Equal(t, nativeRecordingVector(t, "bcast-v1.cast"), clear.cast)
	require.Equal(t, nativeRecordingVector(t, "bcast-head.cbor"), clear.head)
	for i, name := range []string{"bcast-header.unit", "bcast-continuation.unit", "bcast-final.unit", "bcast-seal.unit"} {
		require.Equal(t, nativeRecordingVector(t, name), clear.frames[i], name)
	}

	encrypted := nativeRecordingVector(t, "becast-v1.becast")
	encryptedHead := nativeRecordingVector(t, "becast-head.cbor")
	options := NativeRecordingVerifyOptions{ExpectedProducerId: nativeVectorIdentity(t).ProducerId()}
	outer, err := VerifyNativeRecordingOuter(bytes.NewReader(encrypted), int64(len(encrypted)), options)
	require.NoError(t, err)
	require.True(t, outer.Trusted)
	require.Equal(t, recipient.Fingerprint(), outer.Header.Recipient)
	frozenFrames, frozenGroups := inspectNativeRecordingVector(t, encrypted, encryptedHead, identities, options, true)
	for i, name := range nativeRecordingAgeUnitNames {
		require.Equal(t, frozenFrames[i], nativeRecordingVector(t, name), name)
	}
	require.Equal(t, frozenFrames[0], freshAge.frames[0], "age header must be deterministic before declaring its vector reproducible")
	require.Equal(t, clear.groups, frozenGroups)
	_, err = VerifyNativeRecordingFull(bytes.NewReader(encrypted), int64(len(encrypted)), identities, options)
	require.NoError(t, err)
	var exported bytes.Buffer
	_, err = ExportNativeRecordingCast(bytes.NewReader(encrypted), int64(len(encrypted)), identities, &exported, options)
	require.NoError(t, err)
	require.Equal(t, nativeRecordingVector(t, "becast-v1.cast"), exported.Bytes())
	require.Equal(t, clear.cast, exported.Bytes())
	for _, missing := range []*bfcrypto.AgeSshIdentities{nil, nativeVectorWrongIdentity(t)} {
		_, err = VerifyNativeRecordingFull(bytes.NewReader(encrypted), int64(len(encrypted)), missing, options)
		require.Error(t, err)
		var denied bytes.Buffer
		_, err = ExportNativeRecordingCast(bytes.NewReader(encrypted), int64(len(encrypted)), missing, &denied, options)
		require.Error(t, err)
		require.Zero(t, denied.Len())
	}

	require.Equal(t, exported.Bytes(), freshAge.cast)
	verifyNativeRecordingVectorManifest(t)
}

func nativeVectorWrongIdentity(t *testing.T) *bfcrypto.AgeSshIdentities {
	t.Helper()
	_, identities := newBECastTestEncryptionWithByte(t, 0x97)
	return identities
}

func writeNativeRecordingVectors(t *testing.T, clear, freshAge nativeRecordingVectorFixture, identities *bfcrypto.AgeSshIdentities) {
	t.Helper()
	directory := nativeRecordingVectorDirectory()
	require.NoError(t, os.MkdirAll(directory, 0755))
	files := map[string][]byte{
		"bcast-v1.bcast": clear.container, "bcast-v1.cast": clear.cast, "bcast-head.cbor": clear.head,
		"bcast-header.unit": clear.frames[0], "bcast-continuation.unit": clear.frames[1],
		"bcast-final.unit": clear.frames[2], "bcast-seal.unit": clear.frames[3],
	}
	if *generateNativeRecordingAgeVector {
		files["becast-v1.becast"], files["becast-head.cbor"], files["becast-v1.cast"] = freshAge.container, freshAge.head, freshAge.cast
		for i, name := range nativeRecordingAgeUnitNames {
			files[name] = freshAge.frames[i]
		}
	}
	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), data, 0644))
	}
	if !*generateNativeRecordingAgeVector {
		frozen := nativeRecordingVector(t, "becast-v1.becast")
		frames, _ := inspectNativeRecordingVector(t, frozen, nativeRecordingVector(t, "becast-head.cbor"), identities,
			NativeRecordingVerifyOptions{ExpectedProducerId: nativeVectorIdentity(t).ProducerId()}, true)
		require.Equal(t, freshAge.frames[0], frames[0], "age header must be deterministic")
		for i, name := range nativeRecordingAgeUnitNames {
			path := filepath.Join(directory, name)
			published, err := os.ReadFile(path)
			if err == nil {
				require.Equal(t, frames[i], published, name)
				continue
			}
			require.ErrorIs(t, err, os.ErrNotExist)
			require.NoError(t, os.WriteFile(path, frames[i], 0644))
		}
	}
	manifest := nativeRecordingVectorManifest{
		Schema: nativeRecordingVectorSchema, SigningSeedHex: recordingFormatVectorSigningSeedHex,
		BECastRecipientSeedHex: hex.EncodeToString(bytes.Repeat([]byte{recordingFormatVectorBECastRecipientSeedByte}, 32)),
	}
	for _, spec := range nativeRecordingVectorArtifacts {
		data := nativeRecordingVector(t, spec.Path)
		digest := sha256.Sum256(data)
		spec.Bytes, spec.SHA256 = len(data), hex.EncodeToString(digest[:])
		manifest.Artifacts = append(manifest.Artifacts, spec)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "manifest.json"), append(encoded, '\n'), 0644))
}

func verifyNativeRecordingVectorManifest(t *testing.T) {
	t.Helper()
	data := nativeRecordingVector(t, "manifest.json")
	require.NoError(t, rejectDuplicateJSONFields(data))
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest nativeRecordingVectorManifest
	require.NoError(t, decoder.Decode(&manifest))
	require.ErrorIs(t, decoder.Decode(&struct{}{}), io.EOF)
	require.Equal(t, nativeRecordingVectorSchema, manifest.Schema)
	require.Equal(t, recordingFormatVectorSigningSeedHex, manifest.SigningSeedHex)
	require.Equal(t, hex.EncodeToString(bytes.Repeat([]byte{recordingFormatVectorBECastRecipientSeedByte}, 32)), manifest.BECastRecipientSeedHex)
	require.Len(t, manifest.Artifacts, len(nativeRecordingVectorArtifacts))
	for i, spec := range nativeRecordingVectorArtifacts {
		artifact := manifest.Artifacts[i]
		require.Equal(t, spec.Path, artifact.Path)
		require.Equal(t, spec.Format, artifact.Format)
		require.Equal(t, spec.Description, artifact.Description)
		require.Equal(t, spec.Reproducible, artifact.Reproducible)
		content := nativeRecordingVector(t, artifact.Path)
		digest := sha256.Sum256(content)
		require.Equal(t, len(content), artifact.Bytes, artifact.Path)
		require.Equal(t, hex.EncodeToString(digest[:]), artifact.SHA256, artifact.Path)
	}
	entries, err := os.ReadDir(nativeRecordingVectorDirectory())
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		require.Zero(t, entry.Type()&os.ModeSymlink, entry.Name())
		info, err := entry.Info()
		require.NoError(t, err)
		require.True(t, info.Mode().IsRegular(), entry.Name())
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	expected := []string{"manifest.json"}
	for _, spec := range nativeRecordingVectorArtifacts {
		expected = append(expected, spec.Path)
	}
	sort.Strings(expected)
	require.Equal(t, expected, names)
}
