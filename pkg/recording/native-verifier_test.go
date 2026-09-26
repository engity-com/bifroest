package recording

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func nativeSignerTest(t *testing.T) (*NativeRecordingSigner, Id, time.Time) {
	t.Helper()
	seed, err := hex.DecodeString(recordingFormatVectorSigningSeedHex)
	require.NoError(t, err)
	key, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	identity, err := audit.NewIdentity(key)
	require.NoError(t, err)
	signer, err := NewNativeRecordingSigner(identity)
	require.NoError(t, err)
	_, _, metadata := castTestValues(t, true)
	return signer, metadata.RecordingId, metadata.StartedAt
}

func nativeCastTest(t *testing.T, signer *NativeRecordingSigner) ([]byte, castSha256Checkpoint) {
	t.Helper()
	_, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastWriter(&output, signer.identity, header, metadata)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(248*time.Millisecond, OutputStreamTerminal, []byte("Welcome")))
	checkpoint, err := padCastForSha256Checkpoint(writer)
	require.NoError(t, err)
	status := uint32(0)
	_, err = writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &status)
	require.NoError(t, err)
	return output.Bytes(), checkpoint
}

func TestNativeRecordingCheckpointReadOnlyRejectsCorruption(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		fixture := newNativeRecoveryFixture(t, encrypted)
		options := NativeRecordingVerifyOptions{ExpectedProducerId: fixture.identity.ProducerId()}
		verify := func(data, head []byte) error {
			return VerifyNativeRecordingCheckpoint(bytes.NewReader(data), int64(len(data)), head, fixture.identity, options)
		}
		require.NoError(t, verify(fixture.container, fixture.head))

		corruptCRC := bytes.Clone(fixture.container)
		corruptCRC[fixture.headEnd-1] ^= 1
		require.Error(t, verify(corruptCRC, fixture.head))

		headerEnd := int64(len(nativeformat.RecordingMagic))
		_, headerEnd, _, err := nativeformat.ReadUnitAt(bytes.NewReader(fixture.container), headerEnd, fixture.headEnd, nativeformat.MaxMetadataPayload)
		require.NoError(t, err)
		unit, _, _, err := nativeformat.ReadUnitAt(bytes.NewReader(fixture.container), headerEnd, fixture.headEnd, nativeformat.MaxRecordingChunkPayload)
		require.NoError(t, err)
		chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
		require.NoError(t, err)
		chunk.Signature[0] ^= 1
		payload, err := nativeformat.Marshal(chunk, nativeformat.MaxRecordingChunkPayload)
		require.NoError(t, err)
		frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxRecordingChunkPayload)
		require.NoError(t, err)
		require.Equal(t, int(fixture.headEnd-headerEnd), len(frame))
		badSignature := bytes.Clone(fixture.container)
		copy(badSignature[headerEnd:fixture.headEnd], frame)
		require.Error(t, verify(badSignature, fixture.head))

		head, err := nativeformat.Unmarshal[NativeRecordingHead](fixture.head, nativeformat.MaxMetadataPayload)
		require.NoError(t, err)
		head.LastUnitHash[0] ^= 1
		signer, err := NewNativeRecordingSigner(fixture.identity)
		require.NoError(t, err)
		wrongHead, err := signer.Head(head)
		require.NoError(t, err)
		require.ErrorContains(t, verify(fixture.container, wrongHead), "exact signed checkpoint")
	}
}

func TestNativeRecordingOuterSignedClearAndHead(t *testing.T) {
	signer, id, started := nativeSignerTest(t)
	header, err := signer.Header(id, started, "")
	require.NoError(t, err)
	headerUnit, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, header, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	decoded, key, err := verifyNativeRecordingHeader(header)
	require.NoError(t, err)
	require.Equal(t, [32]byte(signer.identity.ProducerId()), decoded.ProducerId)
	require.Len(t, key, ed25519.PublicKeySize)
	// A synthetic CBOR map exercises outer signatures only; it is not an event schema.
	inner, err := nativeformat.Marshal(map[uint64]any{1: []any{map[uint64]any{1: uint64(0), 2: []byte("terminal")}}}, nativeformat.MaxRecordingDecodedChunk)
	require.NoError(t, err)
	stored, err := nativeformat.EncodeStoredPayload(inner, nil, nativeformat.PayloadLimits{MaxDecoded: nativeformat.MaxRecordingDecodedChunk, MaxStored: nativeformat.MaxRecordingChunkPayload})
	require.NoError(t, err)
	prefix := append([]byte(nativeformat.RecordingMagic), headerUnit...)
	previous := nativeRecordingHash(nativeRecordingUnitDomain, headerUnit)
	castBytes, checkpoint := nativeCastTest(t, signer)
	lastElapsed := uint64(248 * time.Millisecond)
	chunk := nativeRecordingChunk{Sequence: 1, PreviousUnitHash: previous, DecodedLength: uint32(len(inner)), StoredPayload: stored, StoredHash: sha256.Sum256(stored), CastHashBytes: checkpoint.Bytes, CastHashState: checkpoint.State, LastElapsedNanos: &lastElapsed}
	chunkPayload, err := signer.Chunk(chunk)
	require.NoError(t, err)
	chunkUnit, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, chunkPayload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	prefix = append(prefix, chunkUnit...)
	previous = nativeRecordingHash(nativeRecordingUnitDomain, chunkUnit)
	headPayload, err := signer.Head(NativeRecordingHead{Version: 1, RecordingId: [16]byte(id), ProducerId: [32]byte(signer.identity.ProducerId()), PrefixBytes: uint64(len(prefix)), ChunkCount: 1, LastUnitHash: previous, CastHashState: chunk.CastHashState, CastHashBytes: chunk.CastHashBytes})
	require.NoError(t, err)
	head, err := VerifyNativeRecordingHead(headPayload, header)
	require.NoError(t, err)
	require.Equal(t, previous, head.LastUnitHash)
	brokenHead := bytes.Clone(headPayload)
	brokenHead[len(brokenHead)-1] ^= 1
	_, err = VerifyNativeRecordingHead(brokenHead, header)
	require.Error(t, err)

	cast, err := VerifyCast(bytes.NewReader(castBytes), CastVerifyOptions{ExpectedProducerId: signer.identity.ProducerId()})
	require.NoError(t, err)
	castSignature, err := signer.identity.NewSessionRecordingCastSignature(id.String(), cast.Digest.String())
	require.NoError(t, err)
	finalDigest, finalBytes := [32]byte(cast.Digest), uint64(len(castBytes))
	endedAt := nativeformat.TimestampOf(started.Add(time.Second))
	finalChunk := nativeRecordingChunk{Sequence: 2, PreviousUnitHash: previous, DecodedLength: uint32(len(inner)), StoredPayload: stored, StoredHash: sha256.Sum256(stored), CastHashState: finalDigest, FinalStatus: 1, CastDigest: &finalDigest, CastSignature: castSignature.Signature, CastBytes: &finalBytes, EndedAt: &endedAt}
	finalPayload, err := signer.Chunk(finalChunk)
	require.NoError(t, err)
	finalUnit, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, finalPayload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	prefix = append(prefix, finalUnit...)
	previous = nativeRecordingHash(nativeRecordingUnitDomain, finalUnit)
	seal := nativeRecordingSeal{Status: 1, ChunkCount: 2, LastUnitHash: previous, ContentHash: nativeRecordingHash(nativeRecordingContentDomain, prefix), CastDigest: finalDigest, CastSignature: castSignature.Signature, CastBytes: finalBytes, EndedAt: endedAt}
	sealPayload, err := signer.Seal(seal, id)
	require.NoError(t, err)
	sealUnit, err := nativeformat.EncodeUnit(nativeformat.SealUnit, sealPayload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	container := append(prefix, sealUnit...)
	verify := func(value []byte) error {
		_, err := VerifyNativeRecordingOuter(bytes.NewReader(value), int64(len(value)), NativeRecordingVerifyOptions{ExpectedProducerId: signer.identity.ProducerId()})
		return err
	}
	require.NoError(t, verify(container))
	verification, err := VerifyNativeRecordingOuter(bytes.NewReader(container), int64(len(container)), NativeRecordingVerifyOptions{ExpectedProducerId: signer.identity.ProducerId()})
	require.NoError(t, err)
	require.True(t, verification.Trusted)
	require.Equal(t, [32]byte(cast.Digest), verification.Seal.CastDigest)
	var denied bytes.Buffer
	_, err = ExportNativeRecordingCast(bytes.NewReader(container), int64(len(container)), nil, &denied, NativeRecordingVerifyOptions{ExpectedProducerId: signer.identity.ProducerId()})
	require.Error(t, err, "outer-valid synthetic CBOR events are not a valid Cast")
	require.Zero(t, denied.Len())
	changedStatus := seal
	changedStatus.Status = 3
	changedSeal, err := signer.Seal(changedStatus, id)
	require.NoError(t, err)
	changedUnit, err := nativeformat.EncodeUnit(nativeformat.SealUnit, changedSeal, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.Error(t, verify(append(bytes.Clone(prefix), changedUnit...)), "validly signed seal cannot override final chunk status")
	changedTime := seal
	changedTime.EndedAt = nativeformat.TimestampOf(started.Add(2 * time.Second))
	changedSeal, err = signer.Seal(changedTime, id)
	require.NoError(t, err)
	changedUnit, err = nativeformat.EncodeUnit(nativeformat.SealUnit, changedSeal, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.Error(t, verify(append(bytes.Clone(prefix), changedUnit...)), "validly signed seal cannot override final chunk end time")
	_, err = VerifyNativeRecordingOuter(bytes.NewReader(container), int64(len(container)), NativeRecordingVerifyOptions{})
	require.Error(t, err, "missing trust anchor")
	other := signer.identity.ProducerId()
	other[0] ^= 1
	_, err = VerifyNativeRecordingOuter(bytes.NewReader(container), int64(len(container)), NativeRecordingVerifyOptions{ExpectedProducerId: other})
	require.Error(t, err)
	require.Error(t, verify(prefix), "unsealed prefix")
	broken := bytes.Clone(container)
	broken[len(nativeformat.RecordingMagic)+6] ^= 1
	require.Error(t, verify(broken), "tampered header")
	broken = bytes.Clone(container)
	broken[len(prefix)-len(finalUnit)-len(chunkUnit)+6] ^= 1
	require.Error(t, verify(broken), "tampered chunk")
	broken = bytes.Clone(container)
	broken[len(broken)-1] ^= 1
	require.Error(t, verify(broken), "tampered seal")
	tamperedHeader := decoded
	tamperedHeader.StartedAt.Seconds++
	payload, err := nativeformat.Marshal(tamperedHeader, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	framed, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	broken = append(append([]byte(nativeformat.RecordingMagic), framed...), container[len(nativeformat.RecordingMagic)+len(headerUnit):]...)
	require.Error(t, verify(broken), "valid CRC cannot replace a signed header")
	tamperedChunk, err := nativeformat.Unmarshal[nativeRecordingChunk](chunkPayload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	tamperedChunk.CastHashState[0] ^= 1
	payload, err = nativeformat.Marshal(tamperedChunk, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	framed, err = nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	broken = append(bytes.Clone(container[:len(nativeformat.RecordingMagic)+len(headerUnit)]), framed...)
	broken = append(broken, finalUnit...)
	broken = append(broken, sealUnit...)
	require.Error(t, verify(broken), "valid CRC cannot replace a signed chunk")
	tamperedSeal, err := nativeformat.Unmarshal[nativeRecordingSeal](sealPayload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	tamperedSeal.CastDigest[0] ^= 1
	payload, err = nativeformat.Marshal(tamperedSeal, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	framed, err = nativeformat.EncodeUnit(nativeformat.SealUnit, payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	broken = append(bytes.Clone(prefix), framed...)
	require.Error(t, verify(broken), "valid CRC cannot replace a signed Cast digest")
	require.Error(t, verify(append(bytes.Clone(container), 0)), "trailing bytes")
	broken = bytes.Clone(container)
	broken[len(nativeformat.RecordingMagic)+5] = 0
	require.Error(t, verify(broken), "uncommitted header")
	broken = bytes.Clone(container)
	broken[len(prefix)-len(finalUnit)-len(chunkUnit)+5] = 0
	require.Error(t, verify(broken), "uncommitted chunk")
	// A committed final chunk is mandatory; a seal cannot reinterpret a
	// continuation as a completed recording.
	withoutFinal := append(bytes.Clone(prefix[:len(prefix)-len(finalUnit)]), sealUnit...)
	require.Error(t, verify(withoutFinal))
	_, err = VerifyNativeRecordingOuter(bytes.NewReader(container), int64(len(container)), NativeRecordingVerifyOptions{ExpectedProducerId: signer.identity.ProducerId(), MaximumChunks: 0, MaximumContainerBytes: int64(len(container) - 1)})
	require.Error(t, err)
}

func TestNativeRecordingRejectsForeignRecipientAndUnsignedCast(t *testing.T) {
	signer, id, started := nativeSignerTest(t)
	_, err := signer.Header(id, started, signer.identity.Fingerprint())
	require.Error(t, err)
	_, err = signer.Seal(nativeRecordingSeal{Status: 1, ChunkCount: 1, CastSignature: make([]byte, 64), CastBytes: 1, EndedAt: nativeformat.TimestampOf(started)}, id)
	require.Error(t, err)
	_, checkpoint := nativeCastTest(t, signer)
	lastElapsed := uint64(248 * time.Millisecond)
	_, err = signer.Chunk(nativeRecordingChunk{Sequence: 1, DecodedLength: 5, StoredPayload: []byte("JSON!"), StoredHash: sha256.Sum256([]byte("JSON!")), CastHashState: checkpoint.State, CastHashBytes: checkpoint.Bytes, LastElapsedNanos: &lastElapsed})
	require.Error(t, err, "raw or JSON chunk must not be signed")
}

func TestNativeRecordingEncryptedOuterNeedsNoPrivateDecryptionKey(t *testing.T) {
	signer, id, started := nativeSignerTest(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := bfcrypto.PrivateKeyFromSdk(private)
	require.NoError(t, err)
	recipient, err := bfcrypto.NewAgeSshRecipient(key.PublicKey().ToSsh())
	require.NoError(t, err)
	header, err := signer.Header(id, started, recipient.Fingerprint())
	require.NoError(t, err)
	headerUnit, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, header, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	// Outer-only fixture: a full verifier must reject unrecognized event maps.
	inner, err := nativeformat.Marshal(map[uint64]any{1: []any{map[uint64]any{1: uint64(1), 2: []byte("secret")}}}, nativeformat.MaxRecordingDecodedChunk)
	require.NoError(t, err)
	stored, err := nativeformat.EncodeStoredPayload(inner, recipient, nativeformat.PayloadLimits{MaxDecoded: nativeformat.MaxRecordingDecodedChunk, MaxStored: nativeformat.MaxRecordingChunkPayload})
	require.NoError(t, err)
	castBytes, checkpoint := nativeCastTest(t, signer)
	lastElapsed := uint64(248 * time.Millisecond)
	chunk, err := signer.Chunk(nativeRecordingChunk{Sequence: 1, PreviousUnitHash: nativeRecordingHash(nativeRecordingUnitDomain, headerUnit), DecodedLength: uint32(len(inner)), StoredPayload: stored, StoredHash: sha256.Sum256(stored), CastHashState: checkpoint.State, CastHashBytes: checkpoint.Bytes, LastElapsedNanos: &lastElapsed})
	require.NoError(t, err)
	chunkUnit, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, chunk, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	prefix := append(append([]byte(nativeformat.RecordingMagic), headerUnit...), chunkUnit...)
	cast, err := VerifyCast(bytes.NewReader(castBytes), CastVerifyOptions{ExpectedProducerId: signer.identity.ProducerId()})
	require.NoError(t, err)
	castSignature, err := signer.identity.NewSessionRecordingCastSignature(id.String(), cast.Digest.String())
	require.NoError(t, err)
	finalDigest, finalBytes := [32]byte(cast.Digest), uint64(len(castBytes))
	endedAt := nativeformat.TimestampOf(started.Add(time.Second))
	finalChunk, err := signer.Chunk(nativeRecordingChunk{Sequence: 2, PreviousUnitHash: nativeRecordingHash(nativeRecordingUnitDomain, chunkUnit), DecodedLength: uint32(len(inner)), StoredPayload: stored, StoredHash: sha256.Sum256(stored), CastHashState: finalDigest, FinalStatus: 1, CastDigest: &finalDigest, CastSignature: castSignature.Signature, CastBytes: &finalBytes, EndedAt: &endedAt})
	require.NoError(t, err)
	finalUnit, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, finalChunk, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	prefix = append(prefix, finalUnit...)
	seal, err := signer.Seal(nativeRecordingSeal{Status: 1, ChunkCount: 2, LastUnitHash: nativeRecordingHash(nativeRecordingUnitDomain, finalUnit), ContentHash: nativeRecordingHash(nativeRecordingContentDomain, prefix), CastDigest: finalDigest, CastSignature: castSignature.Signature, CastBytes: finalBytes, EndedAt: endedAt}, id)
	require.NoError(t, err)
	sealUnit, err := nativeformat.EncodeUnit(nativeformat.SealUnit, seal, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	container := append(prefix, sealUnit...)
	verification, err := VerifyNativeRecordingOuter(bytes.NewReader(container), int64(len(container)), NativeRecordingVerifyOptions{ExpectedProducerId: signer.identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, recipient.Fingerprint(), verification.Header.Recipient)
	// The encrypted inner CBOR is deliberately not claimed to be fully verified.
	_, err = nativeformat.DecodeStoredPayload(stored, nil, recipient.Fingerprint(), nativeformat.PayloadLimits{MaxDecoded: nativeformat.MaxRecordingDecodedChunk, MaxStored: nativeformat.MaxRecordingChunkPayload})
	require.Error(t, err)
}
