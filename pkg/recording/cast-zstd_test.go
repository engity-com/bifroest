package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
)

func TestCastZstdV1GoldenHash(t *testing.T) {
	container, _, _, _ := sealedCastZstdTestContent(t, 300)
	digest := sha256.Sum256(container)
	require.Equal(t, "aa6b6376f21b09d5f0d08f0fcb9d2c63a16201b111d0e5c75c596ce0a4ee4c23", hex.EncodeToString(digest[:]))
}

func TestCastZstdRoundTripAndStandardDecoderCompatibility(t *testing.T) {
	container, cast, summary, identity := sealedCastZstdTestContent(t, 300)
	require.Greater(t, summary.ChunkCount, uint64(1))

	verification, err := VerifyCastZstd(bytes.NewReader(container), int64(len(container)), CastZstdVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, summary, verification.Summary)
	require.Equal(t, uint64(2), verification.Cast.OutputEvents)
	require.Equal(t, uint64(1), verification.Cast.ResizeEvents)
	require.True(t, verification.Trusted)
	require.True(t, verification.Cast.Trusted)

	decoder, err := zstd.NewReader(bytes.NewReader(container))
	require.NoError(t, err)
	decoded, err := io.ReadAll(decoder)
	require.NoError(t, err)
	decoder.Close()
	require.Equal(t, cast, decoded)

	var exported bytes.Buffer
	exportedVerification, err := ExportCastZstd(bytes.NewReader(container), int64(len(container)), &exported, CastZstdVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, verification.Summary, exportedVerification.Summary)
	require.Equal(t, cast, exported.Bytes())
}

func TestCastZstdWriterCommitsInitialMetadataChunkDuringConstruction(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastZstdWriter(&output, identity, header, metadata, 0)
	require.NoError(t, err)
	require.Greater(t, output.Len(), 8+castZstdHeaderPayloadSize+8+castZstdChunkPayloadSize)
	require.Equal(t, zstdSkippableMagicBase|uint32(castZstdChunkSkippableId), binary.LittleEndian.Uint32(output.Bytes()[8+castZstdHeaderPayloadSize:]))
	exitStatus := uint32(0)
	_, err = writer.Seal(time.Millisecond, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Millisecond)}, &exitStatus)
	require.NoError(t, err)
}

func TestCastZstdKeepsRelatedCastLinesInOneFrame(t *testing.T) {
	container, _, _, _ := sealedCastZstdTestContent(t, 256)
	chunks := decodeCastZstdTestChunks(t, container)
	require.Greater(t, len(chunks), 1)
	require.Contains(t, string(chunks[0]), "\n"+castMetadataCommentPrefix)
	for _, chunk := range chunks {
		lines := bytes.Split(bytes.TrimSuffix(chunk, []byte{'\n'}), []byte{'\n'})
		last := lines[len(lines)-1]
		require.False(t, bytes.HasPrefix(last, []byte(castEventCommentPrefix)), "event metadata split from its event")
		require.False(t, bytes.HasPrefix(last, []byte(castResultCommentPrefix)), "result split from its signature")
	}
}

func TestCastZstdVerificationRejectsTamperingTruncationAndTrailingData(t *testing.T) {
	container, _, _, identity := sealedCastZstdTestContent(t, 300)
	options := CastZstdVerifyOptions{AllowUntrusted: true}

	frameOffset := castZstdHeaderPayloadSize + 8 + castZstdChunkPayloadSize + 8
	tamperedFrame := append([]byte(nil), container...)
	tamperedFrame[frameOffset+8] ^= 0x01
	_, err := VerifyCastZstd(bytes.NewReader(tamperedFrame), int64(len(tamperedFrame)), options)
	require.ErrorContains(t, err, "frame 1 hash is invalid")

	tamperedDescriptor := append([]byte(nil), container...)
	tamperedDescriptor[castZstdHeaderPayloadSize+8+8+49] ^= 0x01
	_, err = VerifyCastZstd(bytes.NewReader(tamperedDescriptor), int64(len(tamperedDescriptor)), options)
	require.Error(t, err)

	for _, length := range []int{1, castZstdHeaderPayloadSize + 7, frameOffset, len(container) - 1} {
		_, err = VerifyCastZstd(bytes.NewReader(container[:length]), int64(length), options)
		require.Error(t, err, "prefix of length %d was accepted", length)
	}

	trailing := append(append([]byte(nil), container...), 0)
	_, err = VerifyCastZstd(bytes.NewReader(trailing), int64(len(trailing)), options)
	require.ErrorContains(t, err, "after its final seal")

	_, err = VerifyCastZstd(bytes.NewReader(container), int64(len(container)), CastZstdVerifyOptions{})
	require.ErrorContains(t, err, "expected producer ID is required")
	otherIdentity, _, _ := castTestValuesWithSeed(t, true, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_, err = VerifyCastZstd(bytes.NewReader(container), int64(len(container)), CastZstdVerifyOptions{ExpectedProducerId: otherIdentity.ProducerId()})
	require.ErrorContains(t, err, "belongs to producer")
	require.NotEqual(t, identity.ProducerId(), otherIdentity.ProducerId())
}

func TestCastZstdExportWritesNothingBeforeSuccessfulVerification(t *testing.T) {
	container, _, _, _ := sealedCastZstdTestContent(t, 300)
	container[len(container)-1] ^= 0x01
	var output bytes.Buffer
	_, err := ExportCastZstd(bytes.NewReader(container), int64(len(container)), &output, CastZstdVerifyOptions{AllowUntrusted: true})
	require.Error(t, err)
	require.Empty(t, output.Bytes())
}

func TestCastZstdVerificationEnforcesSizeLimits(t *testing.T) {
	container, cast, _, _ := sealedCastZstdTestContent(t, 300)
	_, err := VerifyCastZstd(bytes.NewReader(container), int64(len(container)), CastZstdVerifyOptions{
		MaximumContainerBytes: int64(len(container) - 1),
		AllowUntrusted:        true,
	})
	require.ErrorContains(t, err, "container size")
	_, err = VerifyCastZstd(bytes.NewReader(container), int64(len(container)), CastZstdVerifyOptions{
		MaximumCastBytes: int64(len(cast) - 1),
		AllowUntrusted:   true,
	})
	require.ErrorContains(t, err, "plaintext exceeds")
	_, err = VerifyCastZstd(bytes.NewReader(container), int64(len(container)), CastZstdVerifyOptions{
		MaximumChunks:  1,
		AllowUntrusted: true,
	})
	require.ErrorContains(t, err, "exceeds 1 chunks")
}

func TestCastZstdVerificationRejectsNonAtomicFrameBoundaries(t *testing.T) {
	_, cast, summary, identity := sealedCastZstdTestContent(t, 300)
	for name, split := range map[string]int{
		"inside-line": bytes.Index(cast, []byte("Welcome")) + 3,
		"after-event-metadata": func() int {
			start := bytes.Index(cast, []byte(castEventCommentPrefix))
			return start + bytes.IndexByte(cast[start:], '\n') + 1
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			container := encodeCastZstdTestContainer(t, identity, summary, [][]byte{cast[:split], cast[split:]})
			_, err := VerifyCastZstd(bytes.NewReader(container), int64(len(container)), CastZstdVerifyOptions{AllowUntrusted: true})
			require.ErrorContains(t, err, "boundaries")
		})
	}
}

func TestCastZstdRecoveryFinalizesOpenContainerAndTruncatesPhysicalTail(t *testing.T) {
	file, identity, metadata, writer := newCastZstdRecoveryTestWriter(t)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("before crash\r\n")))
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	partialDescriptor := encodeZstdSkippableFrame(castZstdChunkSkippableId, nil)[:6]
	_, err = file.Write(partialDescriptor)
	require.NoError(t, err)

	result, err := RecoverCastZstd(file, identity, checkpoint, metadata.StartedAt.Add(2*time.Second), CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.True(t, result.Truncated)
	require.True(t, result.Finalized)
	require.Equal(t, CastStatusIncomplete, result.Verification.Summary.Status)
	require.Equal(t, castZstdRecoveryReason, result.Verification.Cast.Result.Reason)

	again, err := RecoverCastZstd(file, identity, checkpoint, metadata.StartedAt.Add(3*time.Second), CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.True(t, again.AlreadySealed)
}

func TestCastZstdRecoveryCompletesSealWithoutChangingCompletedCast(t *testing.T) {
	file, identity, metadata, writer := newCastZstdRecoveryTestWriter(t)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("completed\r\n")))
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	exitStatus := uint32(0)
	_, err = writer.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	size, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(size-10))
	require.NoError(t, file.Sync())

	result, err := RecoverCastZstd(file, identity, checkpoint, metadata.StartedAt.Add(3*time.Second), CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.True(t, result.Truncated)
	require.True(t, result.Finalized)
	require.Equal(t, CastStatusCompleted, result.Verification.Summary.Status)
	require.Empty(t, result.Verification.Cast.Result.Reason)
}

func TestCastZstdRecoveryRejectsDataLossBehindCheckpoint(t *testing.T) {
	file, identity, metadata, writer := newCastZstdRecoveryTestWriter(t)
	initialCheckpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("must not disappear\r\n")))
	latestCheckpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	require.Greater(t, latestCheckpoint.ChunkCount, initialCheckpoint.ChunkCount)
	require.NoError(t, file.Truncate(int64(initialCheckpoint.PrefixBytes)))
	require.NoError(t, file.Sync())

	_, err = RecoverCastZstd(file, identity, latestCheckpoint, metadata.StartedAt.Add(2*time.Second), CastZstdVerifyOptions{})
	require.ErrorContains(t, err, "lost data behind its signed checkpoint")
	size, seekErr := file.Seek(0, io.SeekEnd)
	require.NoError(t, seekErr)
	require.Equal(t, int64(initialCheckpoint.PrefixBytes), size)
}

func TestCastZstdRecoveryRejectsCompleteCorruptionWithoutTruncating(t *testing.T) {
	file, identity, metadata, writer := newCastZstdRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	size, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	frameOffset := int64(8 + castZstdHeaderPayloadSize + 8 + castZstdChunkPayloadSize)
	var original [1]byte
	_, err = file.ReadAt(original[:], frameOffset+8)
	require.NoError(t, err)
	_, err = file.WriteAt([]byte{original[0] ^ 1}, frameOffset+8)
	require.NoError(t, err)
	require.NoError(t, file.Sync())

	_, err = RecoverCastZstd(file, identity, checkpoint, metadata.StartedAt.Add(time.Second), CastZstdVerifyOptions{})
	require.ErrorContains(t, err, "hash is invalid")
	remaining, seekErr := file.Seek(0, io.SeekEnd)
	require.NoError(t, seekErr)
	require.Equal(t, size, remaining)
}

func TestCastZstdRecoveryRejectsInnerOuterIdentityMismatchBeforeMutation(t *testing.T) {
	_, cast, summary, identity := sealedCastZstdTestContent(t, 300)
	var otherRecordingId Id
	require.NoError(t, otherRecordingId.UnmarshalText([]byte("44e34ab8-7457-4d88-a5e4-c57791775c3a")))
	outerSummary := summary
	outerSummary.RecordingId = otherRecordingId
	container := encodeCastZstdTestContainer(t, identity, outerSummary, [][]byte{cast})
	sealOffset := len(container) - (8 + castZstdSealPayloadSize)
	seal, err := decodeCastZstdSeal(container[sealOffset+8:], [16]byte(otherRecordingId), identity.ProducerId())
	require.NoError(t, err)
	checkpoint, err := identity.NewSessionRecordingZstdHead(audit.SessionRecordingZstdHead{
		FormatVersion: castZstdFormatVersion,
		RecordingId:   [16]byte(otherRecordingId),
		ChunkCount:    seal.ChunkCount,
		PrefixBytes:   uint64(sealOffset),
		LastUnitHash:  seal.LastChunkUnitHash,
	})
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "mismatched-*.cast.zst")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	_, err = file.Write(container[:sealOffset])
	require.NoError(t, err)

	_, err = RecoverCastZstd(file, identity, checkpoint, time.Now(), CastZstdVerifyOptions{})
	require.ErrorContains(t, err, "identity does not match")
	size, seekErr := file.Seek(0, io.SeekEnd)
	require.NoError(t, seekErr)
	require.Equal(t, int64(sealOffset), size)
}

func TestCastZstdRecoveryChecksPlannedLimitsBeforeMutation(t *testing.T) {
	file, identity, metadata, writer := newCastZstdRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	size, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)

	_, err = RecoverCastZstd(file, identity, checkpoint, metadata.StartedAt.Add(time.Second), CastZstdVerifyOptions{MaximumChunks: checkpoint.ChunkCount})
	require.ErrorContains(t, err, "would exceed")
	remaining, seekErr := file.Seek(0, io.SeekEnd)
	require.NoError(t, seekErr)
	require.Equal(t, size, remaining)
}

func sealedCastZstdTestContent(t *testing.T, chunkSize int) ([]byte, []byte, CastZstdSummary, *audit.Identity) {
	t.Helper()
	identity, header, metadata := castTestValues(t, true)
	write := func(writer interface {
		WriteOutput(time.Duration, OutputStream, []byte) error
		WriteResize(time.Duration, uint32, uint32) error
	}) {
		require.NoError(t, writer.WriteOutput(248*time.Millisecond, OutputStreamTerminal, []byte("Welcome to production\r\n")))
		require.NoError(t, writer.WriteOutput(500*time.Millisecond, OutputStreamTerminal, []byte{0xff, 0x00}))
		require.NoError(t, writer.WriteResize(1001*time.Millisecond, 132, 43))
	}
	result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2104 * time.Millisecond)}
	exitStatus := uint32(0)

	var container bytes.Buffer
	zstdWriter, err := NewCastZstdWriter(&container, identity, header, metadata, chunkSize)
	require.NoError(t, err)
	write(zstdWriter)
	summary, err := zstdWriter.Seal(2104*time.Millisecond, result, &exitStatus)
	require.NoError(t, err)

	var cast bytes.Buffer
	castWriter, err := NewCastWriter(&cast, identity, header, metadata)
	require.NoError(t, err)
	write(castWriter)
	digest, err := castWriter.Seal(2104*time.Millisecond, result, &exitStatus)
	require.NoError(t, err)
	require.Equal(t, digest, summary.Digest)
	require.Equal(t, uint64(cast.Len()), summary.CastBytes)
	return container.Bytes(), cast.Bytes(), summary, identity
}

func newCastZstdRecoveryTestWriter(t *testing.T) (*os.File, *audit.Identity, CastMetadata, *CastZstdWriter) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "active-*.cast.zst")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	identity, header, metadata := castTestValues(t, true)
	writer, err := NewCastZstdWriter(file, identity, header, metadata, 0)
	require.NoError(t, err)
	return file, identity, metadata, writer
}

func decodeCastZstdTestChunks(t *testing.T, container []byte) [][]byte {
	t.Helper()
	offset := 8 + castZstdHeaderPayloadSize
	decoder, err := zstd.NewReader(nil)
	require.NoError(t, err)
	defer decoder.Close()
	var result [][]byte
	for binary.LittleEndian.Uint32(container[offset:]) == zstdSkippableMagicBase|castZstdChunkSkippableId {
		require.Equal(t, uint32(castZstdChunkPayloadSize), binary.LittleEndian.Uint32(container[offset+4:]))
		payload := container[offset+8 : offset+8+castZstdChunkPayloadSize]
		frameSize := int(binary.BigEndian.Uint32(payload[53:]))
		offset += 8 + castZstdChunkPayloadSize
		plaintext, err := decoder.DecodeAll(container[offset:offset+frameSize], nil)
		require.NoError(t, err)
		result = append(result, plaintext)
		offset += frameSize
	}
	require.Equal(t, zstdSkippableMagicBase|uint32(castZstdSealSkippableId), binary.LittleEndian.Uint32(container[offset:]))
	return result
}

func encodeCastZstdTestContainer(t *testing.T, identity *audit.Identity, summary CastZstdSummary, chunks [][]byte) []byte {
	t.Helper()
	header, err := identity.NewSessionRecordingZstdHeader(castZstdFormatVersion, castVersion, castZstdCodec, [16]byte(summary.RecordingId))
	require.NoError(t, err)
	headerFrame, err := encodeCastZstdHeader(header)
	require.NoError(t, err)
	result := append([]byte(nil), headerFrame...)
	previousHash := hashSessionRecording(castZstdUnitHashDomain, headerFrame)
	headerHash := previousHash
	streamHasher := hashSessionRecordingWriter(castZstdStreamHashDomain)
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1),
		zstd.WithWindowSize(castZstdWindowSize),
		zstd.WithSingleSegment(true),
	)
	require.NoError(t, err)
	defer encoder.Close()
	var castBytes, zstdBytes uint64
	for index, plaintext := range chunks {
		frame := encoder.EncodeAll(plaintext, nil)
		value, err := identity.NewSessionRecordingZstdChunk(audit.SessionRecordingZstdChunk{
			FormatVersion:    castZstdFormatVersion,
			RecordingId:      [16]byte(summary.RecordingId),
			Sequence:         uint64(index + 1),
			PreviousUnitHash: previousHash,
			PlaintextOffset:  castBytes,
			PlaintextLength:  uint32(len(plaintext)),
			FrameLength:      uint32(len(frame)),
			FrameHash:        hashSessionRecording(castZstdFrameHashDomain, frame),
		})
		require.NoError(t, err)
		descriptor, err := encodeCastZstdChunk(value)
		require.NoError(t, err)
		result = append(result, descriptor...)
		result = append(result, frame...)
		previousHash = hashSessionRecording(castZstdUnitHashDomain, descriptor, frame)
		castBytes += uint64(len(plaintext))
		zstdBytes += uint64(len(frame))
		_, _ = streamHasher.Write(plaintext)
	}
	var digest audit.SessionRecordingHash
	copy(digest[:], summary.Digest[:])
	var streamHash audit.SessionRecordingHash
	copy(streamHash[:], streamHasher.Sum(nil))
	status, err := castZstdStatus(summary.Status)
	require.NoError(t, err)
	seal, err := identity.NewSessionRecordingZstdSeal(audit.SessionRecordingZstdSeal{
		FormatVersion:     castZstdFormatVersion,
		RecordingId:       [16]byte(summary.RecordingId),
		Status:            status,
		ChunkCount:        uint64(len(chunks)),
		CastBytes:         castBytes,
		ZstdBytes:         zstdBytes,
		PrefixBytes:       uint64(len(result)),
		HeaderUnitHash:    headerHash,
		LastChunkUnitHash: previousHash,
		CastContentDigest: digest,
		CastStreamHash:    streamHash,
	})
	require.NoError(t, err)
	sealFrame, err := encodeCastZstdSeal(seal)
	require.NoError(t, err)
	return append(result, sealFrame...)
}
