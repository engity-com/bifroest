package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestCastZstdWriterEnforcesVerifierLimits(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var baselineOutput bytes.Buffer
	baseline, err := NewCastZstdWriter(&baselineOutput, identity, header, metadata, 1)
	require.NoError(t, err)
	initialCastBytes := baseline.sink.castBytes
	initialPrefixBytes := baseline.sink.prefixBytes
	require.NoError(t, baseline.release())

	for _, current := range []struct {
		name    string
		options CastZstdVerifyOptions
		message string
	}{
		{name: "chunks", options: CastZstdVerifyOptions{MaximumChunks: 1}, message: "chunk count exceeds maximum"},
		{name: "Cast bytes", options: CastZstdVerifyOptions{MaximumCastBytes: int64(initialCastBytes)}, message: "Cast size exceeds maximum"},
		{name: "container bytes", options: CastZstdVerifyOptions{MaximumContainerBytes: int64(initialPrefixBytes + castZstdSealFrameSize)}, message: "container exceeds maximum size"},
	} {
		t.Run(current.name, func(t *testing.T) {
			var output bytes.Buffer
			writer, err := newCastZstdWriter(&output, identity, header, metadata, 1, current.options)
			require.NoError(t, err)
			initialContainerBytes := output.Len()

			err = writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("blocked"))
			require.ErrorContains(t, err, current.message)
			require.Equal(t, initialContainerBytes, output.Len())
			require.ErrorContains(t, writer.repositoryFailure(), current.message)
			require.NoError(t, writer.release())
		})
	}
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

func TestCastZstdExportRejectsExpansionBeyondDeclaredPlaintext(t *testing.T) {
	const declaredPlaintext = uint32(256)
	frame := zstdExpansionTestFrame(t, declaredPlaintext)
	require.NoError(t, validateSingleCastZstdFrame(frame, declaredPlaintext))
	container, identity := castZstdExpansionTestContainer(t, frame, declaredPlaintext)

	var output bytes.Buffer
	_, err := ExportCastZstd(bytes.NewReader(container), int64(len(container)), &output, CastZstdVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.ErrorContains(t, err, "cannot decompress Cast Zstandard frame")
	require.ErrorIs(t, err, zstd.ErrDecoderSizeExceeded)
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
	require.Equal(t, startupRecoveryReason, result.Verification.Cast.Result.Reason)

	again, err := RecoverCastZstd(file, identity, checkpoint, metadata.StartedAt.Add(3*time.Second), CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.True(t, again.AlreadySealed)
}

func TestCastZstdRecoveryCompletesSealWithoutChangingFinalCast(t *testing.T) {
	for _, test := range []struct {
		status     CastStatus
		reason     string
		exitStatus *uint32
	}{
		{status: CastStatusCompleted, exitStatus: func() *uint32 { value := uint32(0); return &value }()},
		{status: CastStatusFailed, reason: "recording-capture"},
		{status: CastStatusIncomplete, reason: "canceled"},
	} {
		t.Run(string(test.status), func(t *testing.T) {
			file, identity, metadata, writer := newCastZstdRecoveryTestWriter(t)
			require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("final\r\n")))
			checkpoint, err := writer.Checkpoint()
			require.NoError(t, err)
			_, err = writer.Seal(2*time.Second, CastResult{Status: test.status, EndedAt: metadata.StartedAt.Add(2 * time.Second), Reason: test.reason}, test.exitStatus)
			require.NoError(t, err)
			size, err := file.Seek(0, io.SeekEnd)
			require.NoError(t, err)
			require.NoError(t, file.Truncate(size-10))
			require.NoError(t, file.Sync())

			result, err := RecoverCastZstd(file, identity, checkpoint, metadata.StartedAt.Add(3*time.Second), CastZstdVerifyOptions{})
			require.NoError(t, err)
			require.True(t, result.Truncated)
			require.True(t, result.Finalized)
			require.Equal(t, test.status, result.Verification.Summary.Status)
			require.Equal(t, test.reason, result.Verification.Cast.Result.Reason)
		})
	}
}

func TestCastZstdRecoveryHandlesEveryPostCheckpointCrashPosition(t *testing.T) {
	file, identity, metadata, writer := newCastZstdRecoveryTestWriter(t)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("durable\r\n")))
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	require.NoError(t, writer.WriteOutput(2*time.Second, OutputStreamTerminal, []byte("after checkpoint\r\n")))
	continuation, err := writer.Checkpoint()
	require.NoError(t, err)
	exitStatus := uint32(0)
	_, err = writer.Seal(3*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(3 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	require.NoError(t, file.Sync())

	containerSize, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	container := make([]byte, containerSize)
	_, err = file.ReadAt(container, 0)
	require.NoError(t, err)
	checkpointEnd := int(checkpoint.PrefixBytes)
	continuationEnd := int(continuation.PrefixBytes)
	sealStart := len(container) - castZstdSealFrameSize
	require.Less(t, checkpointEnd, continuationEnd)
	require.Less(t, continuationEnd, sealStart)
	unitEnds := map[int]bool{checkpointEnd: true}
	for offset := checkpointEnd; offset < len(container); {
		require.GreaterOrEqual(t, len(container)-offset, 8)
		switch binary.LittleEndian.Uint32(container[offset:]) {
		case zstdSkippableMagicBase | uint32(castZstdChunkSkippableId):
			require.GreaterOrEqual(t, len(container)-offset, 8+castZstdChunkPayloadSize)
			frameSize := int(binary.BigEndian.Uint32(container[offset+8+53:]))
			offset += 8 + castZstdChunkPayloadSize + frameSize
		case zstdSkippableMagicBase | uint32(castZstdSealSkippableId):
			offset += castZstdSealFrameSize
		default:
			require.FailNowf(t, "unexpected unit", "offset %d", offset)
		}
		require.LessOrEqual(t, offset, len(container))
		unitEnds[offset] = true
	}
	require.True(t, unitEnds[continuationEnd])
	require.True(t, unitEnds[sealStart])
	require.True(t, unitEnds[len(container)])

	for cut := checkpointEnd; cut <= len(container); cut++ {
		crashFile := &memoryRecoveryFile{content: append([]byte(nil), container[:cut]...), offset: int64(cut)}

		result, err := RecoverCastZstd(crashFile, identity, checkpoint, metadata.StartedAt.Add(4*time.Second), CastZstdVerifyOptions{})
		require.NoErrorf(t, err, "cut %d", cut)
		if cut == len(container) {
			require.Truef(t, result.AlreadySealed, "cut %d", cut)
			require.Falsef(t, result.Finalized, "cut %d", cut)
		} else {
			require.Falsef(t, result.AlreadySealed, "cut %d", cut)
			require.Truef(t, result.Finalized, "cut %d", cut)
		}
		require.Equalf(t, !unitEnds[cut], result.Truncated, "cut %d", cut)
		if cut >= sealStart {
			require.Equalf(t, CastStatusCompleted, result.Verification.Summary.Status, "cut %d", cut)
			require.Emptyf(t, result.Verification.Cast.Result.Reason, "cut %d", cut)
		} else {
			require.Equalf(t, CastStatusIncomplete, result.Verification.Summary.Status, "cut %d", cut)
			require.Equalf(t, startupRecoveryReason, result.Verification.Cast.Result.Reason, "cut %d", cut)
		}
		expectedOutputEvents := uint64(1)
		if cut >= continuationEnd {
			expectedOutputEvents = 2
		}
		require.Equalf(t, expectedOutputEvents, result.Verification.Cast.OutputEvents, "cut %d", cut)

		preservedEnd := checkpointEnd
		for unitEnd := range unitEnds {
			if unitEnd <= cut && unitEnd <= sealStart && unitEnd > preservedEnd {
				preservedEnd = unitEnd
			}
		}
		if cut == len(container) {
			preservedEnd = len(container)
		}
		recovered := append([]byte(nil), crashFile.content...)
		require.GreaterOrEqualf(t, len(recovered), preservedEnd, "cut %d", cut)
		require.Equalf(t, container[:preservedEnd], recovered[:preservedEnd], "preserved prefix at cut %d", cut)
		if unitEnds[cut] {
			again, err := RecoverCastZstd(crashFile, identity, checkpoint, metadata.StartedAt.Add(5*time.Second), CastZstdVerifyOptions{})
			require.NoErrorf(t, err, "second recovery at cut %d", cut)
			require.Truef(t, again.AlreadySealed, "second recovery at cut %d", cut)
			require.Equalf(t, recovered, crashFile.content, "second recovery at cut %d", cut)
		}
	}
}

func TestCastZstdRecoveryHandlesCrashDuringRecovery(t *testing.T) {
	file, identity, metadata, writer := newCastZstdRecoveryTestWriter(t)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("durable\r\n")))
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	original := make([]byte, checkpoint.PrefixBytes)
	_, err = file.ReadAt(original, 0)
	require.NoError(t, err)

	firstRecoveredAt := metadata.StartedAt.Add(2 * time.Second)
	first := &memoryRecoveryFile{content: append([]byte(nil), original...), offset: int64(len(original))}
	firstResult, err := RecoverCastZstd(first, identity, checkpoint, firstRecoveredAt, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.True(t, firstResult.Finalized)
	recovered := append([]byte(nil), first.content...)
	chunkStart := len(original)
	sealStart := len(recovered) - castZstdSealFrameSize
	descriptorEnd := chunkStart + 8 + castZstdChunkPayloadSize
	require.Less(t, descriptorEnd, sealStart)
	cuts := sortedUniqueRecoveryOffsets(
		chunkStart,
		chunkStart+1,
		chunkStart+7,
		chunkStart+8,
		descriptorEnd-1,
		descriptorEnd,
		descriptorEnd+(sealStart-descriptorEnd)/2,
		sealStart-1,
		sealStart,
		sealStart+1,
		sealStart+7,
		sealStart+8,
		len(recovered)-1,
		len(recovered),
	)
	secondRecoveredAt := metadata.StartedAt.Add(3 * time.Second)
	for _, cut := range cuts {
		crashFile := &memoryRecoveryFile{content: append([]byte(nil), recovered[:cut]...), offset: int64(cut)}
		result, err := RecoverCastZstd(crashFile, identity, checkpoint, secondRecoveredAt, CastZstdVerifyOptions{})
		require.NoErrorf(t, err, "cut %d", cut)
		require.Equalf(t, CastStatusIncomplete, result.Verification.Summary.Status, "cut %d", cut)
		require.Equalf(t, startupRecoveryReason, result.Verification.Cast.Result.Reason, "cut %d", cut)
		require.Equalf(t, uint64(1), result.Verification.Cast.OutputEvents, "cut %d", cut)
		expectedEndedAt := secondRecoveredAt
		if cut >= sealStart {
			expectedEndedAt = firstRecoveredAt
		}
		require.Equalf(t, expectedEndedAt, result.Verification.Cast.Result.EndedAt, "cut %d", cut)
		exactBoundary := cut == chunkStart || cut == sealStart || cut == len(recovered)
		require.Equalf(t, !exactBoundary, result.Truncated, "cut %d", cut)

		preservedEnd := chunkStart
		if cut >= sealStart {
			preservedEnd = sealStart
		}
		if cut == len(recovered) {
			preservedEnd = len(recovered)
		}
		require.Equalf(t, recovered[:preservedEnd], crashFile.content[:preservedEnd], "preserved prefix at cut %d", cut)
		sealed := append([]byte(nil), crashFile.content...)
		again, err := RecoverCastZstd(crashFile, identity, checkpoint, metadata.StartedAt.Add(4*time.Second), CastZstdVerifyOptions{})
		require.NoErrorf(t, err, "second recovery at cut %d", cut)
		require.Truef(t, again.AlreadySealed, "second recovery at cut %d", cut)
		require.Equalf(t, sealed, crashFile.content, "second recovery at cut %d", cut)
	}
}

func TestCastZstdRecoveryRejectsFinalSizeOverflow(t *testing.T) {
	identity, _, metadata := castTestValues(t, true)
	scan := &castZstdStream{
		header:           audit.SessionRecordingZstdHeader{RecordingId: uuid.UUID(metadata.RecordingId)},
		headerUnitHash:   audit.SessionRecordingHash{1},
		previousUnitHash: audit.SessionRecordingHash{2},
		streamHash:       newDomainHasher(castZstdStreamHashDomain),
		validEnd:         math.MaxInt64,
		castBytes:        1,
		zstdBytes:        1,
		chunkCount:       1,
	}
	cast := &CastVerification{
		Result: CastResult{Status: CastStatusCompleted},
		Digest: CastDigest{3},
	}

	_, err := planRecoveredCastZstdSeal(identity, scan, cast, nil, CastZstdVerifyOptions{MaximumContainerBytes: math.MaxInt64})
	require.ErrorContains(t, err, "would exceed")
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
	previousHash := hashDomainValues(castZstdUnitHashDomain, headerFrame)
	headerHash := previousHash
	streamHasher := newDomainHasher(castZstdStreamHashDomain)
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
			FrameHash:        hashDomainValues(castZstdFrameHashDomain, frame),
		})
		require.NoError(t, err)
		descriptor, err := encodeCastZstdChunk(value)
		require.NoError(t, err)
		result = append(result, descriptor...)
		result = append(result, frame...)
		previousHash = hashDomainValues(castZstdUnitHashDomain, descriptor, frame)
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

func castZstdExpansionTestContainer(t *testing.T, frame []byte, plaintextLength uint32) ([]byte, *audit.Identity) {
	t.Helper()
	identity, _, metadata := castTestValues(t, true)
	recordingId := [16]byte(metadata.RecordingId)
	header, err := identity.NewSessionRecordingZstdHeader(castZstdFormatVersion, castVersion, castZstdCodec, recordingId)
	require.NoError(t, err)
	headerFrame, err := encodeCastZstdHeader(header)
	require.NoError(t, err)
	headerHash := hashDomainValues(castZstdUnitHashDomain, headerFrame)
	chunk, err := identity.NewSessionRecordingZstdChunk(audit.SessionRecordingZstdChunk{
		FormatVersion:    castZstdFormatVersion,
		RecordingId:      recordingId,
		Sequence:         1,
		PreviousUnitHash: headerHash,
		PlaintextLength:  plaintextLength,
		FrameLength:      uint32(len(frame)),
		FrameHash:        hashDomainValues(castZstdFrameHashDomain, frame),
	})
	require.NoError(t, err)
	descriptor, err := encodeCastZstdChunk(chunk)
	require.NoError(t, err)
	result := append(append(append([]byte(nil), headerFrame...), descriptor...), frame...)
	lastChunkHash := hashDomainValues(castZstdUnitHashDomain, descriptor, frame)
	digest := audit.SessionRecordingHash{1}
	streamHash := audit.SessionRecordingHash{1}
	seal, err := identity.NewSessionRecordingZstdSeal(audit.SessionRecordingZstdSeal{
		FormatVersion:     castZstdFormatVersion,
		RecordingId:       recordingId,
		Status:            1,
		ChunkCount:        1,
		CastBytes:         uint64(plaintextLength),
		ZstdBytes:         uint64(len(frame)),
		PrefixBytes:       uint64(len(result)),
		HeaderUnitHash:    headerHash,
		LastChunkUnitHash: lastChunkHash,
		CastContentDigest: digest,
		CastStreamHash:    streamHash,
	})
	require.NoError(t, err)
	sealFrame, err := encodeCastZstdSeal(seal)
	require.NoError(t, err)
	return append(result, sealFrame...), identity
}

func zstdExpansionTestFrame(t *testing.T, declaredPlaintext uint32) []byte {
	t.Helper()
	expanded := bytes.Repeat([]byte{'A'}, 128<<10)
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true), zstd.WithEncoderConcurrency(1))
	require.NoError(t, err)
	encoded := encoder.EncodeAll(expanded, nil)
	encoder.Close()
	require.GreaterOrEqual(t, len(encoded), 4)

	header := zstd.Header{
		WindowSize:       uint64(len(expanded)),
		HasFCS:           true,
		FrameContentSize: uint64(declaredPlaintext),
		HasCheckSum:      true,
	}
	frame, err := header.AppendTo(nil)
	require.NoError(t, err)
	blockHeader := uint32(len(expanded))<<3 | 1<<1 | 1
	frame = append(frame, byte(blockHeader), byte(blockHeader>>8), byte(blockHeader>>16), expanded[0])
	return append(frame, encoded[len(encoded)-4:]...)
}

type memoryRecoveryFile struct {
	content []byte
	offset  int64
}

func (this *memoryRecoveryFile) ReadAt(target []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("negative read offset %d", offset)
	}
	if offset >= int64(len(this.content)) {
		return 0, io.EOF
	}
	read := copy(target, this.content[offset:])
	if read != len(target) {
		return read, io.EOF
	}
	return read, nil
}

func (this *memoryRecoveryFile) Write(value []byte) (int, error) {
	if this.offset < 0 {
		return 0, fmt.Errorf("negative write offset %d", this.offset)
	}
	end := this.offset + int64(len(value))
	if end > int64(len(this.content)) {
		this.content = append(this.content, make([]byte, int(end)-len(this.content))...)
	}
	copy(this.content[this.offset:end], value)
	this.offset = end
	return len(value), nil
}

func (this *memoryRecoveryFile) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = this.offset
	case io.SeekEnd:
		base = int64(len(this.content))
	default:
		return 0, fmt.Errorf("illegal seek whence %d", whence)
	}
	next := base + offset
	if next < 0 {
		return 0, fmt.Errorf("negative seek offset %d", next)
	}
	this.offset = next
	return next, nil
}

func (this *memoryRecoveryFile) Truncate(size int64) error {
	if size < 0 {
		return fmt.Errorf("negative truncate size %d", size)
	}
	if size <= int64(len(this.content)) {
		this.content = this.content[:size]
	} else {
		this.content = append(this.content, make([]byte, int(size)-len(this.content))...)
	}
	return nil
}

func (this *memoryRecoveryFile) Sync() error {
	return nil
}

func sortedUniqueRecoveryOffsets(values ...int) []int {
	unique := make(map[int]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	result := make([]int, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}
