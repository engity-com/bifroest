package recording

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"math"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestBECastRecoveryFinalizesOpenContainerAndDecrypts(t *testing.T) {
	file, identity, recipient, identities, metadata, writer := newBECastRecoveryTestWriter(t)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("before crash\r\n")))
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, file.Sync())

	result, err := RecoverBECast(file, identity, recipient, checkpoint, metadata.StartedAt.Add(2*time.Second), BECastVerifyOptions{})
	require.NoError(t, err)
	require.True(t, result.Finalized)
	require.False(t, result.Truncated)
	require.Equal(t, CastStatusIncomplete, result.Verification.Summary.Status)

	size := beCastRecoveryFileSize(t, file)
	var plaintext bytes.Buffer
	verification, err := DecryptBECast(file, size, identities, &plaintext, BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, CastStatusIncomplete, verification.Cast.Result.Status)
	require.Equal(t, startupRecoveryReason, verification.Cast.Result.Reason)
	require.Equal(t, metadata.RecordingId, verification.Cast.Metadata.RecordingId)
	require.Equal(t, identity.ProducerId(), verification.Cast.Metadata.ProducerId)
	require.Contains(t, plaintext.String(), "before crash")
	fullyVerified, err := VerifyCast(bytes.NewReader(plaintext.Bytes()), CastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, verification.Cast, fullyVerified)

	parsed := parseBECastTestContainer(t, beCastRecoveryFileBytes(t, file))
	finalChunk := parsed.chunks[len(parsed.chunks)-1].value
	require.Equal(t, uint8(3), finalChunk.FinalStatus)
	require.Zero(t, finalChunk.ContentHashBytes)
	require.Equal(t, finalChunk.FinalStatus, parsed.seal.Status)
}

func TestBECastRecoverySupportsYear2300Checkpoint(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	startedAt := time.Date(2300, time.January, 2, 3, 4, 5, 987654321, time.UTC)
	header.Timestamp = startedAt.Unix()
	metadata.StartedAt = startedAt
	recipient, identities := newBECastTestEncryption(t)
	file, err := os.CreateTemp(t.TempDir(), "future-recovery-*.becast")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	writer, err := NewBECastWriter(file, identity, recipient, header, metadata, 256)
	require.NoError(t, err)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	require.Equal(t, startedAt.Unix(), checkpoint.StartedAtUnixSeconds)
	require.Equal(t, uint32(startedAt.Nanosecond()), checkpoint.StartedAtNanoseconds)
	require.NoError(t, file.Sync())

	result, err := RecoverBECast(file, identity, recipient, checkpoint, startedAt.Add(time.Second), BECastVerifyOptions{})
	require.NoError(t, err)
	require.True(t, result.Finalized)
	var plaintext bytes.Buffer
	verification, err := DecryptBECast(file, beCastRecoveryFileSize(t, file), identities, &plaintext, BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, startedAt, verification.Cast.Metadata.StartedAt)
	require.Equal(t, startedAt.Add(time.Second), verification.Cast.Result.EndedAt)
}

func TestBECastRecoveryTruncatesOnlyPhysicalPartialTail(t *testing.T) {
	file, identity, recipient, _, metadata, writer := newBECastRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	partial := encodeBECastUnit(castBECastChunkUnitType, make([]byte, castBECastChunkDescriptorSize+1))
	_, err = file.Write(partial[:len(partial)-5])
	require.NoError(t, err)

	result, err := RecoverBECast(file, identity, recipient, checkpoint, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.NoError(t, err)
	require.True(t, result.Truncated)
	require.True(t, result.Finalized)
	require.Equal(t, CastStatusIncomplete, result.Verification.Summary.Status)
}

func TestBECastRecoveryPreservesFinalChunkAndAddsSeal(t *testing.T) {
	for _, test := range []struct {
		status CastStatus
		reason string
	}{
		{status: CastStatusCompleted},
		{status: CastStatusFailed, reason: "recording-capture"},
		{status: CastStatusIncomplete, reason: "canceled"},
	} {
		t.Run(string(test.status), func(t *testing.T) {
			file, identity, recipient, identities, metadata, writer := newBECastRecoveryTestWriter(t)
			require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("finished\r\n")))
			checkpoint, err := writer.Checkpoint()
			require.NoError(t, err)
			var exitStatus *uint32
			if test.status == CastStatusCompleted {
				value := uint32(0)
				exitStatus = &value
			}
			_, err = writer.Seal(2*time.Second, CastResult{Status: test.status, EndedAt: metadata.StartedAt.Add(2 * time.Second), Reason: test.reason}, exitStatus)
			require.NoError(t, err)
			sealed := beCastRecoveryFileBytes(t, file)
			parsed := parseBECastTestContainer(t, sealed)
			prefix := append([]byte(nil), sealed[:parsed.sealOffset]...)
			require.NoError(t, file.Truncate(int64(parsed.sealOffset)))
			require.NoError(t, file.Sync())
			checkpoint.StartedAtUnixSeconds = math.MaxInt64
			checkpoint.StartedAtNanoseconds = 999_999_999
			checkpoint, err = identity.NewSessionRecordingBECastHead(checkpoint)
			require.NoError(t, err)

			result, err := RecoverBECast(file, identity, recipient, checkpoint, time.Time{}, BECastVerifyOptions{})
			require.NoError(t, err)
			require.True(t, result.Finalized)
			require.False(t, result.Truncated)
			require.Equal(t, test.status, result.Verification.Summary.Status)
			recovered := beCastRecoveryFileBytes(t, file)
			require.True(t, bytes.HasPrefix(recovered, prefix))

			var plaintext bytes.Buffer
			verification, err := DecryptBECast(file, int64(len(recovered)), identities, &plaintext, BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			require.NoError(t, err)
			require.Equal(t, test.status, verification.Cast.Result.Status)
			require.Equal(t, test.reason, verification.Cast.Result.Reason)
		})
	}
}

func TestBECastRecoveryHandlesEveryPostCheckpointCrashPosition(t *testing.T) {
	file, identity, recipient, identities, metadata, writer := newBECastRecoveryTestWriter(t)
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

	container := beCastRecoveryFileBytes(t, file)
	parsed := parseBECastTestContainer(t, container)
	checkpointEnd := int(checkpoint.PrefixBytes)
	continuationEnd := int(continuation.PrefixBytes)
	sealStart := parsed.sealOffset
	require.Less(t, checkpointEnd, continuationEnd)
	require.Less(t, continuationEnd, sealStart)
	unitEnds := map[int]bool{checkpointEnd: true}
	for _, chunk := range parsed.chunks {
		if chunk.endOffset >= checkpointEnd {
			unitEnds[chunk.endOffset] = true
		}
	}
	unitEnds[len(container)] = true
	require.True(t, unitEnds[continuationEnd])
	require.True(t, unitEnds[sealStart])

	for cut := checkpointEnd; cut <= len(container); cut++ {
		crashFile := &memoryRecoveryFile{content: append([]byte(nil), container[:cut]...), offset: int64(cut)}

		result, err := RecoverBECast(crashFile, identity, recipient, checkpoint, metadata.StartedAt.Add(4*time.Second), BECastVerifyOptions{})
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
		} else {
			require.Equalf(t, CastStatusIncomplete, result.Verification.Summary.Status, "cut %d", cut)
		}

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
			var plaintext bytes.Buffer
			verification, err := DecryptBECast(crashFile, int64(len(crashFile.content)), identities, &plaintext, BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			require.NoErrorf(t, err, "decrypt recovered boundary at cut %d", cut)
			require.Containsf(t, plaintext.String(), "durable", "cut %d", cut)
			expectedOutputEvents := uint64(1)
			if cut >= continuationEnd {
				expectedOutputEvents = 2
				require.Containsf(t, plaintext.String(), "after checkpoint", "cut %d", cut)
			} else {
				require.NotContainsf(t, plaintext.String(), "after checkpoint", "cut %d", cut)
			}
			require.Equalf(t, expectedOutputEvents, verification.Cast.OutputEvents, "cut %d", cut)
			if cut >= sealStart {
				require.Equalf(t, CastStatusCompleted, verification.Cast.Result.Status, "cut %d", cut)
				require.Emptyf(t, verification.Cast.Result.Reason, "cut %d", cut)
			} else {
				require.Equalf(t, CastStatusIncomplete, verification.Cast.Result.Status, "cut %d", cut)
				require.Equalf(t, startupRecoveryReason, verification.Cast.Result.Reason, "cut %d", cut)
			}

			again, err := RecoverBECast(crashFile, identity, recipient, checkpoint, metadata.StartedAt.Add(5*time.Second), BECastVerifyOptions{})
			require.NoErrorf(t, err, "second recovery at cut %d", cut)
			require.Truef(t, again.AlreadySealed, "second recovery at cut %d", cut)
			require.Equalf(t, recovered, crashFile.content, "second recovery at cut %d", cut)
		}
	}
}

func TestBECastRecoveryHandlesCrashDuringRecovery(t *testing.T) {
	file, identity, recipient, identities, metadata, writer := newBECastRecoveryTestWriter(t)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("durable\r\n")))
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	original := make([]byte, checkpoint.PrefixBytes)
	_, err = file.ReadAt(original, 0)
	require.NoError(t, err)

	firstRecoveredAt := metadata.StartedAt.Add(2 * time.Second)
	first := &memoryRecoveryFile{content: append([]byte(nil), original...), offset: int64(len(original))}
	firstResult, err := RecoverBECast(first, identity, recipient, checkpoint, firstRecoveredAt, BECastVerifyOptions{})
	require.NoError(t, err)
	require.True(t, firstResult.Finalized)
	recovered := append([]byte(nil), first.content...)
	parsed := parseBECastTestContainer(t, recovered)
	chunkStart := len(original)
	sealStart := parsed.sealOffset
	require.NotEmpty(t, parsed.chunks)
	recoveryChunk := parsed.chunks[len(parsed.chunks)-1]
	require.Equal(t, sealStart, recoveryChunk.endOffset)
	ciphertextStart := chunkStart + castBECastUnitPrefixSize + castBECastChunkDescriptorSize
	ciphertextEnd := sealStart - castBECastUnitTrailerSize
	require.Less(t, ciphertextStart, ciphertextEnd)
	cuts := sortedUniqueRecoveryOffsets(
		chunkStart,
		chunkStart+1,
		chunkStart+castBECastUnitPrefixSize-1,
		chunkStart+castBECastUnitPrefixSize,
		ciphertextStart-1,
		ciphertextStart,
		ciphertextStart+(ciphertextEnd-ciphertextStart)/2,
		ciphertextEnd-1,
		ciphertextEnd,
		sealStart-8,
		sealStart-1,
		sealStart,
		sealStart+1,
		sealStart+castBECastUnitPrefixSize-1,
		sealStart+castBECastUnitPrefixSize,
		len(recovered)-castBECastUnitTrailerSize,
		len(recovered)-8,
		len(recovered)-1,
		len(recovered),
	)
	secondRecoveredAt := metadata.StartedAt.Add(3 * time.Second)
	for _, cut := range cuts {
		crashFile := &memoryRecoveryFile{content: append([]byte(nil), recovered[:cut]...), offset: int64(cut)}
		result, err := RecoverBECast(crashFile, identity, recipient, checkpoint, secondRecoveredAt, BECastVerifyOptions{})
		require.NoErrorf(t, err, "cut %d", cut)
		require.Equalf(t, CastStatusIncomplete, result.Verification.Summary.Status, "cut %d", cut)
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
		var plaintext bytes.Buffer
		verification, err := DecryptBECast(crashFile, int64(len(crashFile.content)), identities, &plaintext, BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
		require.NoErrorf(t, err, "decrypt recovered cut %d", cut)
		require.Equalf(t, uint64(1), verification.Cast.OutputEvents, "cut %d", cut)
		require.Containsf(t, plaintext.String(), "durable", "cut %d", cut)
		require.Equalf(t, startupRecoveryReason, verification.Cast.Result.Reason, "cut %d", cut)
		expectedEndedAt := secondRecoveredAt
		if cut >= sealStart {
			expectedEndedAt = firstRecoveredAt
		}
		require.Equalf(t, expectedEndedAt, verification.Cast.Result.EndedAt, "cut %d", cut)

		sealed := append([]byte(nil), crashFile.content...)
		again, err := RecoverBECast(crashFile, identity, recipient, checkpoint, metadata.StartedAt.Add(4*time.Second), BECastVerifyOptions{})
		require.NoErrorf(t, err, "second recovery at cut %d", cut)
		require.Truef(t, again.AlreadySealed, "second recovery at cut %d", cut)
		require.Equalf(t, sealed, crashFile.content, "second recovery at cut %d", cut)
	}
}

func TestBECastRecoveryAlreadySealedIsIdempotent(t *testing.T) {
	file, identity, recipient, _, metadata, writer := newBECastRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	exitStatus := uint32(0)
	_, err = writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &exitStatus)
	require.NoError(t, err)
	before := beCastRecoveryFileBytes(t, file)
	checkpoint.StartedAtUnixSeconds = math.MinInt64
	checkpoint.StartedAtNanoseconds = 999_999_999
	checkpoint, err = identity.NewSessionRecordingBECastHead(checkpoint)
	require.NoError(t, err)

	result, err := RecoverBECast(file, identity, recipient, checkpoint, time.Time{}, BECastVerifyOptions{})
	require.NoError(t, err)
	require.True(t, result.AlreadySealed)
	require.False(t, result.Finalized)
	require.Equal(t, before, beCastRecoveryFileBytes(t, file))
}

func TestBECastRecoveryUsesValidContinuationAfterPersistedHead(t *testing.T) {
	file, identity, recipient, identities, metadata, writer := newBECastRecoveryTestWriter(t)
	persisted, err := writer.Checkpoint()
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("after persisted head\r\n")))
	latest, err := writer.Checkpoint()
	require.NoError(t, err)
	require.Greater(t, latest.ChunkCount, persisted.ChunkCount)
	require.NoError(t, file.Sync())

	result, err := RecoverBECast(file, identity, recipient, persisted, metadata.StartedAt.Add(2*time.Second), BECastVerifyOptions{})
	require.NoError(t, err)
	require.True(t, result.Finalized)
	var plaintext bytes.Buffer
	verification, err := DecryptBECast(file, beCastRecoveryFileSize(t, file), identities, &plaintext, BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Contains(t, plaintext.String(), "after persisted head")
	require.Equal(t, CastStatusIncomplete, verification.Cast.Result.Status)
}

func TestBECastRecoveryRejectsCompleteCorruptionWithoutMutation(t *testing.T) {
	file, identity, recipient, _, metadata, writer := newBECastRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	before := beCastRecoveryFileBytes(t, file)
	parsed := parseBECastTestContainer(t, before)
	offset := len(castBECastFileMagic) + len(parsed.headerUnit) + castBECastUnitPrefixSize
	_, err = file.WriteAt([]byte{before[offset] ^ 1}, int64(offset))
	require.NoError(t, err)
	corrupted := beCastRecoveryFileBytes(t, file)

	_, err = RecoverBECast(file, identity, recipient, checkpoint, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.Error(t, err)
	require.True(t, bferrors.System.IsErr(err))
	require.Equal(t, corrupted, beCastRecoveryFileBytes(t, file))
}

func TestBECastRecoveryRejectsCompleteMalformedUnitWithoutMutation(t *testing.T) {
	file, identity, recipient, _, metadata, writer := newBECastRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	malformed := encodeBECastUnit(99, nil)
	_, err = file.Write(malformed)
	require.NoError(t, err)
	before := beCastRecoveryFileBytes(t, file)

	_, err = RecoverBECast(file, identity, recipient, checkpoint, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.ErrorContains(t, err, "unexpected complete BECast unit type")
	require.True(t, bferrors.System.IsErr(err))
	require.Equal(t, before, beCastRecoveryFileBytes(t, file))
}

func TestBECastRecoveryRejectsFileSizeChangeDuringPlanning(t *testing.T) {
	file, identity, recipient, _, metadata, writer := newBECastRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	originalSize := beCastRecoveryFileSize(t, file)
	changing := &beCastChangingRecoveryFile{File: file, originalSize: originalSize}

	_, err = RecoverBECast(changing, identity, recipient, checkpoint, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.ErrorContains(t, err, "changed while being verified")
	require.True(t, bferrors.System.IsErr(err))
	require.Equal(t, originalSize+1, beCastRecoveryFileSize(t, file))
}

func TestBECastRecoveryRejectsWrongInputsWithoutMutation(t *testing.T) {
	file, identity, recipient, _, metadata, writer := newBECastRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	before := beCastRecoveryFileBytes(t, file)

	tampered := checkpoint
	tampered.ContentHashState[0] ^= 1
	_, err = RecoverBECast(file, identity, recipient, tampered, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.Error(t, err)
	require.True(t, bferrors.System.IsErr(err))
	require.Equal(t, before, beCastRecoveryFileBytes(t, file))

	for name, mutate := range map[string]func(*audit.SessionRecordingBECastHead){
		"Cast state":        func(value *audit.SessionRecordingBECastHead) { value.CastState++ },
		"start seconds":     func(value *audit.SessionRecordingBECastHead) { value.StartedAtUnixSeconds++ },
		"start nanoseconds": func(value *audit.SessionRecordingBECastHead) { value.StartedAtNanoseconds++ },
	} {
		t.Run("tampered "+name, func(t *testing.T) {
			tamperedHead := checkpoint
			mutate(&tamperedHead)
			_, err := RecoverBECast(file, identity, recipient, tamperedHead, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
			require.ErrorContains(t, err, "illegal session recording signature")
			require.True(t, bferrors.System.IsErr(err))
			require.Equal(t, before, beCastRecoveryFileBytes(t, file))
		})
	}

	unsupportedState := checkpoint
	unsupportedState.CastState++
	unsupportedState, err = identity.NewSessionRecordingBECastHead(unsupportedState)
	require.NoError(t, err)
	_, err = RecoverBECast(file, identity, recipient, unsupportedState, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.ErrorContains(t, err, "unsupported Cast state")
	require.True(t, bferrors.System.IsErr(err))
	require.Equal(t, before, beCastRecoveryFileBytes(t, file))

	wrongState := checkpoint
	wrongState.PrefixBytes++
	wrongState, err = identity.NewSessionRecordingBECastHead(wrongState)
	require.NoError(t, err)
	_, err = RecoverBECast(file, identity, recipient, wrongState, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.ErrorContains(t, err, "exact signed checkpoint state")
	require.True(t, bferrors.System.IsErr(err))
	require.Equal(t, before, beCastRecoveryFileBytes(t, file))

	otherIdentity, _, _ := castTestValuesWithSeed(t, true, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	_, err = RecoverBECast(file, otherIdentity, recipient, checkpoint, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.Error(t, err)
	require.True(t, bferrors.System.IsErr(err))
	require.Equal(t, before, beCastRecoveryFileBytes(t, file))

	otherRecipient, _ := newBECastTestEncryptionWithByte(t, 0x24)
	_, err = RecoverBECast(file, identity, otherRecipient, checkpoint, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.Equal(t, before, beCastRecoveryFileBytes(t, file))

	signingRecipient, err := bfcrypto.NewAgeSshRecipient(identity.PublicKey().ToSsh())
	require.NoError(t, err)
	_, err = RecoverBECast(file, identity, signingRecipient, checkpoint, metadata.StartedAt.Add(time.Second), BECastVerifyOptions{})
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.Equal(t, before, beCastRecoveryFileBytes(t, file))
}

func TestBECastRecoveryRejectsLimitsAndInvalidTimeWithoutMutation(t *testing.T) {
	file, identity, recipient, _, metadata, writer := newBECastRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	before := beCastRecoveryFileBytes(t, file)

	tests := []struct {
		name      string
		recovered time.Time
		options   BECastVerifyOptions
		config    bool
	}{
		{name: "zero time", config: true},
		{name: "non UTC", recovered: metadata.StartedAt.In(time.FixedZone("UTC+1", 3600)), config: true},
		{name: "before signed start", recovered: metadata.StartedAt.Add(-time.Nanosecond)},
		{name: "excessive duration", recovered: metadata.StartedAt.Add(maximumEventElapsed + time.Nanosecond)},
		{name: "chunk limit", recovered: metadata.StartedAt.Add(time.Second), options: BECastVerifyOptions{MaximumChunks: checkpoint.ChunkCount}},
		{name: "container limit", recovered: metadata.StartedAt.Add(time.Second), options: BECastVerifyOptions{MaximumContainerBytes: int64(len(before))}},
		{name: "Cast limit", recovered: metadata.StartedAt.Add(time.Second), options: BECastVerifyOptions{MaximumCastBytes: int64(checkpoint.ContentHashBytes)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := RecoverBECast(file, identity, recipient, checkpoint, test.recovered, test.options)
			require.Error(t, err)
			if test.config {
				require.True(t, bferrors.Config.IsErr(err))
			} else {
				require.True(t, bferrors.System.IsErr(err))
			}
			require.Equal(t, before, beCastRecoveryFileBytes(t, file))
		})
	}
}

func TestBECastRecoverySyncsAcceptedFinalChunkBeforeSeal(t *testing.T) {
	file, identity, recipient, _, metadata, writer := newBECastRecoveryTestWriter(t)
	checkpoint, err := writer.Checkpoint()
	require.NoError(t, err)
	exitStatus := uint32(0)
	_, err = writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &exitStatus)
	require.NoError(t, err)
	parsed := parseBECastTestContainer(t, beCastRecoveryFileBytes(t, file))
	require.NoError(t, file.Truncate(int64(parsed.sealOffset)))
	require.NoError(t, file.Sync())
	ordered := &beCastOrderedRecoveryFile{File: file}

	_, err = RecoverBECast(ordered, identity, recipient, checkpoint, time.Time{}, BECastVerifyOptions{})
	require.NoError(t, err)
	require.Equal(t, []string{"sync", "write", "sync"}, ordered.operations)
}

func TestBECastRecoveryRejectsFinalSizeOverflow(t *testing.T) {
	identity, _, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	scanner := &beCastScanner{
		header: audit.SessionRecordingBECastHeader{
			RecordingId: uuid.UUID(metadata.RecordingId),
		},
		headerUnitHash:       audit.SessionRecordingHash{1},
		previousUnitHash:     audit.SessionRecordingHash{2},
		ciphertextStreamHash: newDomainHasher(castBECastCiphertextStreamHashDomain),
		castBytes:            1,
		ciphertextBytes:      1,
		chunkCount:           1,
		finalChunkSeen:       true,
		finalContentHash:     audit.SessionRecordingHash{3},
		finalStatus:          1,
	}
	scan := &beCastRecoveryScan{scanner: scanner, validEnd: math.MaxInt64}
	_, err := planRecoveredBECast(identity, recipient, scan, audit.SessionRecordingBECastHead{}, time.Time{}, BECastVerifyOptions{MaximumContainerBytes: math.MaxInt64})
	require.ErrorContains(t, err, "size overflows int64")
	require.True(t, bferrors.System.IsErr(err))
}

func newBECastRecoveryTestWriter(t *testing.T) (*os.File, *audit.Identity, *bfcrypto.AgeSshRecipient, *bfcrypto.AgeSshIdentities, CastMetadata, *BECastWriter) {
	t.Helper()
	identity, header, metadata := castTestValues(t, true)
	recipient, identities := newBECastTestEncryption(t)
	file, err := os.CreateTemp(t.TempDir(), "recovery-*.becast")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	writer, err := NewBECastWriter(file, identity, recipient, header, metadata, 256)
	require.NoError(t, err)
	return file, identity, recipient, identities, metadata, writer
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

func beCastRecoveryFileSize(t *testing.T, file *os.File) int64 {
	t.Helper()
	size, err := file.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	return size
}

func beCastRecoveryFileBytes(t *testing.T, file *os.File) []byte {
	t.Helper()
	size := beCastRecoveryFileSize(t, file)
	result := make([]byte, size)
	read, err := file.ReadAt(result, 0)
	if size == 0 {
		require.ErrorIs(t, err, io.EOF)
	} else {
		require.NoError(t, err)
	}
	require.Equal(t, len(result), read)
	return result
}

type beCastChangingRecoveryFile struct {
	*os.File
	originalSize int64
	endSeeks     int
}

type beCastOrderedRecoveryFile struct {
	*os.File
	operations []string
}

func (this *beCastOrderedRecoveryFile) Write(value []byte) (int, error) {
	this.operations = append(this.operations, "write")
	return this.File.Write(value)
}

func (this *beCastOrderedRecoveryFile) Sync() error {
	this.operations = append(this.operations, "sync")
	return this.File.Sync()
}

func (this *beCastChangingRecoveryFile) Seek(offset int64, whence int) (int64, error) {
	if offset == 0 && whence == io.SeekEnd {
		this.endSeeks++
		if this.endSeeks == 2 {
			if _, err := this.File.WriteAt([]byte{0}, this.originalSize); err != nil {
				return 0, err
			}
		}
	}
	return this.File.Seek(offset, whence)
}
