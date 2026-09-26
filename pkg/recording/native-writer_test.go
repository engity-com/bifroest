package recording

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestNativeRecordingWriterRoundTrip(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "clear"
		if encrypted {
			name = "age"
		}
		t.Run(name, func(t *testing.T) {
			identity, castHeader, metadata := castTestValues(t, true)
			var recipient *bfcrypto.AgeSshRecipient
			var identities *bfcrypto.AgeSshIdentities
			if encrypted {
				recipient, identities = newBECastTestEncryption(t)
			}
			var container, expected bytes.Buffer
			writer, err := NewNativeRecordingWriter(&container, identity, recipient, castHeader, metadata, 128<<10, NativeRecordingWriterLimits{})
			require.NoError(t, err)
			cast, err := NewCastWriter(&expected, identity, castHeader, metadata)
			require.NoError(t, err)
			require.NoError(t, writer.Flush())
			checkpoint, err := padCastForSha256Checkpoint(cast)
			require.NoError(t, err)
			headPayload, err := writer.Checkpoint()
			require.NoError(t, err)
			var headerUnit nativeformat.Unit
			headerUnit, end, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(container.Bytes()), int64(len(nativeformat.RecordingMagic)), int64(container.Len()), nativeformat.MaxMetadataPayload)
			require.NoError(t, err)
			require.False(t, tail)
			head, err := VerifyNativeRecordingHead(headPayload, headerUnit.Payload)
			require.NoError(t, err)
			require.Equal(t, uint64(container.Len()), head.PrefixBytes)
			require.Equal(t, checkpoint.State, head.CastHashState)
			require.Equal(t, checkpoint.Bytes, head.CastHashBytes)
			first, firstEnd, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(container.Bytes()), end, int64(container.Len()), nativeformat.MaxRecordingChunkPayload)
			require.NoError(t, err)
			require.False(t, tail)
			require.Equal(t, int64(head.PrefixBytes), firstEnd)
			require.Equal(t, nativeformat.ContentUnit, first.Type)
			require.Equal(t, nativeRecordingHash(nativeRecordingUnitDomain, container.Bytes()[end:firstEnd]), head.LastUnitHash)
			_, err = VerifyNativeRecordingOuter(bytes.NewReader(container.Bytes()), int64(container.Len()), NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			require.Error(t, err, "active prefix has no seal")

			data := append(bytes.Repeat([]byte("x"), MaximumOutputEventBytes-1), []byte("\xe2\x98\x83\n\xff")...)
			require.NoError(t, writer.WriteOutput(111*time.Millisecond, OutputStreamTerminal, data))
			require.NoError(t, cast.WriteOutput(111*time.Millisecond, OutputStreamTerminal, data))
			data[0] = 'z' // Pending CBOR events must own their raw bytes.
			require.NoError(t, writer.WriteResize(120*time.Millisecond, 93, 24))
			require.NoError(t, cast.WriteResize(120*time.Millisecond, 93, 24))
			require.NoError(t, writer.WriteMarker(123*time.Millisecond, "ready\u2028"))
			require.NoError(t, cast.WriteMarker(123*time.Millisecond, "ready\u2028"))
			secondHead, err := writer.Checkpoint()
			require.NoError(t, err)
			checkpoint, err = padCastForSha256Checkpoint(cast)
			require.NoError(t, err)
			head, err = VerifyNativeRecordingHead(secondHead, headerUnit.Payload)
			require.NoError(t, err)
			require.Equal(t, uint64(container.Len()), head.PrefixBytes)
			require.Equal(t, uint64(2), head.ChunkCount)
			require.Equal(t, checkpoint.State, head.CastHashState)
			require.Equal(t, checkpoint.Bytes, head.CastHashBytes)

			exit := uint32(7)
			result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}
			summary, err := writer.Seal(time.Second, result, &exit)
			require.NoError(t, err)
			digest, err := cast.Seal(time.Second, result, &exit)
			require.NoError(t, err)
			require.Equal(t, digest, summary.Digest)
			require.Equal(t, uint64(expected.Len()), summary.CastBytes)
			require.Equal(t, uint64(container.Len()), summary.Bytes)
			require.Equal(t, uint64(3), summary.ChunkCount)
			if encrypted {
				require.Equal(t, recipient.Fingerprint(), summary.RecipientFingerprint)
			} else {
				require.Empty(t, summary.RecipientFingerprint)
			}
			require.Error(t, writer.WriteMarker(time.Second, "late"))
			_, err = writer.Checkpoint()
			require.Error(t, err)

			verification, err := VerifyNativeRecordingOuter(bytes.NewReader(container.Bytes()), int64(container.Len()), NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			require.NoError(t, err)
			require.True(t, verification.Trusted)
			groups := make([][]byte, 0, summary.ChunkCount)
			reader := bytes.NewReader(container.Bytes())
			offset := end
			for index := uint64(0); index < summary.ChunkCount; index++ {
				unit, next, partial, readErr := nativeformat.ReadUnitAt(reader, offset, int64(container.Len()), nativeformat.MaxRecordingChunkPayload)
				require.NoError(t, readErr)
				require.False(t, partial)
				require.Equal(t, nativeformat.ContentUnit, unit.Type)
				chunk, readErr := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
				require.NoError(t, readErr)
				require.Equal(t, sha256.Sum256(chunk.StoredPayload), chunk.StoredHash)
				if index == summary.ChunkCount-1 {
					require.Zero(t, chunk.CastHashBytes)
					require.Equal(t, uint8(1), chunk.FinalStatus)
					require.Equal(t, (*[32]byte)(&verification.Seal.CastDigest), chunk.CastDigest)
					require.Equal(t, verification.Seal.CastSignature, chunk.CastSignature)
					require.Equal(t, &verification.Seal.CastBytes, chunk.CastBytes)
					require.Equal(t, &verification.Seal.EndedAt, chunk.EndedAt)
				} else {
					require.NotZero(t, chunk.CastHashBytes)
					require.Nil(t, chunk.CastDigest)
				}
				decoded, readErr := nativeformat.DecodeStoredPayload(chunk.StoredPayload, identities, verification.Header.Recipient, nativeRecordingPayloadLimits)
				require.NoError(t, readErr)
				require.Equal(t, int(chunk.DecodedLength), len(decoded))
				require.Equal(t, uint8(5), decoded[0]>>5, "decoded chunk is a CBOR map, not a Cast line")
				_, readErr = decodeNativeRecordingEvents(decoded)
				require.NoError(t, readErr)
				groups = append(groups, decoded)
				offset = next
			}
			require.Equal(t, nativeRecordingHash(nativeRecordingContentDomain, container.Bytes()[:offset]), verification.Seal.ContentHash)
			actual, err := RenderNativeRecordingCast(groups, verification.Header, verification.Seal, int64(expected.Len()))
			require.NoError(t, err)
			require.Equal(t, expected.Bytes(), actual)
			_, err = RenderNativeRecordingCast(groups[:len(groups)-1], verification.Header, verification.Seal, int64(expected.Len()))
			require.Error(t, err)
		})
	}
}

type nativeWriterFailOutput struct {
	bytes.Buffer
	fail, short bool
}

func (w *nativeWriterFailOutput) Write(value []byte) (int, error) {
	if w.fail {
		return 0, io.ErrClosedPipe
	}
	if w.short {
		return w.Buffer.Write(value[:len(value)-1])
	}
	return w.Buffer.Write(value)
}

func TestNativeRecordingWriterPoisonsFailedChunkAndEnforcesLimits(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	for _, short := range []bool{false, true} {
		output := &nativeWriterFailOutput{}
		writer, err := NewNativeRecordingWriter(output, identity, nil, header, metadata, 256, NativeRecordingWriterLimits{MaximumChunks: 2})
		require.NoError(t, err)
		output.fail, output.short = !short, short
		require.Error(t, writer.Flush())
		output.fail, output.short = false, false
		before := output.Len()
		require.Error(t, writer.WriteOutput(time.Second, OutputStreamTerminal, []byte("cannot continue")))
		require.Equal(t, before, output.Len())
		_, err = writer.Checkpoint()
		require.Error(t, err)
	}

	var small bytes.Buffer
	_, err := NewNativeRecordingWriter(&small, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{MaximumContainerBytes: 100})
	require.Error(t, err)
	require.Zero(t, small.Len())
	_, err = NewNativeRecordingWriter(&small, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{MaximumCastBytes: 1})
	require.Error(t, err)
	require.Zero(t, small.Len())
	_, err = NewNativeRecordingWriter(&small, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{MaximumCastBytes: DefaultMaximumCastBytes + 1})
	require.Error(t, err)
	require.Zero(t, small.Len())
}

func TestNativeRecordingWriterAutoFlushAndIncompleteResult(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var container, expected bytes.Buffer
	writer, err := NewNativeRecordingWriter(&container, identity, nil, header, metadata, 1, NativeRecordingWriterLimits{MaximumChunks: 4})
	require.NoError(t, err)
	cast, err := NewCastWriter(&expected, identity, header, metadata)
	require.NoError(t, err)
	_, err = padCastForSha256Checkpoint(cast)
	require.NoError(t, err)
	require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("x")))
	require.NoError(t, cast.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("x")))
	_, err = padCastForSha256Checkpoint(cast)
	require.NoError(t, err)
	require.NoError(t, writer.WriteMarker(2*time.Millisecond, "checkpoint"))
	require.NoError(t, cast.WriteMarker(2*time.Millisecond, "checkpoint"))
	_, err = padCastForSha256Checkpoint(cast)
	require.NoError(t, err)
	result := CastResult{Status: CastStatusIncomplete, EndedAt: metadata.StartedAt.Add(time.Second), Reason: startupRecoveryReason}
	summary, err := writer.Seal(time.Second, result, nil)
	require.NoError(t, err)
	digest, err := cast.Seal(time.Second, result, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(4), summary.ChunkCount)
	require.Equal(t, digest, summary.Digest)
	verified, err := VerifyNativeRecordingOuter(bytes.NewReader(container.Bytes()), int64(container.Len()), NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	groups := make([][]byte, 0, summary.ChunkCount)
	offset := int64(len(nativeformat.RecordingMagic))
	for index := uint64(0); index < summary.ChunkCount+1; index++ {
		unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(container.Bytes()), offset, int64(container.Len()), nativeformat.MaxRecordingChunkPayload)
		require.NoError(t, err)
		require.False(t, tail)
		if index != 0 {
			chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
			require.NoError(t, err)
			decoded, err := nativeformat.DecodeStoredPayload(chunk.StoredPayload, nil, "", nativeRecordingPayloadLimits)
			require.NoError(t, err)
			groups = append(groups, decoded)
		}
		offset = next
	}
	actual, err := RenderNativeRecordingCast(groups, verified.Header, verified.Seal, int64(expected.Len()))
	require.NoError(t, err)
	require.Equal(t, expected.Bytes(), actual)

	var limited bytes.Buffer
	noFinalSlot, err := NewNativeRecordingWriter(&limited, identity, nil, header, metadata, 1, NativeRecordingWriterLimits{MaximumChunks: 1})
	require.NoError(t, err)
	require.Error(t, noFinalSlot.WriteOutput(time.Millisecond, OutputStreamTerminal, []byte("cannot fit")))
	_, err = noFinalSlot.Seal(time.Second, result, nil)
	require.Error(t, err, "failed append cannot silently drop events and seal")
}
