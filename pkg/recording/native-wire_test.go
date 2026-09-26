package recording

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestNativeRecordingWireSchemas(t *testing.T) {
	now := nativeformat.TimestampOf(time.Unix(1000, 123).UTC())
	header := nativeRecordingHeader{
		Version:     1,
		Encryption:  1,
		RecordingId: [16]byte{1},
		ProducerId:  [32]byte{2},
		PublicKey:   []byte("test-public-key"),
		StartedAt:   now,
		Recipient:   "test-recipient",
		Signature:   bytes.Repeat([]byte{3}, 64),
	}
	headerBytes, err := nativeformat.Marshal(header, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	decodedHeader, err := nativeformat.Unmarshal[nativeRecordingHeader](headerBytes, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, header, decodedHeader)
	_, err = nativeformat.Unmarshal[nativeRecordingHeader]([]byte{0xa1, 0x09, 0x01}, nativeformat.MaxMetadataPayload)
	require.Error(t, err, "unknown recording header fields must fail closed")

	chunk := nativeRecordingChunk{
		Sequence: 1, PreviousUnitHash: [32]byte{4}, DecodedLength: 3,
		StoredPayload: []byte{5, 6, 7}, StoredHash: [32]byte{8},
		CastHashState: [32]byte{9}, CastHashBytes: 128, Signature: bytes.Repeat([]byte{10}, 64), LastElapsedNanos: new(uint64),
	}
	chunkBytes, err := nativeformat.Marshal(chunk, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	decodedChunk, err := nativeformat.Unmarshal[nativeRecordingChunk](chunkBytes, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	require.Equal(t, chunk, decodedChunk)
	chunk.DecodedLength = nativeformat.MaxRecordingDecodedChunk + 1
	_, err = nativeformat.Marshal(chunk, nativeformat.MaxRecordingChunkPayload)
	require.Error(t, err)
	badChunkBytes, err := nativeformat.Marshal(map[uint64]any{
		1: uint64(1), 2: [32]byte{}, 3: uint64(nativeformat.MaxRecordingDecodedChunk + 1),
		4: []byte{5, 6, 7}, 5: [32]byte{}, 6: [32]byte{}, 7: uint64(128), 8: bytes.Repeat([]byte{10}, 64), 14: uint64(0),
	}, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	_, err = nativeformat.Unmarshal[nativeRecordingChunk](badChunkBytes, nativeformat.MaxRecordingChunkPayload)
	require.Error(t, err)
	chunk.DecodedLength = 3

	seal := nativeRecordingSeal{
		Status: 1, ChunkCount: 1, LastUnitHash: [32]byte{11}, ContentHash: [32]byte{12},
		CastDigest: [32]byte{13}, CastSignature: bytes.Repeat([]byte{14}, 64),
		CastBytes: 128, EndedAt: now, Signature: bytes.Repeat([]byte{15}, 64),
	}
	sealBytes, err := nativeformat.Marshal(seal, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	decodedSeal, err := nativeformat.Unmarshal[nativeRecordingSeal](sealBytes, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, seal, decodedSeal)
}
