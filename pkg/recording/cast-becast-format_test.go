package recording

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
)

func TestBECastHeaderRoundTrip(t *testing.T) {
	header := beCastTestHeader()
	unit, err := encodeBECastHeader(header)
	require.NoError(t, err)
	requireBECastUnitBodySize(t, unit, castBECastHeaderBodySize)

	decoded, err := decodeBECastHeader(unit)
	require.NoError(t, err)
	require.Equal(t, header, decoded)

	unit[castBECastUnitPrefixSize+52] ^= 0xff
	require.Equal(t, header.PublicKey, decoded.PublicKey)
}

func TestBECastChunkRoundTrip(t *testing.T) {
	recordingId := beCastTestId()
	producerId := beCastTestProducerId()
	ciphertext := []byte{0x80, 0x01, 0x7f, 0xfe, 0x55}
	chunk := audit.SessionRecordingBECastChunk{
		FormatVersion:    castBECastFormatVersion,
		FinalStatus:      2,
		RecordingId:      recordingId,
		ProducerId:       producerId,
		Sequence:         17,
		PreviousUnitHash: beCastTestHash(1),
		PlaintextOffset:  4096,
		PlaintextLength:  512,
		CiphertextLength: uint32(len(ciphertext)),
		CiphertextHash:   hashBECastCiphertext(ciphertext),
		ContentHashState: beCastTestHash(65),
		Signature:        beCastTestBytes(64, 97),
	}
	unit, err := encodeBECastChunk(chunk, ciphertext)
	require.NoError(t, err)
	requireBECastUnitBodySize(t, unit, castBECastChunkDescriptorSize+len(ciphertext))

	decoded, decodedCiphertext, err := decodeBECastChunk(unit, recordingId, producerId)
	require.NoError(t, err)
	require.Equal(t, chunk, decoded)
	require.Equal(t, ciphertext, decodedCiphertext)

	unit[castBECastUnitPrefixSize+castBECastChunkDescriptorSize] ^= 0xff
	require.Equal(t, ciphertext, decodedCiphertext)
}

func TestBECastSealRoundTrip(t *testing.T) {
	recordingId := beCastTestId()
	producerId := beCastTestProducerId()
	seal := beCastTestSeal()
	unit, err := encodeBECastSeal(seal)
	require.NoError(t, err)
	requireBECastUnitBodySize(t, unit, castBECastSealBodySize)

	decoded, err := decodeBECastSeal(unit, recordingId, producerId)
	require.NoError(t, err)
	require.Equal(t, seal, decoded)
}

func TestBECastWireConstantsAndBodySizes(t *testing.T) {
	require.Equal(t, []byte{0x89, 'B', 'E', 'C', 'A', 'S', 'T', '\n'}, []byte(castBECastFileMagic))
	require.Equal(t, 217, castBECastHeaderBodySize)
	require.Equal(t, 194, castBECastChunkDescriptorSize)
	require.Equal(t, 226, castBECastSealBodySize)
	require.Equal(t, 256<<10, DefaultBECastChunkPlaintextTarget)
	require.Equal(t, MaximumCastLineBytes+1, MaximumBECastChunkPlaintext)
	require.Equal(t, 2<<20, MaximumBECastCiphertext)
	require.Equal(t, 1<<18, DefaultMaximumBECastChunks)
	require.Equal(t, int64(32<<30), DefaultMaximumBECastBytes)
}

func TestBECastEncodeRejectsIllegalFixedLengths(t *testing.T) {
	header := beCastTestHeader()
	header.PublicKey = header.PublicKey[:50]
	_, err := encodeBECastHeader(header)
	require.ErrorContains(t, err, "identity size")

	header = beCastTestHeader()
	header.RecipientFingerprint = header.RecipientFingerprint[:49]
	_, err = encodeBECastHeader(header)
	require.ErrorContains(t, err, "identity size")

	header = beCastTestHeader()
	header.Signature = header.Signature[:63]
	_, err = encodeBECastHeader(header)
	require.ErrorContains(t, err, "identity size")

	chunk := audit.SessionRecordingBECastChunk{CiphertextLength: 1, Signature: make([]byte, 64)}
	_, err = encodeBECastChunk(chunk, nil)
	require.ErrorContains(t, err, "ciphertext has 0 bytes instead of 1")
	chunk.Signature = chunk.Signature[:63]
	chunk.CiphertextHash = hashBECastCiphertext([]byte{0})
	_, err = encodeBECastChunk(chunk, []byte{0})
	require.ErrorContains(t, err, "signature size")

	chunk.Signature = make([]byte, 64)
	chunk.CiphertextHash = audit.SessionRecordingHash{}
	_, err = encodeBECastChunk(chunk, []byte{0})
	require.ErrorContains(t, err, "ciphertext hash mismatch")

	_, err = encodeBECastSeal(audit.SessionRecordingBECastSeal{Signature: make([]byte, 63)})
	require.ErrorContains(t, err, "signature size")
}

func TestBECastDecodeRejectsCorruption(t *testing.T) {
	unit, err := encodeBECastHeader(beCastTestHeader())
	require.NoError(t, err)
	crcOffset := castBECastUnitPrefixSize + castBECastHeaderBodySize

	tests := map[string]func([]byte){
		"body": func(value []byte) {
			value[castBECastUnitPrefixSize] ^= 0x01
		},
		"CRC": func(value []byte) {
			value[crcOffset] ^= 0x01
		},
		"commit": func(value []byte) {
			value[crcOffset+4] ^= 0x01
		},
		"unit magic": func(value []byte) {
			value[0] ^= 0x01
		},
		"flags": func(value []byte) {
			value[5] = 1
		},
		"reserved": func(value []byte) {
			value[7] = 1
		},
		"body length": func(value []byte) {
			value[11] ^= 0x01
		},
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			corrupted := append([]byte(nil), unit...)
			corrupt(corrupted)
			_, err := decodeBECastHeader(corrupted)
			require.Error(t, err)
		})
	}
}

func TestBECastDecodeRejectsWrongTypeAndTrailingBytes(t *testing.T) {
	unit, err := encodeBECastHeader(beCastTestHeader())
	require.NoError(t, err)

	wrongType := append([]byte(nil), unit...)
	wrongType[4] = castBECastChunkUnitType
	_, err = decodeBECastHeader(wrongType)
	require.ErrorContains(t, err, "type 2 instead of 1")

	trailing := append(append([]byte(nil), unit...), 0)
	_, err = decodeBECastHeader(trailing)
	require.ErrorContains(t, err, "instead of declared size")
}

func TestBECastDecodeRejectsIllegalBodySizes(t *testing.T) {
	_, err := decodeBECastHeader(encodeBECastUnit(castBECastHeaderUnitType, make([]byte, castBECastHeaderBodySize-1)))
	require.ErrorContains(t, err, "header body has 216 bytes instead of 217")

	_, _, err = decodeBECastChunk(encodeBECastUnit(castBECastChunkUnitType, make([]byte, castBECastChunkDescriptorSize-1)), uuid.Nil, audit.ProducerId{})
	require.ErrorContains(t, err, "fewer than descriptor size")

	chunkBody := make([]byte, castBECastChunkDescriptorSize)
	binary.BigEndian.PutUint32(chunkBody[54:], 1)
	_, _, err = decodeBECastChunk(encodeBECastUnit(castBECastChunkUnitType, chunkBody), uuid.Nil, audit.ProducerId{})
	require.ErrorContains(t, err, "body has 194 bytes instead of 195")

	_, err = decodeBECastSeal(encodeBECastUnit(castBECastSealUnitType, make([]byte, castBECastSealBodySize-1)), uuid.Nil, audit.ProducerId{})
	require.ErrorContains(t, err, "seal body has 225 bytes instead of 226")
}

func TestBECastStatusConversions(t *testing.T) {
	for status, encoded := range map[CastStatus]uint8{
		CastStatusCompleted:  1,
		CastStatusFailed:     2,
		CastStatusIncomplete: 3,
	} {
		actualEncoded, err := castBECastStatus(status)
		require.NoError(t, err)
		require.Equal(t, encoded, actualEncoded)
		actualStatus, err := castStatusFromBECast(encoded)
		require.NoError(t, err)
		require.Equal(t, status, actualStatus)
	}
	_, err := castBECastStatus("unknown")
	require.Error(t, err)
	_, err = castStatusFromBECast(0)
	require.Error(t, err)
}

func TestBECastHeaderUnitGoldenHash(t *testing.T) {
	unit, err := encodeBECastHeader(beCastTestHeader())
	require.NoError(t, err)
	digest := sha256.Sum256(unit)
	require.Equal(t, "c0c9b2cea53c9ba944f8324b3c9712c4206dea511ed41479c3a4e7e847686b03", hex.EncodeToString(digest[:]))
}

func TestBECastChunkUnitGoldenHash(t *testing.T) {
	ciphertext := []byte{0x80, 0x01, 0x7f, 0xfe, 0x55}
	unit, err := encodeBECastChunk(audit.SessionRecordingBECastChunk{
		FormatVersion:    castBECastFormatVersion,
		FinalStatus:      2,
		RecordingId:      beCastTestId(),
		ProducerId:       beCastTestProducerId(),
		Sequence:         17,
		PreviousUnitHash: beCastTestHash(1),
		PlaintextOffset:  4096,
		PlaintextLength:  512,
		CiphertextLength: uint32(len(ciphertext)),
		CiphertextHash:   hashBECastCiphertext(ciphertext),
		ContentHashState: beCastTestHash(65),
		Signature:        beCastTestBytes(64, 97),
	}, ciphertext)
	require.NoError(t, err)
	digest := sha256.Sum256(unit)
	require.Equal(t, "12269be5c8391839c29bf0de4fa09657f10a1e29d38d2410b0373a56769e8950", hex.EncodeToString(digest[:]))
}

func TestBECastSealUnitGoldenHash(t *testing.T) {
	unit, err := encodeBECastSeal(beCastTestSeal())
	require.NoError(t, err)
	digest := sha256.Sum256(unit)
	require.Equal(t, "c6fb52d78acdaed9b7da9b53f33bd8a1569861be98191c8afaba62d8f49b40f1", hex.EncodeToString(digest[:]))
}

func requireBECastUnitBodySize(t *testing.T, unit []byte, bodySize int) {
	t.Helper()
	require.Len(t, unit, castBECastUnitPrefixSize+bodySize+castBECastUnitTrailerSize)
	require.Equal(t, uint32(bodySize), binary.BigEndian.Uint32(unit[8:12]))
}

func beCastTestHeader() audit.SessionRecordingBECastHeader {
	return audit.SessionRecordingBECastHeader{
		FormatVersion:        castBECastFormatVersion,
		CastVersion:          3,
		Codec:                castBECastCodec,
		Encryption:           castBECastEncryption,
		RecordingId:          beCastTestId(),
		ProducerId:           beCastTestProducerId(),
		PublicKey:            beCastTestBytes(51, 32),
		RecipientFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Signature:            beCastTestBytes(64, 96),
	}
}

func beCastTestSeal() audit.SessionRecordingBECastSeal {
	return audit.SessionRecordingBECastSeal{
		FormatVersion:        castBECastFormatVersion,
		RecordingId:          beCastTestId(),
		ProducerId:           beCastTestProducerId(),
		Status:               2,
		ChunkCount:           17,
		CastBytes:            8192,
		CiphertextBytes:      9216,
		PrefixBytes:          4096,
		HeaderUnitHash:       beCastTestHash(1),
		LastChunkUnitHash:    beCastTestHash(33),
		CastContentDigest:    beCastTestHash(65),
		CiphertextStreamHash: beCastTestHash(97),
		Signature:            beCastTestBytes(64, 129),
	}
}

func beCastTestId() uuid.UUID {
	return uuid.MustParse("fd70203b-ea19-4288-8ec2-577b623e92d0")
}

func beCastTestProducerId() audit.ProducerId {
	var result audit.ProducerId
	copy(result[:], beCastTestBytes(len(result), 0))
	return result
}

func beCastTestHash(start byte) audit.SessionRecordingHash {
	var result audit.SessionRecordingHash
	copy(result[:], beCastTestBytes(len(result), start))
	return result
}

func beCastTestBytes(length int, start byte) []byte {
	result := make([]byte, length)
	for i := range result {
		result[i] = start + byte(i)
	}
	return result
}
