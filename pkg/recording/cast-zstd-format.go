package recording

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	castZstdFormatVersion = 1
	castZstdCodec         = 1

	castZstdHeaderSkippableId = 8
	castZstdChunkSkippableId  = 9
	castZstdSealSkippableId   = 10

	castZstdHeaderPayloadSize = 166
	castZstdChunkPayloadSize  = 153
	castZstdSealPayloadSize   = 226
	castZstdSealFrameSize     = 8 + castZstdSealPayloadSize

	castZstdFrameHashDomain  = "BIFROEST-SESSION-RECORDING-ZSTD-FRAME-HASH/v1\x00"
	castZstdUnitHashDomain   = "BIFROEST-SESSION-RECORDING-ZSTD-UNIT-HASH/v1\x00"
	castZstdStreamHashDomain = "BIFROEST-SESSION-RECORDING-ZSTD-CAST-STREAM-HASH/v1\x00"

	DefaultCastZstdChunkSize     = 256 << 10
	MaximumCastZstdChunkSize     = MaximumCastLineBytes + 1
	MaximumCastZstdFrameSize     = 2 << 20
	DefaultMaximumCastZstdChunks = 1 << 18
	castZstdWindowSize           = 2 << 20
	maximumCastZstdBlocks        = 16
)

const zstdSkippableMagicBase = uint32(0x184d2a50)

type CastZstdSummary struct {
	RecordingId Id
	ProducerId  audit.ProducerId
	Status      CastStatus
	ChunkCount  uint64
	CastBytes   uint64
	ZstdBytes   uint64
	Digest      CastDigest
	StreamHash  audit.SessionRecordingHash
}

func encodeCastZstdHeader(value audit.SessionRecordingZstdHeader) ([]byte, error) {
	if len(value.PublicKey) != 51 || len(value.Signature) != 64 {
		return nil, errors.System.Newf("illegal Cast Zstandard header identity size")
	}
	payload := make([]byte, castZstdHeaderPayloadSize)
	payload[0] = value.FormatVersion
	payload[1] = value.CastVersion
	payload[2] = value.Codec
	copy(payload[3:], value.RecordingId[:])
	copy(payload[19:], value.ProducerId[:])
	copy(payload[51:], value.PublicKey)
	copy(payload[102:], value.Signature)
	return encodeZstdSkippableFrame(castZstdHeaderSkippableId, payload), nil
}

func decodeCastZstdHeader(payload []byte) (audit.SessionRecordingZstdHeader, error) {
	if len(payload) != castZstdHeaderPayloadSize {
		return audit.SessionRecordingZstdHeader{}, errors.System.Newf("cast Zstandard header payload has %d bytes instead of %d", len(payload), castZstdHeaderPayloadSize)
	}
	value := audit.SessionRecordingZstdHeader{
		FormatVersion: payload[0],
		CastVersion:   payload[1],
		Codec:         payload[2],
		RecordingId:   uuid.UUID(payload[3:19]),
		ProducerId:    audit.ProducerId(payload[19:51]),
		PublicKey:     append([]byte(nil), payload[51:102]...),
		Signature:     append([]byte(nil), payload[102:166]...),
	}
	return value, nil
}

func encodeCastZstdChunk(value audit.SessionRecordingZstdChunk) ([]byte, error) {
	if len(value.Signature) != 64 {
		return nil, errors.System.Newf("illegal Cast Zstandard chunk signature size")
	}
	payload := make([]byte, castZstdChunkPayloadSize)
	payload[0] = value.FormatVersion
	binary.BigEndian.PutUint64(payload[1:], value.Sequence)
	copy(payload[9:], value.PreviousUnitHash[:])
	binary.BigEndian.PutUint64(payload[41:], value.PlaintextOffset)
	binary.BigEndian.PutUint32(payload[49:], value.PlaintextLength)
	binary.BigEndian.PutUint32(payload[53:], value.FrameLength)
	copy(payload[57:], value.FrameHash[:])
	copy(payload[89:], value.Signature)
	return encodeZstdSkippableFrame(castZstdChunkSkippableId, payload), nil
}

func decodeCastZstdChunk(payload []byte, recordingId uuid.UUID, producerId audit.ProducerId) (audit.SessionRecordingZstdChunk, error) {
	if len(payload) != castZstdChunkPayloadSize {
		return audit.SessionRecordingZstdChunk{}, errors.System.Newf("cast Zstandard chunk payload has %d bytes instead of %d", len(payload), castZstdChunkPayloadSize)
	}
	value := audit.SessionRecordingZstdChunk{
		FormatVersion:   payload[0],
		RecordingId:     recordingId,
		ProducerId:      producerId,
		Sequence:        binary.BigEndian.Uint64(payload[1:]),
		PlaintextOffset: binary.BigEndian.Uint64(payload[41:]),
		PlaintextLength: binary.BigEndian.Uint32(payload[49:]),
		FrameLength:     binary.BigEndian.Uint32(payload[53:]),
		Signature:       append([]byte(nil), payload[89:153]...),
	}
	copy(value.PreviousUnitHash[:], payload[9:41])
	copy(value.FrameHash[:], payload[57:89])
	return value, nil
}

func encodeCastZstdSeal(value audit.SessionRecordingZstdSeal) ([]byte, error) {
	if len(value.Signature) != 64 {
		return nil, errors.System.Newf("illegal Cast Zstandard seal signature size")
	}
	payload := make([]byte, castZstdSealPayloadSize)
	payload[0] = value.FormatVersion
	payload[1] = value.Status
	binary.BigEndian.PutUint64(payload[2:], value.ChunkCount)
	binary.BigEndian.PutUint64(payload[10:], value.CastBytes)
	binary.BigEndian.PutUint64(payload[18:], value.ZstdBytes)
	binary.BigEndian.PutUint64(payload[26:], value.PrefixBytes)
	copy(payload[34:], value.HeaderUnitHash[:])
	copy(payload[66:], value.LastChunkUnitHash[:])
	copy(payload[98:], value.CastContentDigest[:])
	copy(payload[130:], value.CastStreamHash[:])
	copy(payload[162:], value.Signature)
	return encodeZstdSkippableFrame(castZstdSealSkippableId, payload), nil
}

func decodeCastZstdSeal(payload []byte, recordingId uuid.UUID, producerId audit.ProducerId) (audit.SessionRecordingZstdSeal, error) {
	if len(payload) != castZstdSealPayloadSize {
		return audit.SessionRecordingZstdSeal{}, errors.System.Newf("cast Zstandard seal payload has %d bytes instead of %d", len(payload), castZstdSealPayloadSize)
	}
	value := audit.SessionRecordingZstdSeal{
		FormatVersion: payload[0],
		RecordingId:   recordingId,
		ProducerId:    producerId,
		Status:        payload[1],
		ChunkCount:    binary.BigEndian.Uint64(payload[2:]),
		CastBytes:     binary.BigEndian.Uint64(payload[10:]),
		ZstdBytes:     binary.BigEndian.Uint64(payload[18:]),
		PrefixBytes:   binary.BigEndian.Uint64(payload[26:]),
		Signature:     append([]byte(nil), payload[162:226]...),
	}
	copy(value.HeaderUnitHash[:], payload[34:66])
	copy(value.LastChunkUnitHash[:], payload[66:98])
	copy(value.CastContentDigest[:], payload[98:130])
	copy(value.CastStreamHash[:], payload[130:162])
	return value, nil
}

func encodeZstdSkippableFrame(id int, payload []byte) []byte {
	result := make([]byte, 8+len(payload))
	binary.LittleEndian.PutUint32(result, zstdSkippableMagicBase|uint32(id))
	binary.LittleEndian.PutUint32(result[4:], uint32(len(payload)))
	copy(result[8:], payload)
	return result
}

func hashDomainValues(domain string, values ...[]byte) audit.SessionRecordingHash {
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(domain))
	for _, value := range values {
		_, _ = hasher.Write(value)
	}
	var result audit.SessionRecordingHash
	copy(result[:], hasher.Sum(nil))
	return result
}

func castZstdStatus(status CastStatus) (uint8, error) {
	switch status {
	case CastStatusCompleted:
		return 1, nil
	case CastStatusFailed:
		return 2, nil
	case CastStatusIncomplete:
		return 3, nil
	default:
		return 0, errors.System.Newf("illegal Cast Zstandard status %q", status)
	}
}

func castStatusFromZstd(value uint8) (CastStatus, error) {
	switch value {
	case 1:
		return CastStatusCompleted, nil
	case 2:
		return CastStatusFailed, nil
	case 3:
		return CastStatusIncomplete, nil
	default:
		return "", errors.System.Newf("illegal Cast Zstandard status %d", value)
	}
}
