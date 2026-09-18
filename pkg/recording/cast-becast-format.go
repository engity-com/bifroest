package recording

import (
	"encoding/binary"
	"hash/crc32"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	castBECastFormatVersion = 1
	castBECastCodec         = 1
	castBECastEncryption    = 1

	castBECastFileMagic    = "\x89BECAST\n"
	castBECastUnitMagic    = "BECU"
	castBECastCommitMarker = "BECOMMIT"

	castBECastHeaderUnitType = 1
	castBECastChunkUnitType  = 2
	castBECastSealUnitType   = 3

	castBECastUnitPrefixSize  = 12
	castBECastUnitTrailerSize = 12

	castBECastHeaderBodySize      = 217
	castBECastChunkDescriptorSize = 194
	castBECastSealBodySize        = 226
	castBECastSealUnitSize        = castBECastUnitPrefixSize + castBECastSealBodySize + castBECastUnitTrailerSize

	castBECastCiphertextHashDomain       = "BIFROEST-SESSION-RECORDING-BECAST-CIPHERTEXT-HASH/v1\x00"
	castBECastUnitHashDomain             = "BIFROEST-SESSION-RECORDING-BECAST-UNIT-HASH/v1\x00"
	castBECastCiphertextStreamHashDomain = "BIFROEST-SESSION-RECORDING-BECAST-CIPHERTEXT-STREAM-HASH/v1\x00"

	DefaultBECastChunkPlaintextTarget = 256 << 10
	MaximumBECastChunkPlaintext       = MaximumCastLineBytes + 1
	MaximumBECastCiphertext           = 2 << 20
	DefaultMaximumBECastChunks        = 1 << 18
)

var castBECastCRC32CTable = crc32.MakeTable(crc32.Castagnoli)

type BECastSummary struct {
	RecordingId          Id
	ProducerId           audit.ProducerId
	RecipientFingerprint string
	Status               CastStatus
	ChunkCount           uint64
	CastBytes            uint64
	CiphertextBytes      uint64
	Digest               CastDigest
	CiphertextStreamHash audit.SessionRecordingHash
}

func encodeBECastHeader(value audit.SessionRecordingBECastHeader) ([]byte, error) {
	if len(value.PublicKey) != 51 || len(value.RecipientFingerprint) != 50 || len(value.Signature) != 64 {
		return nil, errors.System.Newf("illegal BECast header identity size")
	}
	body := make([]byte, castBECastHeaderBodySize)
	body[0] = value.FormatVersion
	body[1] = value.CastVersion
	body[2] = value.Codec
	body[3] = value.Encryption
	copy(body[4:], value.RecordingId[:])
	copy(body[20:], value.ProducerId[:])
	copy(body[52:], value.PublicKey)
	copy(body[103:], value.RecipientFingerprint)
	copy(body[153:], value.Signature)
	return encodeBECastUnit(castBECastHeaderUnitType, body), nil
}

func decodeBECastHeader(unit []byte) (audit.SessionRecordingBECastHeader, error) {
	body, err := decodeBECastUnit(unit, castBECastHeaderUnitType)
	if err != nil {
		return audit.SessionRecordingBECastHeader{}, err
	}
	if len(body) != castBECastHeaderBodySize {
		return audit.SessionRecordingBECastHeader{}, errors.System.Newf("BECast header body has %d bytes instead of %d", len(body), castBECastHeaderBodySize)
	}
	return audit.SessionRecordingBECastHeader{
		FormatVersion:        body[0],
		CastVersion:          body[1],
		Codec:                body[2],
		Encryption:           body[3],
		RecordingId:          uuid.UUID(body[4:20]),
		ProducerId:           audit.ProducerId(body[20:52]),
		PublicKey:            append([]byte(nil), body[52:103]...),
		RecipientFingerprint: string(body[103:153]),
		Signature:            append([]byte(nil), body[153:217]...),
	}, nil
}

func encodeBECastChunk(value audit.SessionRecordingBECastChunk, ciphertext []byte) ([]byte, error) {
	if len(value.Signature) != 64 {
		return nil, errors.System.Newf("illegal BECast chunk signature size")
	}
	if uint64(len(ciphertext)) != uint64(value.CiphertextLength) {
		return nil, errors.System.Newf("BECast chunk ciphertext has %d bytes instead of %d", len(ciphertext), value.CiphertextLength)
	}
	if value.CiphertextHash != hashBECastCiphertext(ciphertext) {
		return nil, errors.System.Newf("BECast chunk ciphertext hash mismatch")
	}
	body := make([]byte, castBECastChunkDescriptorSize+len(ciphertext))
	body[0] = value.FormatVersion
	body[1] = value.FinalStatus
	binary.BigEndian.PutUint64(body[2:], value.Sequence)
	copy(body[10:], value.PreviousUnitHash[:])
	binary.BigEndian.PutUint64(body[42:], value.PlaintextOffset)
	binary.BigEndian.PutUint32(body[50:], value.PlaintextLength)
	binary.BigEndian.PutUint32(body[54:], value.CiphertextLength)
	copy(body[58:], value.CiphertextHash[:])
	copy(body[90:], value.ContentHashState[:])
	binary.BigEndian.PutUint64(body[122:], value.ContentHashBytes)
	copy(body[130:], value.Signature)
	copy(body[castBECastChunkDescriptorSize:], ciphertext)
	return encodeBECastUnit(castBECastChunkUnitType, body), nil
}

func decodeBECastChunk(unit []byte, recordingId uuid.UUID, producerId audit.ProducerId) (audit.SessionRecordingBECastChunk, []byte, error) {
	body, err := decodeBECastUnit(unit, castBECastChunkUnitType)
	if err != nil {
		return audit.SessionRecordingBECastChunk{}, nil, err
	}
	if len(body) < castBECastChunkDescriptorSize {
		return audit.SessionRecordingBECastChunk{}, nil, errors.System.Newf("BECast chunk body has %d bytes, fewer than descriptor size %d", len(body), castBECastChunkDescriptorSize)
	}
	ciphertextLength := binary.BigEndian.Uint32(body[54:])
	if uint64(len(body)) != uint64(castBECastChunkDescriptorSize)+uint64(ciphertextLength) {
		return audit.SessionRecordingBECastChunk{}, nil, errors.System.Newf("BECast chunk body has %d bytes instead of %d", len(body), uint64(castBECastChunkDescriptorSize)+uint64(ciphertextLength))
	}
	value := audit.SessionRecordingBECastChunk{
		FormatVersion:    body[0],
		FinalStatus:      body[1],
		RecordingId:      recordingId,
		ProducerId:       producerId,
		Sequence:         binary.BigEndian.Uint64(body[2:]),
		PlaintextOffset:  binary.BigEndian.Uint64(body[42:]),
		PlaintextLength:  binary.BigEndian.Uint32(body[50:]),
		CiphertextLength: ciphertextLength,
		ContentHashBytes: binary.BigEndian.Uint64(body[122:]),
		Signature:        append([]byte(nil), body[130:194]...),
	}
	copy(value.PreviousUnitHash[:], body[10:42])
	copy(value.CiphertextHash[:], body[58:90])
	copy(value.ContentHashState[:], body[90:122])
	ciphertext := append([]byte(nil), body[castBECastChunkDescriptorSize:]...)
	if value.CiphertextHash != hashBECastCiphertext(ciphertext) {
		return audit.SessionRecordingBECastChunk{}, nil, errors.System.Newf("BECast chunk ciphertext hash mismatch")
	}
	return value, ciphertext, nil
}

func encodeBECastSeal(value audit.SessionRecordingBECastSeal) ([]byte, error) {
	if len(value.Signature) != 64 {
		return nil, errors.System.Newf("illegal BECast seal signature size")
	}
	body := make([]byte, castBECastSealBodySize)
	body[0] = value.FormatVersion
	body[1] = value.Status
	binary.BigEndian.PutUint64(body[2:], value.ChunkCount)
	binary.BigEndian.PutUint64(body[10:], value.CastBytes)
	binary.BigEndian.PutUint64(body[18:], value.CiphertextBytes)
	binary.BigEndian.PutUint64(body[26:], value.PrefixBytes)
	copy(body[34:], value.HeaderUnitHash[:])
	copy(body[66:], value.LastChunkUnitHash[:])
	copy(body[98:], value.CastContentDigest[:])
	copy(body[130:], value.CiphertextStreamHash[:])
	copy(body[162:], value.Signature)
	return encodeBECastUnit(castBECastSealUnitType, body), nil
}

func decodeBECastSeal(unit []byte, recordingId uuid.UUID, producerId audit.ProducerId) (audit.SessionRecordingBECastSeal, error) {
	body, err := decodeBECastUnit(unit, castBECastSealUnitType)
	if err != nil {
		return audit.SessionRecordingBECastSeal{}, err
	}
	if len(body) != castBECastSealBodySize {
		return audit.SessionRecordingBECastSeal{}, errors.System.Newf("BECast seal body has %d bytes instead of %d", len(body), castBECastSealBodySize)
	}
	value := audit.SessionRecordingBECastSeal{
		FormatVersion:   body[0],
		RecordingId:     recordingId,
		ProducerId:      producerId,
		Status:          body[1],
		ChunkCount:      binary.BigEndian.Uint64(body[2:]),
		CastBytes:       binary.BigEndian.Uint64(body[10:]),
		CiphertextBytes: binary.BigEndian.Uint64(body[18:]),
		PrefixBytes:     binary.BigEndian.Uint64(body[26:]),
		Signature:       append([]byte(nil), body[162:226]...),
	}
	copy(value.HeaderUnitHash[:], body[34:66])
	copy(value.LastChunkUnitHash[:], body[66:98])
	copy(value.CastContentDigest[:], body[98:130])
	copy(value.CiphertextStreamHash[:], body[130:162])
	return value, nil
}

func encodeBECastUnit(unitType uint8, body []byte) []byte {
	result := make([]byte, castBECastUnitPrefixSize+len(body)+castBECastUnitTrailerSize)
	copy(result, castBECastUnitMagic)
	result[4] = unitType
	binary.BigEndian.PutUint32(result[8:], uint32(len(body)))
	copy(result[castBECastUnitPrefixSize:], body)
	crcOffset := castBECastUnitPrefixSize + len(body)
	binary.BigEndian.PutUint32(result[crcOffset:], crc32.Checksum(result[:crcOffset], castBECastCRC32CTable))
	copy(result[crcOffset+4:], castBECastCommitMarker)
	return result
}

func decodeBECastUnit(unit []byte, expectedType uint8) ([]byte, error) {
	minimumSize := castBECastUnitPrefixSize + castBECastUnitTrailerSize
	if len(unit) < minimumSize {
		return nil, errors.System.Newf("BECast unit has %d bytes, fewer than minimum size %d", len(unit), minimumSize)
	}
	if string(unit[:4]) != castBECastUnitMagic {
		return nil, errors.System.Newf("BECast unit magic mismatch")
	}
	if unit[4] != expectedType {
		return nil, errors.System.Newf("BECast unit has type %d instead of %d", unit[4], expectedType)
	}
	if unit[5] != 0 {
		return nil, errors.System.Newf("BECast unit has non-zero flags")
	}
	if binary.BigEndian.Uint16(unit[6:]) != 0 {
		return nil, errors.System.Newf("BECast unit has non-zero reserved value")
	}
	bodyLength := binary.BigEndian.Uint32(unit[8:])
	expectedLength := uint64(castBECastUnitPrefixSize+castBECastUnitTrailerSize) + uint64(bodyLength)
	if uint64(len(unit)) != expectedLength {
		return nil, errors.System.Newf("BECast unit has %d bytes instead of declared size %d", len(unit), expectedLength)
	}
	crcOffset := castBECastUnitPrefixSize + int(bodyLength)
	if string(unit[crcOffset+4:]) != castBECastCommitMarker {
		return nil, errors.System.Newf("BECast unit commit marker mismatch")
	}
	expectedCRC := binary.BigEndian.Uint32(unit[crcOffset:])
	actualCRC := crc32.Checksum(unit[:crcOffset], castBECastCRC32CTable)
	if actualCRC != expectedCRC {
		return nil, errors.System.Newf("BECast unit CRC mismatch")
	}
	return unit[castBECastUnitPrefixSize:crcOffset], nil
}

func hashBECastCiphertext(ciphertext []byte) audit.SessionRecordingHash {
	return hashDomainValues(castBECastCiphertextHashDomain, ciphertext)
}

func hashBECastUnit(unit []byte) audit.SessionRecordingHash {
	return hashDomainValues(castBECastUnitHashDomain, unit)
}

func castBECastStatus(status CastStatus) (uint8, error) {
	switch status {
	case CastStatusCompleted:
		return 1, nil
	case CastStatusFailed:
		return 2, nil
	case CastStatusIncomplete:
		return 3, nil
	default:
		return 0, errors.System.Newf("illegal BECast status %q", status)
	}
}

func castStatusFromBECast(value uint8) (CastStatus, error) {
	switch value {
	case 1:
		return CastStatusCompleted, nil
	case 2:
		return CastStatusFailed, nil
	case 3:
		return CastStatusIncomplete, nil
	default:
		return "", errors.System.Newf("illegal BECast status %d", value)
	}
}
