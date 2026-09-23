package nativeformat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
)

const (
	AuditMagic     = "\x89BAUDIT\n"
	RecordingMagic = "\x89BCAST\n"
	CommitMarker   = "BFCOMMIT"

	MaxMetadataPayload       = 4 << 10
	MaxAuditEventPayload     = 64 << 10
	MaxAuditRecordPayload    = 128 << 10
	MaxRecordingDecodedChunk = 2 << 20
	MaxRecordingChunkPayload = 4 << 20

	framePrefixSize  = 1 + 4 + 1
	frameTrailerSize = 4 + len(CommitMarker)
	commitOffset     = framePrefixSize - 1
)

type Family uint8

const (
	AuditFamily Family = iota + 1
	RecordingFamily
)

type UnitType uint8

const (
	HeaderUnit UnitType = iota + 1
	ContentUnit
	SealUnit
)

type Unit struct {
	Type    UnitType
	Payload []byte
}

var crcTable = crc32.MakeTable(crc32.Castagnoli)

func DetectFamily(source io.ReaderAt) (Family, int64, error) {
	var prefix [len(AuditMagic)]byte
	if _, err := source.ReadAt(prefix[:len(RecordingMagic)], 0); err != nil {
		return 0, 0, fmt.Errorf("cannot read native container magic: %w", err)
	}
	if string(prefix[:len(RecordingMagic)]) == RecordingMagic {
		return RecordingFamily, int64(len(RecordingMagic)), nil
	}
	if _, err := source.ReadAt(prefix[:], 0); err != nil {
		return 0, 0, fmt.Errorf("cannot read native container magic: %w", err)
	}
	if string(prefix[:]) == AuditMagic {
		return AuditFamily, int64(len(AuditMagic)), nil
	}
	return 0, 0, fmt.Errorf("unknown native container magic")
}

func validType(kind UnitType) bool {
	return kind == HeaderUnit || kind == ContentUnit || kind == SealUnit
}

func EncodeUnit(kind UnitType, payload []byte, maximum int) ([]byte, error) {
	if !validType(kind) || maximum < 1 || len(payload) == 0 || len(payload) > maximum || uint64(len(payload)) > math.MaxUint32 {
		return nil, fmt.Errorf("invalid native container unit type or payload size")
	}
	if _, err := Unmarshal[map[uint64]any](payload, maximum); err != nil {
		return nil, err
	}
	result := make([]byte, framePrefixSize+len(payload)+frameTrailerSize)
	result[0] = byte(kind)
	binary.BigEndian.PutUint32(result[1:commitOffset], uint32(len(payload)))
	result[commitOffset] = 1
	copy(result[framePrefixSize:], payload)
	checksumOffset := framePrefixSize + len(payload)
	binary.BigEndian.PutUint32(result[checksumOffset:], checksumUnit(result[:checksumOffset]))
	copy(result[checksumOffset+4:], CommitMarker)
	return result, nil
}

func checksumUnit(frame []byte) uint32 {
	checksum := crc32.Checksum(frame[:commitOffset], crcTable)
	return crc32.Update(checksum, crcTable, frame[framePrefixSize:])
}

// ReadUnitAt distinguishes an uncommitted tail from an invalid committed unit.
// Callers must compare the tail against their signed recovery checkpoint.
func ReadUnitAt(source io.ReaderAt, offset, size int64, maximum int) (Unit, int64, bool, error) {
	if maximum < 1 || offset < 0 || size < offset {
		return Unit{}, offset, false, fmt.Errorf("invalid native container unit bounds")
	}
	remaining := size - offset
	if remaining < framePrefixSize {
		return Unit{}, offset, true, nil
	}
	var prefix [framePrefixSize]byte
	if _, err := source.ReadAt(prefix[:], offset); err != nil {
		return Unit{}, offset, false, fmt.Errorf("cannot read native container unit header: %w", err)
	}
	if prefix[commitOffset] == 0 {
		return Unit{}, offset, true, nil
	}
	if prefix[commitOffset] != 1 {
		return Unit{}, offset, false, fmt.Errorf("invalid native container commit state")
	}
	kind := UnitType(prefix[0])
	length := uint64(binary.BigEndian.Uint32(prefix[1:commitOffset]))
	if !validType(kind) || length == 0 || length > uint64(maximum) {
		return Unit{}, offset, false, fmt.Errorf("invalid native container unit type or payload size")
	}
	unitSize := int64(framePrefixSize) + int64(length) + int64(frameTrailerSize)
	if remaining < unitSize {
		return Unit{}, offset, false, fmt.Errorf("committed native container unit is physically incomplete")
	}
	frame := make([]byte, unitSize)
	if _, err := source.ReadAt(frame, offset); err != nil {
		return Unit{}, offset, false, fmt.Errorf("cannot read native container unit: %w", err)
	}
	if !bytes.Equal(prefix[:], frame[:framePrefixSize]) {
		return Unit{}, offset, false, fmt.Errorf("native container unit header changed while reading")
	}
	checksumOffset := framePrefixSize + int(length)
	if string(frame[checksumOffset+4:]) != CommitMarker {
		return Unit{}, offset, false, fmt.Errorf("native container unit commit marker mismatch")
	}
	if checksumUnit(frame[:checksumOffset]) != binary.BigEndian.Uint32(frame[checksumOffset:]) {
		return Unit{}, offset, false, fmt.Errorf("native container unit checksum mismatch")
	}
	payload := frame[framePrefixSize:checksumOffset]
	if _, err := Unmarshal[map[uint64]any](payload, maximum); err != nil {
		return Unit{}, offset, false, err
	}
	return Unit{kind, payload}, offset + unitSize, false, nil
}
