package nativeformat

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type changingUnitReader struct {
	first  []byte
	second []byte
	reads  int
}

func (this *changingUnitReader) ReadAt(target []byte, offset int64) (int, error) {
	source := this.second
	if this.reads == 0 {
		source = this.first
	}
	this.reads++
	if offset < 0 || offset > int64(len(source)) {
		return 0, io.EOF
	}
	n := copy(target, source[int(offset):])
	if n != len(target) {
		return n, io.EOF
	}
	return n, nil
}

func TestNativeContainerUnits(t *testing.T) {
	payload := []byte{0xa1, 0x01, 0x02}
	encoded, err := EncodeUnit(ContentUnit, payload, MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, byte(ContentUnit), encoded[0])
	require.Equal(t, uint32(len(payload)), binary.BigEndian.Uint32(encoded[1:commitOffset]))
	require.Equal(t, byte(1), encoded[commitOffset])
	require.Equal(t, []byte(CommitMarker), encoded[len(encoded)-len(CommitMarker):])

	for _, test := range []struct {
		magic  string
		family Family
	}{
		{AuditMagic, AuditFamily},
		{RecordingMagic, RecordingFamily},
	} {
		content := []byte(test.magic)
		content = append(content, encoded...)
		reader := bytes.NewReader(content)
		family, offset, err := DetectFamily(reader)
		require.NoError(t, err)
		require.Equal(t, test.family, family)
		unit, next, incomplete, err := ReadUnitAt(reader, offset, int64(len(content)), MaxMetadataPayload)
		require.NoError(t, err)
		require.False(t, incomplete)
		require.Equal(t, Unit{ContentUnit, payload}, unit)
		require.Equal(t, int64(len(content)), next)
	}
}

func TestNativeContainerRejectsMalformedUnits(t *testing.T) {
	original, err := EncodeUnit(HeaderUnit, []byte{0xa1, 0x01, 0x02}, MaxMetadataPayload)
	require.NoError(t, err)

	for name, mutate := range map[string]func([]byte){
		"checksum":     func(v []byte) { v[framePrefixSize] ^= 1 },
		"marker":       func(v []byte) { v[len(v)-1] ^= 1 },
		"type":         func(v []byte) { v[0] = 4 },
		"length":       func(v []byte) { binary.BigEndian.PutUint32(v[1:], 10) },
		"commit state": func(v []byte) { v[commitOffset] = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := bytes.Clone(original)
			mutate(candidate)
			_, _, incomplete, err := ReadUnitAt(bytes.NewReader(candidate), 0, int64(len(candidate)), MaxMetadataPayload)
			require.Error(t, err)
			require.False(t, incomplete)
		})
	}
	for length := range len(original) {
		candidate := bytes.Clone(original[:length])
		if length >= framePrefixSize {
			candidate[commitOffset] = 0
		}
		_, _, incomplete, err := ReadUnitAt(bytes.NewReader(candidate), 0, int64(length), MaxMetadataPayload)
		require.NoError(t, err)
		require.True(t, incomplete)
	}
	completeButUncommitted := bytes.Clone(original)
	completeButUncommitted[commitOffset] = 0
	_, _, incomplete, err := ReadUnitAt(bytes.NewReader(completeButUncommitted), 0, int64(len(completeButUncommitted)), MaxMetadataPayload)
	require.NoError(t, err)
	require.True(t, incomplete, "a fully written body before the final commit remains uncommitted")
	for _, extra := range [][]byte{{0}, original} {
		candidate := append(bytes.Clone(completeButUncommitted), extra...)
		_, _, incomplete, err := ReadUnitAt(bytes.NewReader(candidate), 0, int64(len(candidate)), MaxMetadataPayload)
		require.Error(t, err, "bytes beyond a complete state-0 frame are not a recoverable tail")
		require.False(t, incomplete)
	}
	partialPrefix := bytes.Clone(original[:framePrefixSize])
	clear(partialPrefix[1:commitOffset])
	partialPrefix[commitOffset] = 0
	_, _, incomplete, err = ReadUnitAt(bytes.NewReader(partialPrefix), 0, int64(len(partialPrefix)), MaxMetadataPayload)
	require.NoError(t, err, "an interrupted state-0 length field is a recoverable prefix")
	require.True(t, incomplete)
	_, _, incomplete, err = ReadUnitAt(bytes.NewReader(append(partialPrefix, 0)), 0, int64(len(partialPrefix)+1), MaxMetadataPayload)
	require.Error(t, err, "a zero length cannot hide a following unit")
	require.False(t, incomplete)
	_, _, incomplete, err = ReadUnitAt(bytes.NewReader(original[:len(original)-1]), 0, int64(len(original)-1), MaxMetadataPayload)
	require.Error(t, err, "a committed unit must never have a short tail")
	require.False(t, incomplete)
	inner := append(bytes.Repeat([]byte{0x01}, 12), []byte(CommitMarker)...)
	payload := append([]byte{0xa1, 0x01, 0x54}, inner...)
	withMarkerInPayload, err := EncodeUnit(HeaderUnit, payload, MaxMetadataPayload)
	require.NoError(t, err)
	physicalTail := bytes.Clone(withMarkerInPayload[:framePrefixSize+len(payload)])
	physicalTail[commitOffset] = 0
	_, _, incomplete, err = ReadUnitAt(bytes.NewReader(physicalTail), 0, int64(len(physicalTail)), MaxMetadataPayload)
	require.NoError(t, err, "payload ending in a marker is not a committed unit")
	require.True(t, incomplete)
	markedStateZero := bytes.Clone(withMarkerInPayload)
	markedStateZero[commitOffset] = 0
	_, _, incomplete, err = ReadUnitAt(bytes.NewReader(markedStateZero), 0, int64(len(markedStateZero)), MaxMetadataPayload)
	require.NoError(t, err, "a marker inside the payload does not terminate a state-0 frame")
	require.True(t, incomplete)
	markedWithFollowingFrame := append(markedStateZero, original...)
	_, _, incomplete, err = ReadUnitAt(bytes.NewReader(markedWithFollowingFrame), 0, int64(len(markedWithFollowingFrame)), MaxMetadataPayload)
	require.Error(t, err, "a payload marker cannot hide bytes after the actual frame boundary")
	require.False(t, incomplete)
	corruptLengthWithExtraByte := bytes.Clone(original)
	binary.BigEndian.PutUint32(corruptLengthWithExtraByte[1:], 10)
	corruptLengthWithExtraByte = append(corruptLengthWithExtraByte, 0)
	_, _, incomplete, err = ReadUnitAt(bytes.NewReader(corruptLengthWithExtraByte), 0, int64(len(corruptLengthWithExtraByte)), MaxMetadataPayload)
	require.Error(t, err, "extra bytes cannot hide a corrupted committed length")
	require.False(t, incomplete)
	shorterLength := bytes.Clone(original)
	binary.BigEndian.PutUint32(shorterLength[1:], 2)
	_, _, incomplete, err = ReadUnitAt(bytes.NewReader(shorterLength), 0, int64(len(shorterLength)), MaxMetadataPayload)
	require.Error(t, err, "a complete frame with a short claimed length is corrupt")
	require.False(t, incomplete)
	reader := &changingUnitReader{first: original, second: completeButUncommitted}
	_, _, incomplete, err = ReadUnitAt(reader, 0, int64(len(original)), MaxMetadataPayload)
	require.Error(t, err, "commit state changed between the two reads")
	require.False(t, incomplete)
	otherType, err := EncodeUnit(SealUnit, []byte{0xa1, 0x01, 0x02}, MaxMetadataPayload)
	require.NoError(t, err)
	reader = &changingUnitReader{first: original, second: otherType}
	_, _, incomplete, err = ReadUnitAt(reader, 0, int64(len(original)), MaxMetadataPayload)
	require.Error(t, err, "unit type changed between the two reads")
	require.False(t, incomplete)

	_, err = EncodeUnit(HeaderUnit, []byte{1, 2, 3}, 2)
	require.Error(t, err)
	_, err = EncodeUnit(HeaderUnit, []byte{0x81, 0x01}, MaxMetadataPayload)
	require.Error(t, err)
	_, err = EncodeUnit(HeaderUnit, []byte{0xa1, 0x61, 'a', 0x01}, MaxMetadataPayload)
	require.Error(t, err)
	_, err = EncodeUnit(UnitType(4), []byte{1}, MaxMetadataPayload)
	require.Error(t, err)
	_, _, _, err = ReadUnitAt(bytes.NewReader(original), 0, int64(len(original)), 2)
	require.Error(t, err)
	_, _, err = DetectFamily(bytes.NewReader([]byte("not a native container")))
	require.Error(t, err)

	malformed := bytes.Clone(original)
	malformed[framePrefixSize] = 0x81
	checksumOffset := len(malformed) - frameTrailerSize
	binary.BigEndian.PutUint32(malformed[checksumOffset:], checksumUnit(malformed[:checksumOffset]))
	_, _, incomplete, err = ReadUnitAt(bytes.NewReader(malformed), 0, int64(len(malformed)), MaxMetadataPayload)
	require.Error(t, err, "a valid CRC must not make a non-CBOR map acceptable")
	require.False(t, incomplete)
}

func TestNativeContainerRejectsLengthSwallowingCommittedUnit(t *testing.T) {
	payload := []byte{0xa1, 0x01, 0x02}
	first, err := EncodeUnit(ContentUnit, payload, MaxMetadataPayload)
	require.NoError(t, err)
	second, err := EncodeUnit(ContentUnit, payload, MaxMetadataPayload)
	require.NoError(t, err)
	first[commitOffset] = 0
	data := append(bytes.Clone(first), second...)
	binary.BigEndian.PutUint32(data[1:commitOffset], uint32(len(data)))
	for _, corruptCRC := range []bool{false, true} {
		candidate := bytes.Clone(data)
		if corruptCRC {
			candidate[len(first)+framePrefixSize] ^= 1
		}
		_, _, tail, err := ReadUnitAt(bytes.NewReader(candidate), 0, int64(len(candidate)), MaxMetadataPayload)
		require.Error(t, err)
		require.False(t, tail)
	}
}

func TestNativeContainerStateZeroTailValidation(t *testing.T) {
	frame, err := EncodeUnit(ContentUnit, []byte{0xa1, 0x01, 0x02}, MaxMetadataPayload)
	require.NoError(t, err)
	frame[commitOffset] = 0
	for _, mutate := range []func([]byte){
		func(v []byte) { v[framePrefixSize] ^= 1 },
		func(v []byte) { v[len(v)-1] ^= 1 },
		func(v []byte) {
			v[framePrefixSize] = 0x81
			binary.BigEndian.PutUint32(v[len(v)-frameTrailerSize:], checksumUnit(v[:len(v)-frameTrailerSize]))
		},
	} {
		candidate := bytes.Clone(frame)
		mutate(candidate)
		_, _, tail, err := ReadUnitAt(bytes.NewReader(candidate), 0, int64(len(candidate)), MaxMetadataPayload)
		require.Error(t, err)
		require.False(t, tail)
	}
	// The marker alone, even preceded by arbitrary binary data, is not a frame.
	partial := append(bytes.Clone(frame[:framePrefixSize]), bytes.Repeat([]byte{0x7f}, 32)...)
	partial = append(partial, CommitMarker...)
	binary.BigEndian.PutUint32(partial[1:commitOffset], uint32(len(partial)+10))
	_, _, tail, err := ReadUnitAt(bytes.NewReader(partial), 0, int64(len(partial)), MaxMetadataPayload)
	require.NoError(t, err)
	require.True(t, tail)
	zeroPrefix := bytes.Clone(frame[:framePrefixSize])
	clear(zeroPrefix[1:commitOffset])
	_, _, tail, err = ReadUnitAt(bytes.NewReader(zeroPrefix), 0, int64(len(zeroPrefix)), MaxMetadataPayload)
	require.NoError(t, err)
	require.True(t, tail)
}
