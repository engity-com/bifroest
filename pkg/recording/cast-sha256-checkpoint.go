package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"fmt"
	"hash"
)

const (
	castCheckpointPaddingCommentPrefix = "# becast-checkpoint-padding:v1 "
	sha256MarshaledSize                = 4 + sha256.Size + sha256.BlockSize + 8
)

var sha256MarshaledMagic = [4]byte{'s', 'h', 'a', 3}

type castSha256Checkpoint struct {
	State [sha256.Size]byte
	Bytes uint64
}

func padCastForSha256Checkpoint(writer *CastWriter) (castSha256Checkpoint, error) {
	if writer == nil || writer.digest == nil {
		return castSha256Checkpoint{}, fmt.Errorf("nil cast writer")
	}
	if writer.poisoned != nil {
		return castSha256Checkpoint{}, writer.poisoned
	}
	if writer.sealed {
		return castSha256Checkpoint{}, fmt.Errorf("cast is already sealed")
	}
	processed, err := castSha256ProcessedBytes(writer.digest)
	if err != nil {
		return castSha256Checkpoint{}, err
	}
	lineBytes := uint64(len(castCheckpointPaddingCommentPrefix) + 1)
	paddingBytes := (sha256.BlockSize - (processed+lineBytes)%sha256.BlockSize) % sha256.BlockSize
	line := make([]byte, len(castCheckpointPaddingCommentPrefix)+int(paddingBytes))
	copy(line, castCheckpointPaddingCommentPrefix)
	for index := len(castCheckpointPaddingCommentPrefix); index < len(line); index++ {
		line[index] = '0'
	}
	if err := writer.writeContentLine(line); err != nil {
		return castSha256Checkpoint{}, err
	}
	return checkpointCastSha256(writer.digest)
}

func checkpointCastSha256(hasher hash.Hash) (castSha256Checkpoint, error) {
	state, processed, err := marshalCastSha256(hasher)
	if err != nil {
		return castSha256Checkpoint{}, err
	}
	if processed%sha256.BlockSize != 0 {
		return castSha256Checkpoint{}, fmt.Errorf("cast SHA-256 checkpoint is not block-aligned")
	}
	if !bytes.Equal(state[4+sha256.Size:4+sha256.Size+sha256.BlockSize], make([]byte, sha256.BlockSize)) {
		return castSha256Checkpoint{}, fmt.Errorf("cast SHA-256 checkpoint contains buffered input")
	}
	var result castSha256Checkpoint
	copy(result.State[:], state[4:4+sha256.Size])
	result.Bytes = processed
	return result, nil
}

func resumeCastSha256(checkpoint castSha256Checkpoint) (hash.Hash, error) {
	if checkpoint.Bytes == 0 || checkpoint.Bytes%sha256.BlockSize != 0 {
		return nil, fmt.Errorf("illegal Cast SHA-256 checkpoint byte count %d", checkpoint.Bytes)
	}
	state := make([]byte, sha256MarshaledSize)
	copy(state, sha256MarshaledMagic[:])
	copy(state[4:], checkpoint.State[:])
	binary.BigEndian.PutUint64(state[len(state)-8:], checkpoint.Bytes)
	hasher := sha256.New()
	unmarshaler, ok := hasher.(encoding.BinaryUnmarshaler)
	if !ok {
		return nil, fmt.Errorf("SHA-256 implementation cannot restore state")
	}
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		return nil, fmt.Errorf("cannot restore Cast SHA-256 checkpoint: %w", err)
	}
	return hasher, nil
}

func castSha256ProcessedBytes(hasher hash.Hash) (uint64, error) {
	_, processed, err := marshalCastSha256(hasher)
	return processed, err
}

func marshalCastSha256(hasher hash.Hash) ([]byte, uint64, error) {
	if hasher == nil || hasher.Size() != sha256.Size || hasher.BlockSize() != sha256.BlockSize {
		return nil, 0, fmt.Errorf("illegal Cast SHA-256 implementation")
	}
	marshaler, ok := hasher.(encoding.BinaryMarshaler)
	if !ok {
		return nil, 0, fmt.Errorf("SHA-256 implementation cannot expose checkpoint state")
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		return nil, 0, fmt.Errorf("cannot read Cast SHA-256 state: %w", err)
	}
	if len(state) != sha256MarshaledSize || !bytes.Equal(state[:4], sha256MarshaledMagic[:]) {
		return nil, 0, fmt.Errorf("unsupported SHA-256 checkpoint encoding")
	}
	return state, binary.BigEndian.Uint64(state[len(state)-8:]), nil
}
