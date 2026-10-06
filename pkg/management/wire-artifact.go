package management

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

const WireRecordingCommand = "_bifroest-management-recording-v1"
const maxRecordingHeaderBytes = 4096

type RecordingArtifactHeader struct {
	Version    uint8  `cbor:"1,keyasint"`
	ID         string `cbor:"2,keyasint"`
	ProducerID string `cbor:"3,keyasint"`
	Size       int64  `cbor:"4,keyasint"`
	SHA256     string `cbor:"5,keyasint"`
}

func WriteRecordingArtifact(output io.Writer, header RecordingArtifactHeader, content io.Reader) error {
	if header.Version != 1 || header.ID == "" || header.ProducerID == "" || header.Size <= 0 || header.SHA256 == "" || content == nil {
		return fmt.Errorf("invalid Recording artifact header")
	}
	encoded, err := cbor.Marshal(header)
	if err != nil {
		return err
	}
	if len(encoded) > maxRecordingHeaderBytes {
		return fmt.Errorf("Recording artifact header exceeds %d bytes", maxRecordingHeaderBytes)
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(encoded)))
	if _, err := io.Copy(output, bytes.NewReader(size[:])); err != nil {
		return err
	}
	if _, err := io.Copy(output, bytes.NewReader(encoded)); err != nil {
		return err
	}
	written, err := io.CopyN(output, content, header.Size)
	if err != nil {
		return err
	}
	if written != header.Size {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func ReadRecordingArtifact(input io.Reader, output io.Writer, maxBytes int64) (RecordingArtifactHeader, error) {
	var length [4]byte
	if _, err := io.ReadFull(input, length[:]); err != nil {
		return RecordingArtifactHeader{}, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > maxRecordingHeaderBytes {
		return RecordingArtifactHeader{}, fmt.Errorf("invalid Recording artifact header length %d", size)
	}
	encoded := make([]byte, size)
	if _, err := io.ReadFull(input, encoded); err != nil {
		return RecordingArtifactHeader{}, err
	}
	var header RecordingArtifactHeader
	if err := cbor.Unmarshal(encoded, &header); err != nil {
		return header, err
	}
	if header.Version != 1 || header.ID == "" || header.ProducerID == "" || header.Size <= 0 || header.Size > maxBytes {
		return header, fmt.Errorf("unsupported or oversized Recording artifact")
	}
	hasher := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(output, hasher), input, header.Size); err != nil {
		return header, err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != header.SHA256 {
		return header, fmt.Errorf("Recording artifact SHA-256 does not match the declared digest")
	}
	var trailing [1]byte
	if _, err := io.ReadFull(input, trailing[:]); err != io.EOF {
		return header, fmt.Errorf("Recording artifact contains trailing data or failed before EOF: %v", err)
	}
	return header, nil
}
