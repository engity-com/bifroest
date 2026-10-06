package management

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordingArtifactTransferVerifiesSizeAndDigest(t *testing.T) {
	content := []byte("signed container bytes")
	header := RecordingArtifactHeader{Version: 1, ID: "id", ProducerID: "producer", Size: int64(len(content)), SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
	var wire bytes.Buffer
	require.NoError(t, WriteRecordingArtifact(&wire, header, bytes.NewReader(content)))
	var copy bytes.Buffer
	decoded, err := ReadRecordingArtifact(bytes.NewReader(wire.Bytes()), &copy, 4096)
	require.NoError(t, err)
	require.Equal(t, header, decoded)
	require.Equal(t, content, copy.Bytes())
	broken := append([]byte(nil), wire.Bytes()...)
	broken[len(broken)-1] ^= 1
	_, err = ReadRecordingArtifact(bytes.NewReader(broken), &bytes.Buffer{}, 4096)
	require.ErrorContains(t, err, "SHA-256")
	_, err = ReadRecordingArtifact(bytes.NewReader(wire.Bytes()), &bytes.Buffer{}, 4)
	require.ErrorContains(t, err, "oversized")
	_, err = ReadRecordingArtifact(bytes.NewReader(append(wire.Bytes(), 0)), &bytes.Buffer{}, 4096)
	require.ErrorContains(t, err, "trailing")
}
