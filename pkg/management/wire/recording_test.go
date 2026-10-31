package wire

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
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
	require.ErrorIs(t, err, ErrArtifactLimit)
	_, err = ReadRecordingArtifact(bytes.NewReader(append(wire.Bytes(), 0)), &bytes.Buffer{}, 4096)
	require.ErrorContains(t, err, "trailing")
}

func TestRecordingArtifactPrefixIsProvisionalAndEOFAndWriterFailuresRemainErrors(t *testing.T) {
	content := []byte("untrusted opaque artifact bytes")
	header := RecordingArtifactHeader{Version: 1, ID: "id", ProducerID: "untrusted producer assertion", Size: int64(len(content)), SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
	var wire bytes.Buffer
	require.NoError(t, WriteRecordingArtifact(&wire, header, bytes.NewReader(content)))
	data := bytes.Clone(wire.Bytes())
	failure := errors.New("transport failed after artifact")
	var provisional bytes.Buffer
	_, err := ReadRecordingArtifact(io.MultiReader(bytes.NewReader(data), transferErrorReader{failure}), &provisional, 4096)
	require.ErrorContains(t, err, failure.Error())
	require.Equal(t, content, provisional.Bytes(), "bytes are not published/verified merely because the sink saw them")
	_, err = ReadRecordingArtifact(bytes.NewReader(data[:len(data)-1]), &bytes.Buffer{}, 4096)
	require.Error(t, err)
	_, err = ReadRecordingArtifact(bytes.NewReader(data), shortRecordingStreamWriter{}, 4096)
	require.ErrorIs(t, err, io.ErrShortWrite)
}
