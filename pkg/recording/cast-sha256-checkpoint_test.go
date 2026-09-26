package recording

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCastSha256CheckpointResume(t *testing.T) {
	prefix := bytes.Repeat([]byte("checkpoint"), 64)
	suffix := []byte("continued content")
	hasher := sha256.New()
	_, err := hasher.Write(prefix)
	require.NoError(t, err)

	checkpoint, err := checkpointCastSha256(hasher)
	require.NoError(t, err)
	require.Equal(t, uint64(len(prefix)), checkpoint.Bytes)
	require.Equal(t, "7c0f3c084de2efb3c53dc69cce4b7f47b40cf00c97012ab47e4a96682219f90d", hex.EncodeToString(checkpoint.State[:]))

	resumed, err := resumeCastSha256(checkpoint)
	require.NoError(t, err)
	_, err = resumed.Write(suffix)
	require.NoError(t, err)

	direct := sha256.New()
	_, err = direct.Write(prefix)
	require.NoError(t, err)
	_, err = direct.Write(suffix)
	require.NoError(t, err)
	require.Equal(t, direct.Sum(nil), resumed.Sum(nil))
}

func TestPadCastForSha256Checkpoint(t *testing.T) {
	var output bytes.Buffer
	hasher := sha256.New()
	_, err := hasher.Write([]byte(castContentHashDomain))
	require.NoError(t, err)
	writer := &CastWriter{output: &output, digest: hasher}

	checkpoint, err := padCastForSha256Checkpoint(writer)
	require.NoError(t, err)
	require.Zero(t, checkpoint.Bytes%sha256.BlockSize)
	require.True(t, bytes.HasPrefix(output.Bytes(), []byte(castCheckpointPaddingCommentPrefix)))
	require.Equal(t, byte('\n'), output.Bytes()[output.Len()-1])

	resumed, err := resumeCastSha256(checkpoint)
	require.NoError(t, err)
	require.Equal(t, hasher.Sum(nil), resumed.Sum(nil))
}

func TestCastSha256CheckpointRejectsUnalignedState(t *testing.T) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte("unaligned"))
	require.NoError(t, err)

	_, err = checkpointCastSha256(hasher)
	require.EqualError(t, err, "cast SHA-256 checkpoint is not block-aligned")
}

func TestResumeCastSha256RejectsIllegalLength(t *testing.T) {
	_, err := resumeCastSha256(castSha256Checkpoint{Bytes: 1})
	require.EqualError(t, err, "illegal Cast SHA-256 checkpoint byte count 1")
}
