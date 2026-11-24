package sys

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenFileForRotationIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "material")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	reader, err := OpenFileForRotation(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })

	_, err = reader.Write([]byte("changed"))
	require.Error(t, err)
	raw, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, []byte("original"), raw)
}

func TestOpenFileForRotationDoesNotCreateMissingFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	reader, err := OpenFileForRotation(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Nil(t, reader)
	require.NoFileExists(t, path)
}
