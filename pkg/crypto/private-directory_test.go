package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsurePrivateDirectoryCreatesAndReopensOwnedStorage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	first, err := EnsurePrivateDirectory(path)
	require.NoError(t, err)
	defer first.Close()
	second, err := EnsurePrivateDirectory(path)
	require.NoError(t, err)
	defer second.Close()
	left, err := first.Stat()
	require.NoError(t, err)
	right, err := second.Stat()
	require.NoError(t, err)
	require.True(t, os.SameFile(left, right))
	_, err = EnsurePrivateDirectory("")
	require.Error(t, err)
}

func TestReadSecurePrivateFileDoesNotRequireOrInventAKeyFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opaque-state")
	raw := []byte("opaque private state, not a key")
	require.NoError(t, WriteBootstrapFile(path, raw, false))
	actual, err := ReadSecurePrivateFile(path, 1024)
	require.NoError(t, err)
	require.Equal(t, raw, actual)
	_, err = ReadSecurePrivateFile(path, 4)
	require.Error(t, err)
	_, err = LoadSecurePrivateKeyFile(path, 1024)
	require.Error(t, err)
	stored, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, raw, stored)
}
