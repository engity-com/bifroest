package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadSecurePrivateKeyFileLoadsGeneratedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	expected, err := (KeyRequirement{Type: KeyTypeEd25519}).CreateFile(nil, path)
	require.NoError(t, err)

	actual, err := LoadSecurePrivateKeyFile(path, 1<<20)
	require.NoError(t, err)
	require.True(t, expected.PublicKey().IsEqualTo(actual.PublicKey()))
}

func TestLoadSecurePrivateKeyFileRejectsOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(17))
	require.NoError(t, file.Close())

	_, err = LoadSecurePrivateKeyFile(path, 16)
	require.ErrorContains(t, err, "exceeds 16 bytes")
}

func TestCreateProtectedTempFileRejectsGroupOrOtherPermissions(t *testing.T) {
	directory := t.TempDir()
	file, err := CreateProtectedTempFile(directory, ".private-*", 0640)
	require.Nil(t, file)
	require.ErrorContains(t, err, "grants group or other permissions")
	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	require.Empty(t, entries)
}
