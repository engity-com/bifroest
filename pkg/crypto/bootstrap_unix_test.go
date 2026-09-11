//go:build unix

package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeneratedPrivateKeyHasRestrictiveMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	_, err := (KeyRequirement{Type: KeyTypeEd25519}).CreateFile(nil, path)
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0400), info.Mode().Perm())
}
