//go:build unix

package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrivateDirectoryRejectsPublicPermissionsAndLinksWithoutRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public")
	require.NoError(t, os.Mkdir(path, 0755))
	_, err := EnsurePrivateDirectory(path)
	require.Error(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0755), info.Mode().Perm())
	require.NoError(t, os.Chmod(path, 0700))
	require.NoError(t, os.Symlink(path, path+".link"))
	_, err = EnsurePrivateDirectory(path + ".link")
	require.Error(t, err)
}
