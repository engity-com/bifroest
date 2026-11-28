//go:build unix

package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFsRuntimePrivateStateRejectsLinksAndBroadPermissions(t *testing.T) {
	for _, attack := range []string{"symlink", "hardlink", "permissions"} {
		t.Run(attack, func(t *testing.T) {
			repo, _ := newAssociationRepository(t)
			key, err := repo.RuntimeKey(t.Context())
			require.NoError(t, err)
			path := repo.runtimeFile(FsFileRuntimeKey)
			if attack == "permissions" {
				require.NoError(t, os.Chmod(path, 0644))
			} else {
				original := filepath.Join(t.TempDir(), "original")
				require.NoError(t, os.Rename(path, original))
				if attack == "symlink" {
					require.NoError(t, os.Symlink(original, path))
				} else {
					require.NoError(t, os.Link(original, path))
				}
			}
			_, err = repo.RuntimeKey(t.Context())
			require.ErrorIs(t, err, ErrInvalidRuntimeState)
			preserved, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, key, preserved, "invalid private state must never be silently repaired or replaced")
		})
	}
}
