//go:build unix

package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBrowserBindingPrivateStateRejectsLinksAndLoosePermissionsWithoutRepair(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "permissions"} {
		t.Run(mode, func(t *testing.T) {
			repository, _, sess, spec := browserBindingFixture(t)
			_, err := sess.CreateBrowserBinding(t.Context(), spec, time.Hour)
			require.NoError(t, err)
			path, _ := repository.file(sess.flow, sess.id, FsFileBrowserBindings)
			other := filepath.Join(t.TempDir(), "other-state")
			switch mode {
			case "symlink":
				require.NoError(t, os.Rename(path, other))
				require.NoError(t, os.Symlink(other, path))
			case "hardlink":
				require.NoError(t, os.Link(path, other))
			case "permissions":
				require.NoError(t, os.Chmod(path, 0644))
			}
			_, err = sess.BrowserBindings(t.Context())
			require.ErrorIs(t, err, ErrInvalidBrowserBinding)
			_, err = sess.CreateBrowserBinding(t.Context(), spec, time.Hour)
			require.ErrorIs(t, err, ErrInvalidBrowserBinding)
			if mode == "permissions" {
				info, err := os.Stat(path)
				require.NoError(t, err)
				require.EqualValues(t, 0644, info.Mode().Perm())
			} else {
				require.FileExists(t, other)
			}
		})
	}
}
