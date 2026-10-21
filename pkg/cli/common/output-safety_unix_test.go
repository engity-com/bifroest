//go:build unix

package common

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func denyOutputDirectoryListing(t *testing.T, directory string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory read permissions")
	}
	require.NoError(t, os.Chmod(directory, 0300))
	t.Cleanup(func() { require.NoError(t, os.Chmod(directory, 0700)) })
	_, err := os.ReadDir(directory)
	require.ErrorIs(t, err, fs.ErrPermission)
}
