package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileContentPinsSnapshotIdentityUntilClosed(t *testing.T) {
	dir := t.TempDir()
	path := writeInput(t, filepath.Join(dir, "original.txt"), "original")
	contents, err := newFileContents(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = contents.Close() })
	value, err := contents.read("original.txt")
	require.NoError(t, err)
	require.Equal(t, "original", value)
	require.Len(t, contents.entries, 1)
	pinned := contents.entries[0].file
	require.NotNil(t, pinned)
	require.NoError(t, os.Remove(path))
	info, err := pinned.Stat()
	require.NoError(t, err, "the deleted snapshot's identity must stay pinned")
	require.True(t, os.SameFile(contents.entries[0].info, info))
	writeInput(t, filepath.Join(dir, "large.txt"), strings.Repeat("x", maxSource+1))
	_, err = contents.read("large.txt")
	require.Error(t, err)
	writeInput(t, filepath.Join(dir, "different.txt"), "different")
	value, err = contents.read("different.txt")
	require.NoError(t, err)
	require.Equal(t, "different", value)
	require.Len(t, contents.entries, 2)
	require.False(t, os.SameFile(contents.entries[0].info, contents.entries[1].info))
	require.NoError(t, contents.Close())
	for _, entry := range contents.entries {
		_, err := entry.file.Stat()
		require.Error(t, err)
		require.Equal(t, ^uintptr(0), entry.file.Fd(), "snapshot handle must be closed")
	}
}
