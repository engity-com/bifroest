package sys

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalPathMakesRelativePathAbsolute(t *testing.T) {
	expected, err := filepath.Abs(".")
	require.NoError(t, err)
	expected, err = filepath.EvalSymlinks(expected)
	require.NoError(t, err)

	actual, err := CanonicalPath(".")
	require.NoError(t, err)
	require.Equal(t, filepath.Clean(expected), actual)
}

func TestCanonicalPathIsAbsoluteAndPreservesMissingTail(t *testing.T) {
	parent := t.TempDir()
	canonicalParent, err := filepath.EvalSymlinks(parent)
	require.NoError(t, err)

	actual, err := CanonicalPath(filepath.Join(parent, "missing", "tail"))
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(actual))
	require.Equal(t, filepath.Join(canonicalParent, "missing", "tail"), actual)
	require.NoDirExists(t, filepath.Join(parent, "missing"))
}

func TestCanonicalPathResolvesSymlinkedExistingParent(t *testing.T) {
	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(realParent, 0700))
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realParent, alias); err != nil {
		t.Skipf("cannot create symlink on this platform: %v", err)
	}
	canonicalParent, err := filepath.EvalSymlinks(realParent)
	require.NoError(t, err)

	actual, err := CanonicalPath(filepath.Join(alias, "missing", "tail"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(canonicalParent, "missing", "tail"), actual)
}

func TestCanonicalPathHandlesVolumeRoot(t *testing.T) {
	absolute, err := filepath.Abs(t.TempDir())
	require.NoError(t, err)
	root := filepath.VolumeName(absolute) + string(filepath.Separator)
	expected, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)

	actual, err := CanonicalPath(root)
	require.NoError(t, err)
	require.Equal(t, filepath.Clean(expected), actual)
}

func TestCanonicalPathReturnsFilesystemErrors(t *testing.T) {
	_, err := CanonicalPath("invalid\x00path")
	require.Error(t, err)
}

func TestCanonicalPathReturnsSymlinkErrors(t *testing.T) {
	root := t.TempDir()
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "missing-target"), dangling); err != nil {
		t.Skipf("cannot create symlink on this platform: %v", err)
	}

	_, err := CanonicalPath(filepath.Join(dangling, "tail"))
	require.Error(t, err)
}
