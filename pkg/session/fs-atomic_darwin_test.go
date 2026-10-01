//go:build darwin

package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinAtomicWriteReplacesLinkWithoutFollowingIt(t *testing.T) {
	directory := t.TempDir()
	protected := filepath.Join(directory, "protected")
	target := filepath.Join(directory, "session")
	require.NoError(t, os.WriteFile(protected, []byte("protected"), 0600))
	require.NoError(t, os.Symlink(protected, target))

	require.NoError(t, writeFsFileAtomically(target, []byte("session"), 0600, 0700))
	protectedContent, err := os.ReadFile(protected)
	require.NoError(t, err)
	require.Equal(t, []byte("protected"), protectedContent)
	targetInfo, err := os.Lstat(target)
	require.NoError(t, err)
	require.True(t, targetInfo.Mode().IsRegular())
	targetContent, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("session"), targetContent)
}

func TestDarwinAtomicWritePreservesOtherHardLinkAndCleansTemporaryFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "session")
	alias := filepath.Join(directory, "alias")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0600))
	require.NoError(t, os.Link(target, alias))

	require.NoError(t, writeFsFileAtomically(target, []byte("new"), 0600, 0700))
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("new"), content)
	aliasContent, err := os.ReadFile(alias)
	require.NoError(t, err)
	require.Equal(t, []byte("old"), aliasContent)
	matches, err := filepath.Glob(filepath.Join(directory, ".session.tmp-*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}
