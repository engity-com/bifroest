package main

import (
	goos "os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuditOutputFileRejectsParentSwapAfterPinning(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "output")
	movedParent := filepath.Join(root, "pinned-output")
	require.NoError(t, goos.Mkdir(parent, 0700))

	err := writeAuditOutputFile(filepath.Join(parent, "audit.jsonl"), []byte("protected\n"), false, func() error {
		require.NoError(t, goos.Rename(parent, movedParent))
		require.NoError(t, goos.Mkdir(parent, 0700))
		return nil
	})
	require.ErrorContains(t, err, "output parent changed")
	require.NoFileExists(t, filepath.Join(movedParent, "audit.jsonl"))
	require.NoFileExists(t, filepath.Join(parent, "audit.jsonl"))
}

func TestAuditOutputFileForceNoReplacePermissionsAndCleanup(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "audit.jsonl")
	require.NoError(t, writeAuditOutputFile(path, []byte("first\n"), false, nil))

	info, err := goos.Stat(path)
	require.NoError(t, err)
	requireAuditOutputPrivate(t, path, info)
	require.Error(t, writeAuditOutputFile(path, []byte("second\n"), false, nil))
	raw, err := goos.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "first\n", string(raw))
	require.NoError(t, writeAuditOutputFile(path, []byte("third\n"), true, nil))
	raw, err = goos.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "third\n", string(raw))

	entries, err := goos.ReadDir(parent)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestCanonicalAuditOutputRequiresExistingImmediateParent(t *testing.T) {
	output := filepath.Join(t.TempDir(), "missing", "audit.jsonl")
	_, err := canonicalAuditOutput(output)
	require.ErrorContains(t, err, "must already exist")
	require.NoDirExists(t, filepath.Dir(output))
}
