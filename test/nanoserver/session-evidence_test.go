package nanoserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestCopiedSessionOwnershipGetsPrivatePermissionsWithoutChangingEvidence(t *testing.T) {
	storage := t.TempDir()
	directory := filepath.Join(storage, "flow", "session")
	require.NoError(t, os.MkdirAll(directory, 0700))
	files := map[string][]byte{
		session.FsFileRuntimeOwnership:  []byte(`{"invalid":"must remain invalid"}`),
		session.FsFileRuntimeRevocation: []byte("unmodified tombstone evidence\n"),
		"unrelated":                     []byte("unrelated evidence"),
	}
	for name, raw := range files {
		require.NoError(t, os.WriteFile(filepath.Join(directory, name), raw, 0644))
	}
	require.NoError(t, protectCopiedSessionOwnership(storage))
	for name, expected := range files {
		path := filepath.Join(directory, name)
		actual, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
		if name != "unrelated" {
			private, err := crypto.ReadSecurePrivateFile(path, 4096)
			require.NoError(t, err, "copied ownership must meet the real secure-reader contract")
			require.Equal(t, expected, private)
		}
	}
}

func TestCopiedSessionOwnershipRejectsSymlinksWithoutChangingTargets(t *testing.T) {
	storage := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside")
	expected := []byte("do not rewrite or re-protect external files")
	require.NoError(t, os.WriteFile(target, expected, 0644))
	if err := os.Symlink(target, filepath.Join(storage, session.FsFileRuntimeOwnership)); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	require.ErrorContains(t, protectCopiedSessionOwnership(storage), "unexpected symlink")
	actual, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
