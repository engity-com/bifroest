//go:build windows

package recording

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBindLocalFormatRejectsHardLinkedCleanupTombstone(t *testing.T) {
	root := t.TempDir()
	tombstone := filepath.Join(root, localFormatTempFileName+localRetentionTombstone)
	external := filepath.Join(t.TempDir(), "external")
	payload := []byte("must survive")
	require.NoError(t, os.WriteFile(external, payload, localFileMode))
	require.NoError(t, os.Link(external, tombstone))

	err := bindLocalFormat(root, "cast-zstd/v1")
	require.ErrorContains(t, err, "multiple hard links")
	actual, readErr := os.ReadFile(external)
	require.NoError(t, readErr)
	require.Equal(t, payload, actual)
}
