//go:build darwin

package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinJournalFilesystemPrimitives(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	target := filepath.Join(directory, "target")
	require.NoError(t, os.WriteFile(source, []byte("evidence"), journalFileMode))

	require.NoError(t, publishJournalFile(source, target))
	require.NoFileExists(t, source)
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("evidence"), content)
	require.NoError(t, syncJournalDirectory(directory))
	available, err := availableJournalBytes(directory)
	require.NoError(t, err)
	require.Positive(t, available)
}
