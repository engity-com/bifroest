//go:build darwin

package audit

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinJournalPublicationDoesNotClobberEvidence(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	target := filepath.Join(directory, "target")
	require.NoError(t, os.WriteFile(source, []byte("new"), journalFileMode))
	require.NoError(t, os.WriteFile(target, []byte("existing"), journalFileMode))

	err := publishJournalFile(source, target)
	require.ErrorIs(t, err, fs.ErrExist)
	require.FileExists(t, source)
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("existing"), content)
}

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
	info, err := os.Stat(target)
	require.NoError(t, err)
	require.Equal(t, uint16(1), info.Sys().(*syscall.Stat_t).Nlink)
	require.NoError(t, syncJournalDirectory(directory))
	available, err := availableJournalBytes(directory)
	require.NoError(t, err)
	require.Positive(t, available)
}
