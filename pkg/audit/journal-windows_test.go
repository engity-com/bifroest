//go:build windows

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeJournalOperationsSupportLongWindowsPaths(t *testing.T) {
	directory := t.TempDir()
	for len(directory) < 280 {
		directory = filepath.Join(directory, strings.Repeat("a", 40))
	}
	require.NoError(t, os.MkdirAll(directory, 0700))
	require.NoError(t, secureJournalPath(directory))
	available, err := availableJournalBytes(directory)
	require.NoError(t, err)
	require.NotZero(t, available)

	source := filepath.Join(directory, "source")
	published := filepath.Join(directory, "published")
	replacement := filepath.Join(directory, "replacement")
	require.NoError(t, os.WriteFile(source, []byte("first"), journalFileMode))
	require.NoError(t, publishJournalFile(source, published))
	require.NoFileExists(t, source)
	require.FileExists(t, published)

	require.NoError(t, os.WriteFile(replacement, []byte("second"), journalFileMode))
	require.NoError(t, replaceJournalFile(replacement, published))
	require.NoFileExists(t, replacement)
	raw, err := os.ReadFile(published)
	require.NoError(t, err)
	require.Equal(t, []byte("second"), raw)
}

func TestSealedJournalWindowsPermissionsPreventContentWritesAndAllowRemoval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "segment.journal")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	require.NoError(t, err)
	require.NoError(t, sealJournalFile(path, file))
	require.NoError(t, file.Close())

	writable, err := os.OpenFile(path, os.O_WRONLY, journalFileMode)
	require.Error(t, err)
	if writable != nil {
		require.NoError(t, writable.Close())
	}
	require.NoError(t, os.Chmod(path, journalFileMode))
	require.NoError(t, os.Remove(path))
}

func TestJournalWindowsRejectsHardLinksBeforeSecuringFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "receipt.json")
	alias := filepath.Join(directory, "external.json")
	require.NoError(t, os.WriteFile(path, []byte("receipt"), journalFileMode))
	require.NoError(t, os.Link(path, alias))
	file, err := os.Open(path)
	require.NoError(t, err)
	require.ErrorContains(t, secureJournalFile(path, file), "hard links")
	require.NoError(t, file.Close())

	sealed, err := os.OpenFile(path, os.O_RDWR, journalFileMode)
	require.NoError(t, err)
	require.ErrorContains(t, sealJournalFile(path, sealed), "hard links")
	require.NoError(t, sealed.Close())
	_, err = openSealedJournal(path)
	require.ErrorContains(t, err, "hard links")
}
