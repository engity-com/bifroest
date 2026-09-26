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
