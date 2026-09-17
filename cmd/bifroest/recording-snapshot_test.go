package main

import (
	"bytes"
	stdos "os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordingExportRemovesSnapshotAfterVerificationFailure(t *testing.T) {
	snapshotDirectory := t.TempDir()
	setRecordingSnapshotTestDirectory(t, snapshotDirectory)
	input := filepath.Join(t.TempDir(), "invalid.cast")
	require.NoError(t, stdos.WriteFile(input, []byte("{\n"), 0600))

	err := doRecordingExport(&recordingExportOpts{file: input, allowUntrusted: true}, &bytes.Buffer{})
	require.Error(t, err)
	entries, readErr := stdos.ReadDir(snapshotDirectory)
	require.NoError(t, readErr)
	require.Empty(t, entries)
}
