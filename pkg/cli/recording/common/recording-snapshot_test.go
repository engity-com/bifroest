package common

import (
	"bytes"
	stdos "os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/recording/export"
)

func TestRecordingExportRemovesSnapshotAfterVerificationFailure(t *testing.T) {
	snapshotDirectory := t.TempDir()
	setRecordingSnapshotTestDirectory(t, snapshotDirectory)
	input := filepath.Join(t.TempDir(), "invalid.cast")
	require.NoError(t, stdos.WriteFile(input, []byte("{\n"), 0600))

	err := export.doRecordingExport(&export.recordingExportOpts{file: input, allowUntrusted: true, withSensitive: true}, &bytes.Buffer{})
	require.Error(t, err)
	entries, readErr := stdos.ReadDir(snapshotDirectory)
	require.NoError(t, readErr)
	require.Empty(t, entries)
}

func TestRecordingExportRemovesNativeSnapshotAfterDecryptionFailure(t *testing.T) {
	fixture := export.newRecordingExportTestFixture(t)
	snapshotDirectory := t.TempDir()
	setRecordingSnapshotTestDirectory(t, snapshotDirectory)
	err := export.doRecordingExport(&export.recordingExportOpts{
		file: fixture.nativeEncryptedPath, expectedProducerId: fixture.identity.ProducerId().String(), withSensitive: true,
	}, &bytes.Buffer{})
	require.ErrorContains(t, err, "requires at least one --decryptionIdentityFile")
	entries, readErr := stdos.ReadDir(snapshotDirectory)
	require.NoError(t, readErr)
	require.Empty(t, entries)
}
