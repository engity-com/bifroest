//go:build windows

package main

import (
	stdos "os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordingSnapshotWindowsDeniesSecondWriter(t *testing.T) {
	path, _ := writeRecordingInspectTestCast(t)
	input, info, err := openRecordingInput(path)
	require.NoError(t, err)
	defer input.Close()
	snapshot, err := snapshotRecordingInput(input, info.Size())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, snapshot.Close())
		require.NoError(t, stdos.Remove(snapshot.Name()))
	}()

	second, err := stdos.OpenFile(snapshot.Name(), stdos.O_WRONLY, 0)
	require.Error(t, err)
	if second != nil {
		require.NoError(t, second.Close())
	}
}

func setRecordingSnapshotTestDirectory(t *testing.T, path string) {
	t.Helper()
	t.Setenv("TMP", path)
	t.Setenv("TEMP", path)
	require.Equal(t, path, stdos.TempDir())
}
