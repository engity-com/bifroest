//go:build windows

package recording

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordingSnapshotWindowsDeniesSecondWriter(t *testing.T) {
	fixture := createRecordingFixture(t)
	input, info, err := OpenRecordingInput(fixture.clear)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, input.Close()) })
	snapshot, err := snapshotRecordingInput(input, info.Size())
	require.NoError(t, err)
	defer func() {
		require.NoError(t, snapshot.Close())
		require.NoFileExists(t, snapshot.Name())
	}()
	second, err := os.OpenFile(snapshot.Name(), os.O_WRONLY, 0)
	require.Error(t, err)
	if second != nil {
		require.NoError(t, second.Close())
	}
}

func setRecordingSnapshotTestDirectory(t *testing.T, path string) {
	t.Helper()
	t.Setenv("TMP", path)
	t.Setenv("TEMP", path)
	require.Equal(t, path, os.TempDir())
}
