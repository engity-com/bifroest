//go:build unix

package recording

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordingSnapshotUnixIsUnlinkedAndReadOnly(t *testing.T) {
	fixture := createRecordingFixture(t)
	input, info, err := OpenRecordingInput(fixture.clear)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, input.Close()) })
	snapshot, err := snapshotRecordingInput(input, info.Size())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, snapshot.Close()) })
	_, err = os.Stat(snapshot.Name())
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = snapshot.WriteAt([]byte("x"), 0)
	require.Error(t, err)
}

func setRecordingSnapshotTestDirectory(t *testing.T, path string) {
	t.Helper()
	t.Setenv("TMPDIR", path)
	require.Equal(t, path, os.TempDir())
}
