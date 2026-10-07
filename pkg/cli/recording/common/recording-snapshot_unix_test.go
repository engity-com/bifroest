//go:build unix

package common

import (
	stdos "os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/recording"
)

func TestRecordingSnapshotUnixIsUnlinkedAndReadOnly(t *testing.T) {
	path, _ := recording.writeRecordingInspectTestCast(t)
	input, info, err := openRecordingInput(path)
	require.NoError(t, err)
	defer input.Close()
	snapshot, err := snapshotRecordingInput(input, info.Size())
	require.NoError(t, err)
	defer snapshot.Close()

	_, err = stdos.Stat(snapshot.Name())
	require.ErrorIs(t, err, stdos.ErrNotExist)
	_, err = snapshot.WriteAt([]byte("x"), 0)
	require.Error(t, err)
}

func setRecordingSnapshotTestDirectory(t *testing.T, path string) {
	t.Helper()
	t.Setenv("TMPDIR", path)
	require.Equal(t, path, stdos.TempDir())
}
