//go:build unix

package recording

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLocalCastZstdRepositoryCompletesInterruptedHardlinkPublish(t *testing.T) {
	root, identity, metadata := closedActiveLocalRecordingTestRepository(t)
	activeDirectory := filepath.Join(root, localRecordingActiveDirectory, metadata.RecordingId.String())
	contentPath := filepath.Join(activeDirectory, localRecordingContentFileName)
	headPayload, err := loadLocalRecordingHead(filepath.Join(activeDirectory, localRecordingHeadFileName))
	require.NoError(t, err)
	head, err := decodeCastZstdHead(headPayload)
	require.NoError(t, err)
	file, err := openActiveLocalRecordingFile(contentPath)
	require.NoError(t, err)
	_, err = RecoverCastZstd(file, identity, head, metadata.StartedAt.Add(2*time.Second), CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.NoError(t, sealLocalRecordingFile(contentPath, file))
	require.NoError(t, file.Close())
	target := filepath.Join(root, localRecordingSealedDirectory, metadata.RecordingId.String()+localRecordingSealedSuffix)
	require.NoError(t, os.Link(contentPath, target))
	require.NoError(t, syncLocalRecordingDirectory(filepath.Dir(target)))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	_, err = os.Lstat(activeDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	info, err := os.Lstat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0400), info.Mode().Perm())
}

func TestLocalCastZstdRepositoryRejectsSealedSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	target := filepath.Join(root, localRecordingSealedDirectory, "34e34ab8-7457-4d88-a5e4-c57791775c3a.cast.zst")
	require.NoError(t, os.Symlink(filepath.Join(root, localRecordingLockFileName), target))
	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.Error(t, err)
}
