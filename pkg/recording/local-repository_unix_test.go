//go:build unix

package recording

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
)

func TestLocalCastZstdRepositoryCompletesInterruptedHardlinkPublish(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	contentPath := filepath.Join(activeDirectory, localContentFileName)
	headPayload, err := loadLocalHead(filepath.Join(activeDirectory, localHeadFileName), maximumCastZstdHeadBytes)
	require.NoError(t, err)
	head, err := decodeCastZstdHead(headPayload)
	require.NoError(t, err)
	file, err := openActiveLocalFile(contentPath)
	require.NoError(t, err)
	_, err = RecoverCastZstd(file, identity, head, metadata.StartedAt.Add(2*time.Second), CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.NoError(t, sealLocalFile(contentPath, file))
	require.NoError(t, file.Close())
	target := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localSealedSuffix)
	require.NoError(t, os.Link(contentPath, target))
	require.NoError(t, syncLocalDirectory(filepath.Dir(target)))

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
	target := filepath.Join(root, localSealedDirectory, "34e34ab8-7457-4d88-a5e4-c57791775c3a.cast.zst")
	require.NoError(t, os.Symlink(filepath.Join(root, localLockFileName), target))
	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.Error(t, err)
}

func TestLocalCastZstdRepositoryQuarantinesWritableWorkHeadTemporary(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	headPath := filepath.Join(workDirectory, localHeadFileName)
	temporaryPath := filepath.Join(workDirectory, localHeadTempFileName)
	require.NoError(t, os.Rename(headPath, temporaryPath))
	require.NoError(t, os.Chmod(temporaryPath, localFileMode))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.Empty(t, repository.StartupRecoveries())
	require.NoError(t, repository.Close())
	_, err = os.Lstat(workDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp", localHeadTempFileName))
	require.NoError(t, err)
}

func TestLocalCastZstdRepositoryQuarantinesHardlinkedWorkHead(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	headPath := filepath.Join(workDirectory, localHeadFileName)
	externalLink := filepath.Join(filepath.Dir(root), "recording-head-link")
	require.NoError(t, os.Link(headPath, externalLink))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.Empty(t, repository.StartupRecoveries())
	require.NoError(t, repository.Close())
	_, err = os.Lstat(workDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	quarantinedHead := filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp", localHeadFileName)
	quarantinedInfo, err := os.Lstat(quarantinedHead)
	require.NoError(t, err)
	externalInfo, err := os.Lstat(externalLink)
	require.NoError(t, err)
	require.True(t, os.SameFile(quarantinedInfo, externalInfo))
}

func TestLocalCastZstdRepositoryQuarantinesWritableWorkContent(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	contentPath := filepath.Join(workDirectory, localContentFileName)
	require.NoError(t, os.Chmod(contentPath, 0666))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.Empty(t, repository.StartupRecoveries())
	require.NoError(t, repository.Close())
	_, err = os.Lstat(workDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	quarantined := filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp", localContentFileName)
	info, err := os.Lstat(quarantined)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0666), info.Mode().Perm())
}

func TestLocalCastZstdRepositoryRejectsPublishedWorkInodeReplacement(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	format := &localCastZstdFormat{
		identity: identity,
		options: CastZstdVerifyOptions{
			ExpectedProducerId: identity.ProducerId(),
		},
	}
	repository := &localRepository[audit.SessionRecordingZstdHead, CastZstdSummary]{
		identity: identity,
		format:   format,
	}
	validated, err := repository.validateWorkDirectory(t.Context(), metadata.RecordingId, workDirectory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, validated.close(nil)) })
	require.NoError(t, publishLocalDirectory(workDirectory, activeDirectory))
	contentPath := filepath.Join(activeDirectory, localContentFileName)
	payload, err := os.ReadFile(contentPath)
	require.NoError(t, err)
	require.NoError(t, os.Remove(contentPath))
	replacement, err := createLocalFile(contentPath)
	require.NoError(t, err)
	written, err := replacement.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), written)
	require.NoError(t, replacement.Close())

	err = repository.verifyPublishedWork(context.Background(), activeDirectory, validated)
	require.ErrorContains(t, err, "does not match its validated source")
	require.False(t, isInvalidLocalArtifact(err))
	_, inspectErr := os.Lstat(activeDirectory)
	require.NoError(t, inspectErr)
	_, inspectErr = os.Lstat(filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp"))
	require.ErrorIs(t, inspectErr, os.ErrNotExist)
}
