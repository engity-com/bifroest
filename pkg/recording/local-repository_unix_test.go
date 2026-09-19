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
	"github.com/engity-com/bifroest/pkg/errors"
)

func TestLocalCastZstdRepositoryCompletesInterruptedHardlinkPublish(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	contentPath := filepath.Join(activeDirectory, localCastZstdContentFileName)
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
	target := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localCastZstdSealedSuffix)
	require.NoError(t, os.Link(contentPath, target))
	require.NoError(t, syncLocalDirectory(filepath.Dir(target)))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	_, err = os.Lstat(activeDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	info, err := os.Lstat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0400), info.Mode().Perm())
}

func TestInventoryLocalFilesCountsHardlinksOnceAndDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	external := filepath.Join(t.TempDir(), "external")
	require.NoError(t, os.WriteFile(first, []byte("content"), localFileMode))
	require.NoError(t, os.Link(first, second))
	require.NoError(t, os.WriteFile(external, []byte("not inventory"), localFileMode))
	require.NoError(t, os.Symlink(external, filepath.Join(root, "link")))

	usage, err := inventoryLocalFiles(root)
	require.NoError(t, err)
	require.Equal(t, uint64(len("content")), usage)
}

func TestLocalRepositoryCompletesInterruptedFormatHardlinkPublish(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	target := filepath.Join(root, localFormatFileName)
	temporary := filepath.Join(root, localFormatTempFileName)
	require.NoError(t, os.Rename(target, temporary))
	require.NoError(t, os.Link(temporary, target))
	require.NoError(t, syncLocalDirectory(root))

	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	_, err = os.Lstat(temporary)
	require.ErrorIs(t, err, os.ErrNotExist)
	info, err := os.Lstat(target)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0400), info.Mode().Perm())
	require.Equal(t, uint64(1), hardLinkCount(info))
}

func TestLocalRepositoryRejectsInsecureFormatMarker(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "writable",
			mutate: func(t *testing.T, marker string) {
				t.Helper()
				require.NoError(t, os.Chmod(marker, localFileMode))
			},
		},
		{
			name: "multiple-links",
			mutate: func(t *testing.T, marker string) {
				t.Helper()
				require.NoError(t, os.Link(marker, filepath.Join(filepath.Dir(filepath.Dir(marker)), "format-link")))
			},
		},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, _, _ := castTestValues(t, true)
			repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			require.NoError(t, repository.Close())
			current.mutate(t, filepath.Join(root, localFormatFileName))

			_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
			require.Error(t, err)
			require.True(t, errors.Config.IsErr(err))
		})
	}
}

func TestLocalRepositoryPreservesUnsafeWritableFormatTemporary(t *testing.T) {
	for _, current := range []struct {
		name   string
		create func(*testing.T, string, string)
	}{
		{
			name: "symlink",
			create: func(t *testing.T, root, temporary string) {
				t.Helper()
				require.NoError(t, os.Symlink(filepath.Join(root, localLockFileName), temporary))
			},
		},
		{
			name: "hardlink",
			create: func(t *testing.T, _, temporary string) {
				t.Helper()
				external := filepath.Join(filepath.Dir(filepath.Dir(temporary)), "format-temporary-source")
				file, err := createLocalFile(external)
				require.NoError(t, err)
				_, err = file.Write([]byte("partial"))
				require.NoError(t, err)
				require.NoError(t, file.Close())
				require.NoError(t, os.Link(external, temporary))
			},
		},
	} {
		t.Run(current.name, func(t *testing.T) {
			root := prepareUnboundLocalTestRoot(t)
			temporary := filepath.Join(root, localFormatTempFileName)
			current.create(t, root, temporary)
			before, err := os.Lstat(temporary)
			require.NoError(t, err)
			identity, _, _ := castTestValues(t, true)

			_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
			require.Error(t, err)
			require.True(t, errors.Config.IsErr(err))
			after, inspectErr := os.Lstat(temporary)
			require.NoError(t, inspectErr)
			require.Equal(t, before.Mode(), after.Mode())
			require.NoFileExists(t, filepath.Join(root, localFormatFileName))
		})
	}
}

func TestLocalBECastRepositoryWrongRecipientLeavesProtectedActiveUnchanged(t *testing.T) {
	root, identity, _, _, metadata := closedActiveLocalBECastTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	contentPath := filepath.Join(activeDirectory, localBECastContentFileName)
	require.NoError(t, os.Chmod(contentPath, 0400))
	contentBefore, err := os.ReadFile(contentPath)
	require.NoError(t, err)
	wrongRecipient, _ := newBECastTestEncryptionWithByte(t, 0x71)

	_, err = NewLocalBECastRepository(t.Context(), root, identity, wrongRecipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.ErrorContains(t, err, "recipient does not match")
	require.True(t, errors.Config.IsErr(err))
	contentAfter, readErr := os.ReadFile(contentPath)
	require.NoError(t, readErr)
	require.Equal(t, contentBefore, contentAfter)
	info, inspectErr := os.Lstat(contentPath)
	require.NoError(t, inspectErr)
	require.Equal(t, os.FileMode(0400), info.Mode().Perm())
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localBECastSealedSuffix))
}

func TestLocalCastZstdRepositoryRejectsSealedSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	target := filepath.Join(root, localSealedDirectory, "34e34ab8-7457-4d88-a5e4-c57791775c3a.cast.zst")
	require.NoError(t, os.Symlink(filepath.Join(root, localLockFileName), target))
	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
}

func TestLocalRepositoryRejectsDeliveryStateSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(root, localDeliveryDirectory)))

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.ErrorContains(t, err, "delivery state is not a regular directory")
	require.True(t, errors.Config.IsErr(err))
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

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
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

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
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
	contentPath := filepath.Join(workDirectory, localCastZstdContentFileName)
	require.NoError(t, os.Chmod(contentPath, 0666))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Empty(t, repository.StartupRecoveries())
	require.NoError(t, repository.Close())
	_, err = os.Lstat(workDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	quarantined := filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp", localCastZstdContentFileName)
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
	contentPath := filepath.Join(activeDirectory, localCastZstdContentFileName)
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
