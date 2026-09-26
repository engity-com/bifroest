package recording

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

type nativeSafetyPreparerFunc func(context.Context, audit.RemoteArtifact, time.Time) error

func (f nativeSafetyPreparerFunc) Prepare(ctx context.Context, artifact audit.RemoteArtifact, at time.Time) error {
	return f(ctx, artifact, at)
}

func (f nativeSafetyPreparerFunc) Require(ctx context.Context, artifact audit.RemoteArtifact) error {
	return f(ctx, artifact, time.Time{})
}

func TestLocalNativeRepositoryMarkerlessContentIsNotBound(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	require.NoError(t, os.Mkdir(root, localDirectoryMode))
	content := filepath.Join(root, "existing.bcast")
	before := []byte("existing recording data")
	require.NoError(t, os.WriteFile(content, before, localFileMode))
	identity, _, _ := castTestValues(t, true)

	_, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.NoFileExists(t, filepath.Join(root, localFormatFileName))
	require.NoFileExists(t, filepath.Join(root, localFormatTempFileName))
	after, err := os.ReadFile(content)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestLocalNativeRepositoryMarkerlessActiveStateIsNotRecovered(t *testing.T) {
	root, identity, metadata := closedActiveNativeSafetyRepository(t)
	marker := filepath.Join(root, localFormatFileName)
	require.NoError(t, os.Remove(marker))
	active := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	content := filepath.Join(active, "recording.bcast")
	head := filepath.Join(active, localNativeHeadFileName)
	contentBefore, err := os.ReadFile(content)
	require.NoError(t, err)
	headBefore, err := os.ReadFile(head)
	require.NoError(t, err)

	_, err = NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.NoFileExists(t, marker)
	require.NoFileExists(t, filepath.Join(root, localFormatTempFileName))
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+".bcast"))
	contentAfter, err := os.ReadFile(content)
	require.NoError(t, err)
	require.Equal(t, contentBefore, contentAfter)
	headAfter, err := os.ReadFile(head)
	require.NoError(t, err)
	require.Equal(t, headBefore, headAfter)
}

func TestLocalNativeRepositoryDoesNotBindTemporaryAlongsideMarkerlessActiveState(t *testing.T) {
	root, identity, metadata := closedActiveNativeSafetyRepository(t)
	marker := filepath.Join(root, localFormatFileName)
	temporary := filepath.Join(root, localFormatTempFileName)
	require.NoError(t, os.Rename(marker, temporary))
	active := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	content := filepath.Join(active, "recording.bcast")
	head := filepath.Join(active, localNativeHeadFileName)
	paths := []string{temporary, content, head, filepath.Join(active, localRecoveryReserveName)}
	before := make([][]byte, len(paths))
	for i, path := range paths {
		var err error
		before[i], err = os.ReadFile(path)
		require.NoError(t, err)
	}

	_, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.NoFileExists(t, marker)
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+".bcast"))
	for i, path := range paths {
		after, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		require.Equal(t, before[i], after, path)
	}
}

func TestLocalNativeRepositoryPreservesConflictingFormatTemporary(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	require.NoError(t, os.Mkdir(root, localDirectoryMode))
	temporary := filepath.Join(root, localFormatTempFileName)
	before := []byte("becast-cbor/v1\n")
	file, err := createLocalFile(temporary)
	require.NoError(t, err)
	_, err = file.Write(before)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	identity, _, _ := castTestValues(t, true)

	_, err = NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.NoFileExists(t, filepath.Join(root, localFormatFileName))
	after, err := os.ReadFile(temporary)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestLocalNativeRepositoryRejectsFormatMarkerWithTemporaryWithoutRecovery(t *testing.T) {
	root, identity, metadata := closedActiveNativeSafetyRepository(t)
	marker := filepath.Join(root, localFormatFileName)
	temporary := filepath.Join(root, localFormatTempFileName)
	formatBefore, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.NoError(t, writeProtectedLocalFile(temporary, formatBefore))
	active := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	content := filepath.Join(active, "recording.bcast")
	head := filepath.Join(active, localNativeHeadFileName)
	contentBefore, err := os.ReadFile(content)
	require.NoError(t, err)
	headBefore, err := os.ReadFile(head)
	require.NoError(t, err)

	_, err = NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	for _, path := range []string{marker, temporary} {
		after, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		require.Equal(t, formatBefore, after, path)
	}
	contentAfter, err := os.ReadFile(content)
	require.NoError(t, err)
	require.Equal(t, contentBefore, contentAfter)
	headAfter, err := os.ReadFile(head)
	require.NoError(t, err)
	require.Equal(t, headBefore, headAfter)
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+".bcast"))
}

func TestLocalNativeRepositoryDoesNotPublishOnReceiptPreparationFailure(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "clear"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, header, metadata := castTestValues(t, true)
			var recipient *bfcrypto.AgeSshRecipient
			suffix := ".bcast"
			if encrypted {
				recipient, _ = newBECastTestEncryption(t)
				suffix = ".becast"
			}
			name := metadata.RecordingId.String() + suffix
			failure := stderrors.New("injected receipt preparation failure")
			called := false
			preparer := nativeSafetyPreparerFunc(func(ctx context.Context, artifact audit.RemoteArtifact, at time.Time) error {
				called = true
				require.NoError(t, ctx.Err())
				require.Equal(t, name, artifact.FileName())
				require.NoError(t, artifact.ValidateContext(ctx))
				require.NoFileExists(t, filepath.Join(root, localSealedDirectory, name))
				return failure
			})
			repo, err := NewLocalNativeRecordingRepositoryWithArtifactPreparer(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions, preparer)
			require.NoError(t, err)
			active, err := repo.CreateActive(t.Context(), header, metadata, 0)
			require.NoError(t, err)
			require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("retain on receipt failure")))
			_, err = active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, sealedArtifactUint32(0))
			require.ErrorIs(t, err, failure)
			require.True(t, called)
			activeDir := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
			content := filepath.Join(activeDir, "recording"+suffix)
			before, err := os.ReadFile(content)
			require.NoError(t, err)
			require.NotEmpty(t, before)
			require.FileExists(t, filepath.Join(activeDir, localNativeHeadFileName))
			require.NoFileExists(t, filepath.Join(root, localSealedDirectory, name))
			require.ErrorIs(t, repo.Close(), failure)
			after, err := os.ReadFile(content)
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.NoFileExists(t, filepath.Join(root, localSealedDirectory, name))
		})
	}
}

func closedActiveNativeSafetyRepository(t *testing.T) (string, *audit.Identity, CastMetadata) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repo.CreateActive(t.Context(), header, metadata, 0)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("unrecovered recording")))
	require.NoError(t, active.Close())
	require.NoError(t, repo.Close())
	return root, identity, metadata
}
