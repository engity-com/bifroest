package recording

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

var localRepositoryTestOptions = LocalRepositoryOptions{MaximumSpoolBytes: 1 << 60}

func TestCastZstdHeadCanonicalRoundTrip(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastZstdWriter(&output, identity, header, metadata, 0)
	require.NoError(t, err)
	head, err := writer.Checkpoint()
	require.NoError(t, err)
	payload, err := encodeCastZstdHead(head)
	require.NoError(t, err)
	decoded, err := decodeCastZstdHead(payload)
	require.NoError(t, err)
	require.Equal(t, head, decoded)
	require.NoError(t, audit.VerifySessionRecordingZstdHead(identity.PublicKey(), decoded))

	nonCanonical := []byte(strings.Replace(string(payload), head.LastUnitHash.String(), strings.ToUpper(head.LastUnitHash.String()), 1))
	_, err = decodeCastZstdHead(nonCanonical)
	require.ErrorContains(t, err, "canonically")
}

func TestLocalCastZstdRepositoryCreateCheckpointAndSeal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("repository output\r\n")))
	require.NoError(t, active.Checkpoint())
	exitStatus := uint32(0)
	summary, err := active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	require.Equal(t, CastStatusCompleted, summary.Status)

	sealedPath := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localCastZstdSealedSuffix)
	file, err := openSealedLocalFile(sealedPath)
	require.NoError(t, err)
	info, err := file.Stat()
	require.NoError(t, err)
	verification, err := VerifyCastZstd(file, info.Size(), CastZstdVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, summary, verification.Summary)
	require.NoError(t, file.Close())
	_, err = os.Stat(filepath.Join(root, localActiveDirectory, metadata.RecordingId.String()))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestLocalCastZstdRepositoryRecoversClosedActive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("interrupted\r\n")))
	require.NoError(t, active.Close())
	require.NoError(t, repository.Close())

	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	recoveries := reopened.StartupRecoveries()
	require.Len(t, recoveries, 1)
	require.Equal(t, metadata.RecordingId, recoveries[0].Summary.RecordingId)
	require.Equal(t, CastStatusIncomplete, recoveries[0].Summary.Status)
	require.NoError(t, reopened.Close())

	sealedPath := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localCastZstdSealedSuffix)
	file, err := openSealedLocalFile(sealedPath)
	require.NoError(t, err)
	info, err := file.Stat()
	require.NoError(t, err)
	verification, err := VerifyCastZstd(file, info.Size(), CastZstdVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, startupRecoveryReason, verification.Cast.Result.Reason)
	require.NoError(t, file.Close())
}

func TestLocalCastZstdRepositoryLockIsExclusive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	first, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.NoError(t, first.Close())
	second, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, second.Close())
}

func TestLocalRepositoryFormatMarkerReopensWithSameFormat(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())

	payload, err := os.ReadFile(filepath.Join(root, localFormatFileName))
	require.NoError(t, err)
	require.Equal(t, localCastZstdFormatKey+"\n", string(payload))
	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}

func TestLocalRepositoryMarkerlessNonemptyRootIsNotBound(t *testing.T) {
	root := prepareUnboundLocalTestRoot(t)
	legacy := filepath.Join(root, "legacy-recording.cast.zst")
	require.NoError(t, os.WriteFile(legacy, []byte("legacy repository state"), localFileMode))
	before, err := os.ReadFile(legacy)
	require.NoError(t, err)
	identity, _, _ := castTestValues(t, true)

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.NoFileExists(t, filepath.Join(root, localFormatFileName))
	require.NoFileExists(t, filepath.Join(root, localFormatTempFileName))
	after, readErr := os.ReadFile(legacy)
	require.NoError(t, readErr)
	require.Equal(t, before, after)
}

func TestLocalRepositoryMarkerlessZstdRootRejectsBECastWithoutMutation(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	require.NoError(t, os.Remove(filepath.Join(root, localFormatFileName)))
	contentPath := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String(), localCastZstdContentFileName)
	headPath := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String(), localHeadFileName)
	contentBefore, err := os.ReadFile(contentPath)
	require.NoError(t, err)
	headBefore, err := os.ReadFile(headPath)
	require.NoError(t, err)
	recipient, _ := newBECastTestEncryption(t)

	_, err = NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.NoFileExists(t, filepath.Join(root, localFormatFileName))
	require.NoFileExists(t, filepath.Join(root, localFormatTempFileName))
	contentAfter, readErr := os.ReadFile(contentPath)
	require.NoError(t, readErr)
	headAfter, readErr := os.ReadFile(headPath)
	require.NoError(t, readErr)
	require.Equal(t, contentBefore, contentAfter)
	require.Equal(t, headBefore, headAfter)
}

func TestLocalRepositoryFreshRootContainingOnlyLockCanBind(t *testing.T) {
	root := prepareUnboundLocalTestRoot(t)
	identity, _, _ := castTestValues(t, true)

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	require.FileExists(t, filepath.Join(root, localFormatFileName))
}

func TestLocalRepositoryFormatMarkerRejectsCrossFormatOpen(t *testing.T) {
	for _, first := range []string{"cast-zstd", "becast"} {
		t.Run(first+"-first", func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, _, _ := castTestValues(t, true)
			recipient, _ := newBECastTestEncryption(t)
			if first == "cast-zstd" {
				repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
				require.NoError(t, err)
				require.NoError(t, repository.Close())
				_, err = NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
				require.Error(t, err)
				require.True(t, bferrors.Config.IsErr(err))
			} else {
				repository, err := NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
				require.NoError(t, err)
				require.NoError(t, repository.Close())
				_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
				require.Error(t, err)
				require.True(t, bferrors.Config.IsErr(err))
			}
		})
	}
}

func TestLocalRepositoryFormatMarkerRejectsMalformedContent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	marker := filepath.Join(root, localFormatFileName)
	require.NoError(t, os.Remove(marker))
	require.NoError(t, writeProtectedLocalFile(marker, []byte("cast-zstd/v1")))

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	payload, readErr := os.ReadFile(marker)
	require.NoError(t, readErr)
	require.Equal(t, "cast-zstd/v1", string(payload))
}

func TestLocalRepositoryCompletesInterruptedFormatTemporary(t *testing.T) {
	root := prepareUnboundLocalTestRoot(t)
	identity, _, _ := castTestValues(t, true)
	target := filepath.Join(root, localFormatFileName)
	temporary := filepath.Join(root, localFormatTempFileName)
	require.NoError(t, writeProtectedLocalFile(temporary, []byte(localCastZstdFormatKey+"\n")))

	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	require.FileExists(t, target)
	require.NoFileExists(t, temporary)
}

func TestLocalRepositoryDoesNotBindValidFormatTemporaryAlongsideMarkerlessState(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	target := filepath.Join(root, localFormatFileName)
	temporary := filepath.Join(root, localFormatTempFileName)
	require.NoError(t, os.Rename(target, temporary))
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	contentPath := filepath.Join(activeDirectory, localCastZstdContentFileName)
	headPath := filepath.Join(activeDirectory, localHeadFileName)
	temporaryBefore, err := os.ReadFile(temporary)
	require.NoError(t, err)
	contentBefore, err := os.ReadFile(contentPath)
	require.NoError(t, err)
	headBefore, err := os.ReadFile(headPath)
	require.NoError(t, err)

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.NoFileExists(t, target)
	temporaryAfter, readErr := os.ReadFile(temporary)
	require.NoError(t, readErr)
	contentAfter, readErr := os.ReadFile(contentPath)
	require.NoError(t, readErr)
	headAfter, readErr := os.ReadFile(headPath)
	require.NoError(t, readErr)
	require.Equal(t, temporaryBefore, temporaryAfter)
	require.Equal(t, contentBefore, contentAfter)
	require.Equal(t, headBefore, headAfter)
}

func TestLocalRepositoryProtectsAndPublishesWritableFormatTemporary(t *testing.T) {
	root := prepareUnboundLocalTestRoot(t)
	temporary := filepath.Join(root, localFormatTempFileName)
	file, err := createLocalFile(temporary)
	require.NoError(t, err)
	_, err = file.Write([]byte(localCastZstdFormatKey + "\n"))
	require.NoError(t, err)
	require.NoError(t, file.Close())
	identity, _, _ := castTestValues(t, true)

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	require.NoFileExists(t, temporary)
	payload, err := os.ReadFile(filepath.Join(root, localFormatFileName))
	require.NoError(t, err)
	require.Equal(t, localCastZstdFormatKey+"\n", string(payload))
}

func TestLocalRepositoryRetriesMalformedWritableFormatTemporary(t *testing.T) {
	for _, current := range []struct {
		name  string
		value []byte
	}{
		{name: "empty"},
		{name: "partial", value: []byte("cast-zstd/")},
		{name: "malformed", value: []byte("not a key\n")},
	} {
		t.Run(current.name, func(t *testing.T) {
			root := prepareUnboundLocalTestRoot(t)
			temporary := filepath.Join(root, localFormatTempFileName)
			file, err := createLocalFile(temporary)
			require.NoError(t, err)
			_, err = file.Write(current.value)
			require.NoError(t, err)
			require.NoError(t, file.Close())
			identity, _, _ := castTestValues(t, true)

			repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			require.NoError(t, repository.Close())
			require.NoFileExists(t, temporary)
			payload, err := os.ReadFile(filepath.Join(root, localFormatFileName))
			require.NoError(t, err)
			require.Equal(t, localCastZstdFormatKey+"\n", string(payload))
		})
	}
}

func TestLocalRepositoryPreservesMalformedWritableFormatTemporaryAlongsideState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	require.NoError(t, os.Remove(filepath.Join(root, localFormatFileName)))
	temporary := filepath.Join(root, localFormatTempFileName)
	file, err := createLocalFile(temporary)
	require.NoError(t, err)
	value := []byte("partial")
	_, err = file.Write(value)
	require.NoError(t, err)
	require.NoError(t, file.Close())

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.NoFileExists(t, filepath.Join(root, localFormatFileName))
	payload, readErr := os.ReadFile(temporary)
	require.NoError(t, readErr)
	require.Equal(t, value, payload)
}

func TestLocalRepositoryPreservesWritableTemporaryForDifferentFormat(t *testing.T) {
	root := prepareUnboundLocalTestRoot(t)
	temporary := filepath.Join(root, localFormatTempFileName)
	file, err := createLocalFile(temporary)
	require.NoError(t, err)
	value := []byte(localBECastFormatKey + "\n")
	_, err = file.Write(value)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	identity, _, _ := castTestValues(t, true)

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	require.NoFileExists(t, filepath.Join(root, localFormatFileName))
	payload, readErr := os.ReadFile(temporary)
	require.NoError(t, readErr)
	require.Equal(t, value, payload)
	recipient, _ := newBECastTestEncryption(t)
	repository, err := NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	require.NoFileExists(t, temporary)
	payload, readErr = os.ReadFile(filepath.Join(root, localFormatFileName))
	require.NoError(t, readErr)
	require.Equal(t, value, payload)
}

func TestLocalRepositoryFormatMarkerRejectsConflictingTemporary(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	temporary := filepath.Join(root, localFormatTempFileName)
	require.NoError(t, writeProtectedLocalFile(temporary, []byte(localCastZstdFormatKey+"\n")))

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.Error(t, err)
	require.True(t, bferrors.Config.IsErr(err))
	_, inspectErr := os.Lstat(temporary)
	require.NoError(t, inspectErr)
}

func TestLocalCastZstdRepositoryCanceledEmptyStartupDoesNotCreateRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := NewLocalCastZstdRepository(ctx, root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.ErrorIs(t, err, context.Canceled)
	_, inspectErr := os.Lstat(root)
	require.ErrorIs(t, inspectErr, os.ErrNotExist)
}

func TestLocalCastZstdRepositoryRecoversPublishedHeadTemporary(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	require.NoError(t, os.Rename(
		filepath.Join(activeDirectory, localHeadFileName),
		filepath.Join(activeDirectory, localHeadTempFileName),
	))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Len(t, repository.StartupRecoveries(), 1)
	require.NoError(t, repository.Close())
}

func TestLocalCastZstdRepositoryRecoversCommittedWorkDirectory(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Len(t, repository.StartupRecoveries(), 1)
	require.NoError(t, repository.Close())
	_, err = os.Lstat(workDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(activeDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localCastZstdSealedSuffix))
	require.NoError(t, err)
}

func TestLocalCastZstdRepositoryRecoversCommittedWorkDirectoryWithHeadTemporary(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	require.NoError(t, os.Rename(
		filepath.Join(workDirectory, localHeadFileName),
		filepath.Join(workDirectory, localHeadTempFileName),
	))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Len(t, repository.StartupRecoveries(), 1)
	require.NoError(t, repository.Close())
	_, err = os.Lstat(workDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localCastZstdSealedSuffix))
	require.NoError(t, err)
}

func TestLocalCastZstdRepositoryCanceledStartupLeavesValidWorkInPlace(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := NewLocalCastZstdRepository(ctx, root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.ErrorIs(t, err, context.Canceled)
	_, err = os.Lstat(workDirectory)
	require.NoError(t, err)
	_, err = os.Lstat(activeDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestLocalCastZstdRepositoryRestrictiveLimitsDoNotQuarantineValidWork(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	contentPath := filepath.Join(activeDirectory, localCastZstdContentFileName)
	contentBefore, err := os.ReadFile(contentPath)
	require.NoError(t, err)
	require.NoError(t, os.Rename(activeDirectory, workDirectory))

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{
		MaximumContainerBytes: 1,
		MaximumCastBytes:      1,
		MaximumChunks:         1,
	}, localRepositoryTestOptions)
	require.Error(t, err)
	_, err = os.Lstat(workDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(activeDirectory)
	require.NoError(t, err)
	_, err = os.Lstat(filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp"))
	require.ErrorIs(t, err, os.ErrNotExist)
	contentAfter, err := os.ReadFile(contentPath)
	require.NoError(t, err)
	require.Equal(t, contentBefore, contentAfter)
}

func TestLocalCastZstdWorkValidationTreatsReadFailureAsOperational(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewCastZstdWriter(&output, identity, header, metadata, 300)
	require.NoError(t, err)
	head, err := writer.Checkpoint()
	require.NoError(t, err)
	format := &localCastZstdFormat{
		identity: identity,
		options: CastZstdVerifyOptions{
			ExpectedProducerId: identity.ProducerId(),
		},
	}

	err = format.verifyWorkCheckpointReader(localReadFailure{}, int64(output.Len()), head, t.Context())
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.False(t, isInvalidLocalArtifact(err))
}

func TestLocalCastZstdWorkVerifyOptionsNormalizeLimits(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name     string
		input    CastZstdVerifyOptions
		expected CastZstdVerifyOptions
	}{
		{
			name: "zero",
			expected: CastZstdVerifyOptions{
				MaximumContainerBytes: DefaultMaximumCastZstdBytes,
				MaximumCastBytes:      DefaultMaximumCastBytes,
				MaximumChunks:         DefaultMaximumCastZstdChunks,
			},
		},
		{
			name: "restrictive",
			input: CastZstdVerifyOptions{
				MaximumContainerBytes: 1,
				MaximumCastBytes:      1,
				MaximumChunks:         1,
			},
			expected: CastZstdVerifyOptions{
				MaximumContainerBytes: DefaultMaximumCastZstdBytes,
				MaximumCastBytes:      DefaultMaximumCastBytes,
				MaximumChunks:         DefaultMaximumCastZstdChunks,
			},
		},
		{
			name: "elevated",
			input: CastZstdVerifyOptions{
				MaximumContainerBytes: DefaultMaximumCastZstdBytes + 1,
				MaximumCastBytes:      DefaultMaximumCastBytes + 2,
				MaximumChunks:         DefaultMaximumCastZstdChunks + 3,
			},
			expected: CastZstdVerifyOptions{
				MaximumContainerBytes: DefaultMaximumCastZstdBytes + 1,
				MaximumCastBytes:      DefaultMaximumCastBytes + 2,
				MaximumChunks:         DefaultMaximumCastZstdChunks + 3,
			},
		},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			options, err := (&localCastZstdFormat{options: current.input}).workVerifyOptions(ctx)
			require.NoError(t, err)
			current.expected.Context = ctx
			require.Equal(t, current.expected, options)
		})
	}
}

func TestLocalCastZstdWorkVerifyOptionsRejectNegativeLimits(t *testing.T) {
	for _, options := range []CastZstdVerifyOptions{
		{MaximumContainerBytes: -1},
		{MaximumCastBytes: -1},
	} {
		_, err := (&localCastZstdFormat{options: options}).workVerifyOptions(t.Context())
		require.Error(t, err)
		require.True(t, bferrors.Config.IsErr(err))
		require.False(t, isInvalidLocalArtifact(err))
	}
}

func TestLocalCastZstdRepositoryQuarantinesInvalidCommittedWork(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *audit.Identity, audit.SessionRecordingZstdHead) audit.SessionRecordingZstdHead
	}{
		{
			name: "bad signature",
			mutate: func(t *testing.T, _ *audit.Identity, head audit.SessionRecordingZstdHead) audit.SessionRecordingZstdHead {
				t.Helper()
				head.Signature = append([]byte(nil), head.Signature...)
				head.Signature[0] ^= 1
				return head
			},
		},
		{
			name: "wrong recording ID",
			mutate: func(t *testing.T, identity *audit.Identity, head audit.SessionRecordingZstdHead) audit.SessionRecordingZstdHead {
				t.Helper()
				head.RecordingId = uuid.MustParse("c2691eb9-e8b8-4395-83df-5d90a9581d7e")
				head, err := identity.NewSessionRecordingZstdHead(head)
				require.NoError(t, err)
				return head
			},
		},
		{
			name: "wrong producer",
			mutate: func(t *testing.T, _ *audit.Identity, head audit.SessionRecordingZstdHead) audit.SessionRecordingZstdHead {
				t.Helper()
				otherIdentity, _, _ := castTestValuesWithSeed(t, true, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
				head, err := otherIdentity.NewSessionRecordingZstdHead(head)
				require.NoError(t, err)
				return head
			},
		},
		{
			name: "head content mismatch",
			mutate: func(t *testing.T, identity *audit.Identity, head audit.SessionRecordingZstdHead) audit.SessionRecordingZstdHead {
				t.Helper()
				head.LastUnitHash[0] ^= 1
				head, err := identity.NewSessionRecordingZstdHead(head)
				require.NoError(t, err)
				return head
			},
		},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			root, identity, metadata := closedActiveLocalTestRepository(t)
			activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
			workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
			require.NoError(t, os.Rename(activeDirectory, workDirectory))
			replaceLocalTestHead(t, workDirectory, func(head audit.SessionRecordingZstdHead) audit.SessionRecordingZstdHead {
				return current.mutate(t, identity, head)
			})

			repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			require.Empty(t, repository.StartupRecoveries())
			require.NoError(t, repository.Close())
			_, err = os.Lstat(workDirectory)
			require.ErrorIs(t, err, os.ErrNotExist)
			_, err = os.Lstat(activeDirectory)
			require.ErrorIs(t, err, os.ErrNotExist)
			_, err = os.Lstat(filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp", localCastZstdContentFileName))
			require.NoError(t, err)
		})
	}
}

func TestLocalCastZstdRepositoryQuarantinesCommittedWorkWithInvalidHead(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	headPath := filepath.Join(workDirectory, localHeadFileName)
	require.NoError(t, os.Remove(headPath))
	head, err := createLocalFile(headPath)
	require.NoError(t, err)
	_, err = head.Write([]byte("not a recording head"))
	require.NoError(t, err)
	require.NoError(t, protectLocalReadOnlyFile(headPath, head))
	require.NoError(t, head.Close())

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Empty(t, repository.StartupRecoveries())
	require.NoError(t, repository.Close())
	_, err = os.Lstat(workDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp", localHeadFileName))
	require.NoError(t, err)
}

func TestLocalCastZstdRepositoryQuarantinesCommittedWorkWithOversizedHead(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	headPath := filepath.Join(workDirectory, localHeadFileName)
	require.NoError(t, os.Remove(headPath))
	head, err := createLocalFile(headPath)
	require.NoError(t, err)
	written, err := head.Write(make([]byte, maximumCastZstdHeadBytes+1))
	require.NoError(t, err)
	require.Equal(t, maximumCastZstdHeadBytes+1, written)
	require.NoError(t, protectLocalReadOnlyFile(headPath, head))
	require.NoError(t, head.Close())

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Empty(t, repository.StartupRecoveries())
	require.NoError(t, repository.Close())
	_, err = os.Lstat(workDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp", localHeadFileName))
	require.NoError(t, err)
}

func TestLocalCastZstdRepositoryQuarantinesUncommittedWork(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	work := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, ensureLocalDirectory(work))
	file, err := createLocalFile(filepath.Join(work, localCastZstdContentFileName))
	require.NoError(t, err)
	_, err = file.Write([]byte("partial"))
	require.NoError(t, err)
	require.NoError(t, file.Close())

	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	_, err = os.Lstat(work)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp", localCastZstdContentFileName))
	require.NoError(t, err)
}

func TestLocalCastZstdRepositoryCompletesPublishedWithEmptyActiveDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("published before cleanup\r\n")))
	exitStatus := uint32(0)
	_, err = active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	require.NoError(t, ensureLocalDirectory(activeDirectory))

	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Empty(t, reopened.StartupRecoveries())
	require.NoError(t, reopened.Close())
	_, err = os.Lstat(activeDirectory)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localCastZstdSealedSuffix))
	require.NoError(t, err)
}

func TestLocalCastZstdRepositoryRejectsMissingActiveContentWithoutSealedTarget(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	require.NoError(t, ensureLocalDirectory(activeDirectory))

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.ErrorContains(t, err, "sealed target is unavailable")
	info, inspectErr := os.Lstat(activeDirectory)
	require.NoError(t, inspectErr)
	require.True(t, info.IsDir())
	_, inspectErr = os.Lstat(filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localCastZstdSealedSuffix))
	require.ErrorIs(t, inspectErr, os.ErrNotExist)
}

func TestLocalCastZstdRepositorySerializesConcurrentOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, false)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 0)
	require.NoError(t, err)
	var wait sync.WaitGroup
	errors := make(chan error, 32)
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- active.WriteOutput(time.Second, OutputStreamStdout, []byte("x"))
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.NoError(t, active.Close())
	require.NoError(t, repository.Close())

	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Len(t, reopened.StartupRecoveries(), 1)
	require.NoError(t, reopened.Close())
}

func TestLocalActiveCloseReleasesWriterAfterCheckpointFailure(t *testing.T) {
	root := t.TempDir()
	lockPath := filepath.Join(root, localLockFileName)
	processLock, err := acquireLocalProcessLock(lockPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, processLock.Close()) })
	contentPath := filepath.Join(root, "recording.cast.zst")
	file, err := createLocalFile(contentPath)
	require.NoError(t, err)
	writer := &failingCloseLocalWriter{}
	active := &localActive[audit.SessionRecordingZstdHead, CastZstdSummary]{
		repository: &localRepository[audit.SessionRecordingZstdHead, CastZstdSummary]{
			processLock: processLock,
			lockPath:    lockPath,
		},
		path:   contentPath,
		file:   file,
		writer: writer,
	}

	err = active.close(false)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, 1, writer.releaseCount)
	_, writeErr := file.Write([]byte("closed"))
	require.Error(t, writeErr)

	err = active.close(false)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, 1, writer.releaseCount)
}

func closedActiveLocalTestRepository(t *testing.T) (string, *audit.Identity, CastMetadata) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("interrupted\r\n")))
	require.NoError(t, active.Close())
	require.NoError(t, repository.Close())
	return root, identity, metadata
}

func prepareUnboundLocalTestRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "recordings")
	require.NoError(t, ensureLocalDirectory(root))
	lock, err := createLocalFile(filepath.Join(root, localLockFileName))
	require.NoError(t, err)
	require.NoError(t, lock.Close())
	return root
}

func replaceLocalTestHead(t *testing.T, directory string, mutate func(audit.SessionRecordingZstdHead) audit.SessionRecordingZstdHead) {
	t.Helper()
	path := filepath.Join(directory, localHeadFileName)
	payload, err := loadLocalHead(path, maximumCastZstdHeadBytes)
	require.NoError(t, err)
	head, err := decodeCastZstdHead(payload)
	require.NoError(t, err)
	payload, err = encodeCastZstdHead(mutate(head))
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))
	require.NoError(t, writeLocalHead(directory, payload, nil))
}

type localReadFailure struct{}

func (localReadFailure) ReadAt([]byte, int64) (int, error) {
	return 0, io.ErrClosedPipe
}

type failingCloseLocalWriter struct {
	releaseCount int
}

func (*failingCloseLocalWriter) WriteOutput(time.Duration, OutputStream, []byte) error { return nil }

func (*failingCloseLocalWriter) WriteResize(time.Duration, uint32, uint32) error { return nil }

func (*failingCloseLocalWriter) WriteMarker(time.Duration, string) error { return nil }

func (*failingCloseLocalWriter) Checkpoint() (audit.SessionRecordingZstdHead, error) {
	return audit.SessionRecordingZstdHead{}, io.ErrClosedPipe
}

func (*failingCloseLocalWriter) Seal(time.Duration, CastResult, *uint32) (CastZstdSummary, error) {
	return CastZstdSummary{}, nil
}

func (*failingCloseLocalWriter) replaceOutput(io.Writer) error { return nil }

func (*failingCloseLocalWriter) repositoryFailure() error { return nil }

func (this *failingCloseLocalWriter) release() error {
	this.releaseCount++
	return io.ErrUnexpectedEOF
}
