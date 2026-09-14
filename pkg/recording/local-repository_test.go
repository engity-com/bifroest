package recording

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
)

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
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
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

	sealedPath := filepath.Join(root, localRecordingSealedDirectory, metadata.RecordingId.String()+localRecordingSealedSuffix)
	file, err := openSealedLocalRecordingFile(sealedPath)
	require.NoError(t, err)
	info, err := file.Stat()
	require.NoError(t, err)
	verification, err := VerifyCastZstd(file, info.Size(), CastZstdVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, summary, verification.Summary)
	require.NoError(t, file.Close())
	_, err = os.Stat(filepath.Join(root, localRecordingActiveDirectory, metadata.RecordingId.String()))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestLocalCastZstdRepositoryRecoversClosedActiveRecording(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("interrupted\r\n")))
	require.NoError(t, active.Close())
	require.NoError(t, repository.Close())

	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	recoveries := reopened.StartupRecoveries()
	require.Len(t, recoveries, 1)
	require.Equal(t, metadata.RecordingId, recoveries[0].Summary.RecordingId)
	require.Equal(t, CastStatusIncomplete, recoveries[0].Summary.Status)
	require.NoError(t, reopened.Close())

	sealedPath := filepath.Join(root, localRecordingSealedDirectory, metadata.RecordingId.String()+localRecordingSealedSuffix)
	file, err := openSealedLocalRecordingFile(sealedPath)
	require.NoError(t, err)
	info, err := file.Stat()
	require.NoError(t, err)
	verification, err := VerifyCastZstd(file, info.Size(), CastZstdVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, castZstdRecoveryReason, verification.Cast.Result.Reason)
	require.NoError(t, file.Close())
}

func TestLocalCastZstdRepositoryLockIsExclusive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	first, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.Error(t, err)
	require.NoError(t, first.Close())
	second, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.NoError(t, second.Close())
}

func TestLocalCastZstdRepositoryRecoversPublishedHeadTemporary(t *testing.T) {
	root, identity, metadata := closedActiveLocalRecordingTestRepository(t)
	activeDirectory := filepath.Join(root, localRecordingActiveDirectory, metadata.RecordingId.String())
	require.NoError(t, os.Rename(
		filepath.Join(activeDirectory, localRecordingHeadFileName),
		filepath.Join(activeDirectory, localRecordingHeadTempFileName),
	))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.Len(t, repository.StartupRecoveries(), 1)
	require.NoError(t, repository.Close())
}

func TestLocalCastZstdRepositoryRecoversCommittedWorkDirectory(t *testing.T) {
	root, identity, metadata := closedActiveLocalRecordingTestRepository(t)
	activeDirectory := filepath.Join(root, localRecordingActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localRecordingWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.Len(t, repository.StartupRecoveries(), 1)
	require.NoError(t, repository.Close())
}

func TestLocalCastZstdRepositoryQuarantinesUncommittedWork(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	work := filepath.Join(root, localRecordingWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, ensureLocalRecordingDirectory(work))
	file, err := createLocalRecordingFile(filepath.Join(work, localRecordingContentFileName))
	require.NoError(t, err)
	_, err = file.Write([]byte("partial"))
	require.NoError(t, err)
	require.NoError(t, file.Close())

	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
	_, err = os.Lstat(work)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Lstat(filepath.Join(root, localRecordingQuarantineDirectory, metadata.RecordingId.String()+".tmp", localRecordingContentFileName))
	require.NoError(t, err)
}

func TestLocalCastZstdRepositorySerializesConcurrentOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, false)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
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

	reopened, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	require.Len(t, reopened.StartupRecoveries(), 1)
	require.NoError(t, reopened.Close())
}

func closedActiveLocalRecordingTestRepository(t *testing.T) (string, *audit.Identity, CastMetadata) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{})
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("interrupted\r\n")))
	require.NoError(t, active.Close())
	require.NoError(t, repository.Close())
	return root, identity, metadata
}
