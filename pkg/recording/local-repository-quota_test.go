package recording

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestLocalRepositoryOptionsRequirePositiveMaximumSpoolBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)

	_, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, LocalRepositoryOptions{})
	require.ErrorContains(t, err, "must be positive")
	require.True(t, bferrors.Config.IsErr(err))
	require.NoDirExists(t, root)
}

func TestLocalQuotaAllowsExactLimitAndRejectsGrowthBeyondIt(t *testing.T) {
	quota, err := newLocalQuota(10)
	require.NoError(t, err)
	require.NoError(t, quota.reserve(10))
	require.ErrorContains(t, quota.reserve(1), "would be exceeded")
	require.Equal(t, uint64(10), quota.usage)
}

func TestLocalRepositoryAdmissionAllowsExactInitialSizeAndRejectsOneByteLess(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	baseline, err := NewLocalCastZstdRepository(t.Context(), filepath.Join(t.TempDir(), "baseline"), identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := baseline.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	initialBytes := baseline.repository.quota.usage
	require.Positive(t, initialBytes)
	require.NoError(t, active.Close())
	require.NoError(t, baseline.Close())

	exactRoot := filepath.Join(t.TempDir(), "exact")
	exact, err := NewLocalCastZstdRepository(t.Context(), exactRoot, identity, CastZstdVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: initialBytes})
	require.NoError(t, err)
	exactActive, err := exact.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.Equal(t, initialBytes, exact.repository.quota.usage)
	require.ErrorContains(t, exactActive.Close(), "spool limit")
	require.NoError(t, exact.Close())

	rejectedRoot := filepath.Join(t.TempDir(), "rejected")
	rejected, err := NewLocalCastZstdRepository(t.Context(), rejectedRoot, identity, CastZstdVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: initialBytes - 1})
	require.NoError(t, err)
	_, err = rejected.CreateActive(t.Context(), header, metadata, 300)
	require.ErrorContains(t, err, "spool limit")
	require.Equal(t, uint64(0), rejected.repository.quota.usage)
	entries, err := os.ReadDir(rejected.repository.workPath)
	require.NoError(t, err)
	require.Empty(t, entries)
	require.NoError(t, rejected.Close())
}

func TestLocalQuotaSerializesConcurrentReservations(t *testing.T) {
	quota, err := newLocalQuota(1)
	require.NoError(t, err)
	ready := make(chan struct{})
	var started sync.WaitGroup
	var finished sync.WaitGroup
	var accepted atomic.Int32
	for range 32 {
		started.Add(1)
		finished.Add(1)
		go func() {
			defer finished.Done()
			started.Done()
			<-ready
			if quota.reserve(1) == nil {
				accepted.Add(1)
			}
		}()
	}
	started.Wait()
	close(ready)
	finished.Wait()
	require.Equal(t, int32(1), accepted.Load())
	require.Equal(t, uint64(1), quota.usage)
}

func TestInventoryLocalFilesCountsAllSpoolAreas(t *testing.T) {
	root := t.TempDir()
	var expected uint64
	paths := make([]string, 0, 5)
	for index, name := range []string{localWorkDirectory, localActiveDirectory, localSealedDirectory, localQuarantineDirectory, localDeliveryDirectory} {
		path := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(path, localDirectoryMode))
		paths = append(paths, path)
		payload := make([]byte, index+1)
		require.NoError(t, os.WriteFile(filepath.Join(path, "content"), payload, localFileMode))
		expected += uint64(len(payload))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, localLockFileName), make([]byte, 50), localFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(root, localFormatFileName), make([]byte, 60), localFileMode))

	usage, err := inventoryLocalFiles(paths...)
	require.NoError(t, err)
	require.Equal(t, expected, usage)
}

func TestLocalQuotaAllowsRecoverableReceiptTemporaryAboveLimit(t *testing.T) {
	root := t.TempDir()
	delivery := filepath.Join(root, localDeliveryDirectory)
	state := filepath.Join(delivery, "producer", "artifact")
	require.NoError(t, os.MkdirAll(state, localDirectoryMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.json"), make([]byte, 8), localFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.tmp"), make([]byte, 9), localFileMode))

	quota, err := newLocalQuotaWithReceiptRecovery(9, true, delivery)
	require.NoError(t, err)
	require.Equal(t, uint64(17), quota.usage)
	require.ErrorContains(t, quota.reserve(1), "would be exceeded")
	require.NoError(t, quota.reconcile(0, 17, 9))
	require.Equal(t, uint64(9), quota.usage)
}

func TestLocalQuotaAllowsRecoverableRetentionReceiptTemporaryAboveLimit(t *testing.T) {
	root := t.TempDir()
	delivery := filepath.Join(root, localDeliveryDirectory)
	state := filepath.Join(delivery, "producer", "artifact")
	require.NoError(t, os.MkdirAll(state, localDirectoryMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.retention"), make([]byte, 8), localFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.retention.tmp"), make([]byte, 8), localFileMode))

	quota, err := newLocalQuotaWithReceiptRecovery(8, true, delivery)
	require.NoError(t, err)
	require.Equal(t, uint64(16), quota.usage)
	require.NoError(t, quota.reconcile(0, 16, 8))
	require.Equal(t, uint64(8), quota.usage)
}

func TestLocalQuotaRejectsReceiptTemporaryWhoseRecoveredStateExceedsLimit(t *testing.T) {
	root := t.TempDir()
	delivery := filepath.Join(root, localDeliveryDirectory)
	state := filepath.Join(delivery, "producer", "artifact")
	require.NoError(t, os.MkdirAll(state, localDirectoryMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.json"), make([]byte, 8), localFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.tmp"), make([]byte, 9), localFileMode))

	_, err := newLocalQuotaWithReceiptRecovery(8, true, delivery)
	require.ErrorContains(t, err, "exceeding its 8-byte limit")
}

func TestLocalQuotaRejectsRecoverableReceiptTemporaryWithoutRecoverer(t *testing.T) {
	root := t.TempDir()
	delivery := filepath.Join(root, localDeliveryDirectory)
	state := filepath.Join(delivery, "producer", "artifact")
	require.NoError(t, os.MkdirAll(state, localDirectoryMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.json"), make([]byte, 8), localFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.tmp"), make([]byte, 9), localFileMode))

	_, err := newLocalQuota(9, delivery)
	require.ErrorContains(t, err, "exceeding its 9-byte limit")
}

func TestInventoryLocalFilesCountsHardLinksOnce(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	require.NoError(t, os.WriteFile(first, make([]byte, 7), localFileMode))
	require.NoError(t, os.Link(first, second))

	usage, err := inventoryLocalFiles(root)
	require.NoError(t, err)
	require.Equal(t, uint64(7), usage)
}

func TestLocalRepositoryRecoversReceiptQuotaBeforeRecordingState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	initial, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: 1 << 20})
	require.NoError(t, err)
	require.NoError(t, initial.Close())
	delivery := filepath.Join(root, localDeliveryDirectory)
	state := filepath.Join(delivery, "producer", "artifact")
	require.NoError(t, os.MkdirAll(state, localDirectoryMode))
	target := filepath.Join(state, "receipt.json")
	require.NoError(t, os.WriteFile(target, make([]byte, 8), localFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.tmp"), make([]byte, 9), localFileMode))
	preparer := &localReceiptQuotaRecoveryTestPreparer{target: target}

	repository, err := NewLocalCastZstdRepositoryWithArtifactPreparer(t.Context(), root, identity, CastZstdVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: 9}, preparer)
	require.NoError(t, err)
	require.True(t, preparer.recovered)
	require.Equal(t, uint64(9), repository.repository.quota.usage)
	require.NoError(t, repository.Close())
}

type localReceiptQuotaRecoveryTestPreparer struct {
	quota     *localQuota
	target    string
	recovered bool
}

func (this *localReceiptQuotaRecoveryTestPreparer) BindSealedArtifactQuota(quota audit.RemoteArtifactReceiptQuota) {
	this.quota = quota.(*localQuota)
}

func (this *localReceiptQuotaRecoveryTestPreparer) RecoverSealedArtifactState(context.Context) error {
	if err := os.Remove(this.target); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(filepath.Dir(this.target), "receipt.tmp"), this.target); err != nil {
		return err
	}
	this.recovered = true
	return this.quota.reconcile(0, 17, 9)
}

func (*localReceiptQuotaRecoveryTestPreparer) Prepare(context.Context, audit.RemoteArtifact, time.Time) error {
	return nil
}

func (*localReceiptQuotaRecoveryTestPreparer) Require(context.Context, audit.RemoteArtifact) error {
	return nil
}

func TestLocalQuotaFileAccountsWritesAndSuccessfulTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recording")
	require.NoError(t, os.WriteFile(path, make([]byte, 10), localFileMode))
	file, err := os.OpenFile(path, os.O_RDWR, localFileMode)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	quota := &localQuota{maximum: 12, usage: 10}
	accounted := accountLocalFile(file, quota)
	_, err = accounted.Seek(0, 2)
	require.NoError(t, err)
	written, err := accounted.Write([]byte{1, 2})
	require.NoError(t, err)
	require.Equal(t, 2, written)
	require.Equal(t, uint64(12), quota.usage)
	written, err = accounted.Write([]byte{3})
	require.Zero(t, written)
	require.ErrorContains(t, err, "would be exceeded")

	require.NoError(t, accounted.Truncate(5))
	require.Equal(t, uint64(5), quota.usage)
	_, err = accounted.Seek(0, 2)
	require.NoError(t, err)
	written, err = accounted.Write(make([]byte, 7))
	require.NoError(t, err)
	require.Equal(t, 7, written)
	require.Equal(t, uint64(12), quota.usage)
}

func TestLocalRepositoryStartupOverLimitPreservesData(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	payload := []byte("preserve over-limit quarantine data")
	path := filepath.Join(root, localQuarantineDirectory, "content")
	require.NoError(t, os.WriteFile(path, payload, localFileMode))

	_, err = NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: uint64(len(payload) - 1)})
	require.ErrorContains(t, err, "exceeding")
	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, payload, after)
}

func TestLocalRepositoriesFailClosedOnGrowth(t *testing.T) {
	t.Run("zstd", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "recordings")
		identity, header, metadata := castTestValues(t, true)
		repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
		require.NoError(t, err)
		t.Cleanup(func() { _ = repository.Close() })
		active, err := repository.CreateActive(t.Context(), header, metadata, 1)
		require.NoError(t, err)
		repository.repository.quota.maximum = repository.repository.quota.usage
		err = active.WriteOutput(time.Second, OutputStreamTerminal, []byte("growth"))
		require.ErrorContains(t, err, "spool limit")
	})

	t.Run("becast", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "recordings")
		identity, header, metadata := castTestValues(t, true)
		recipient, _ := newBECastTestEncryption(t)
		repository, err := NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
		require.NoError(t, err)
		t.Cleanup(func() { _ = repository.Close() })
		active, err := repository.CreateActive(t.Context(), header, metadata, 1)
		require.NoError(t, err)
		repository.repository.quota.maximum = repository.repository.quota.usage
		err = active.WriteOutput(time.Second, OutputStreamTerminal, []byte("growth"))
		require.ErrorContains(t, err, "spool limit")
	})
}

func TestLocalRepositoryRecoveryAccountsTruncateAndAppend(t *testing.T) {
	root, identity, metadata := closedActiveLocalTestRepository(t)
	content := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String(), localCastZstdContentFileName)
	file, err := os.OpenFile(content, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	partialDescriptor := encodeZstdSkippableFrame(castZstdChunkSkippableId, nil)[:6]
	_, err = file.Write(partialDescriptor)
	require.NoError(t, err)
	require.NoError(t, file.Close())

	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Len(t, repository.StartupRecoveries(), 1)
	require.True(t, repository.StartupRecoveries()[0].Truncated)
	usage, err := inventoryLocalFiles(repository.repository.workPath, repository.repository.activePath, repository.repository.sealedPath, repository.repository.quarantinePath)
	require.NoError(t, err)
	require.Equal(t, usage, repository.repository.quota.usage)
	require.NoError(t, repository.Close())
}

func TestLocalRepositorySealKeepsQuotaInSync(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 64)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("quota accounting\r\n")))
	require.NoError(t, active.Checkpoint())
	exitStatus := uint32(0)
	_, err = active.Seal(2*time.Second, CastResult{
		Status:  CastStatusCompleted,
		EndedAt: metadata.StartedAt.Add(2 * time.Second),
	}, &exitStatus)
	require.NoError(t, err)

	usage, err := inventoryLocalFiles(repository.repository.workPath, repository.repository.activePath, repository.repository.sealedPath, repository.repository.quarantinePath)
	require.NoError(t, err)
	require.Equal(t, usage, repository.repository.quota.usage)
	require.NoError(t, active.Close())
	require.NoError(t, repository.Close())
}
