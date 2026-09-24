package recording

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestLocalRepositoryOptionsRequirePositiveMaximumSpoolBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)

	_, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{})
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

func TestLocalQuotaInvalidationIsSticky(t *testing.T) {
	quota, err := newLocalQuota(10)
	require.NoError(t, err)
	require.NoError(t, quota.reserve(4))
	injected := stderrors.New("injected inventory failure")
	quota.Invalidate(injected)

	operations := map[string]func() error{
		"validate":  quota.validateMaximum,
		"reserve":   func() error { return quota.reserve(1) },
		"release":   func() error { return quota.release(1) },
		"reconcile": func() error { return quota.reconcile(0, 4, 4) },
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			err := operation()
			require.ErrorIs(t, err, injected)
			require.True(t, bferrors.System.IsErr(err))
		})
	}
	require.Equal(t, uint64(4), quota.usage)

	second := stderrors.New("later failure")
	quota.Invalidate(second)
	err = quota.reserve(0)
	require.ErrorIs(t, err, injected)
	require.NotErrorIs(t, err, second)
}

func TestLocalQuotaReconciliationFailureInvalidatesQuota(t *testing.T) {
	for _, test := range []struct {
		name     string
		maximum  uint64
		usage    uint64
		reserved uint64
		before   int64
		after    int64
		want     string
	}{
		{name: "underflow", maximum: 10, usage: 4, reserved: 5, before: 4, after: 4, want: "underflow"},
		{name: "growth beyond limit", maximum: 5, usage: 4, before: 4, after: 6, want: "grew beyond its reservation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			quota := &localQuota{maximum: test.maximum, usage: test.usage}

			err := quota.reconcile(test.reserved, test.before, test.after)
			require.ErrorContains(t, err, test.want)
			require.True(t, bferrors.System.IsErr(err))
			require.Equal(t, test.usage, quota.usage)
			require.EqualError(t, quota.reserve(0), err.Error())
		})
	}
}

func TestLocalRepositoryAdmissionAllowsExactInitialSizeAndRejectsOneByteLess(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	baseline, err := NewLocalNativeRecordingRepository(t.Context(), filepath.Join(t.TempDir(), "baseline"), identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := baseline.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	initialBytes := baseline.repository.quota.usage
	require.Positive(t, initialBytes)
	require.NoError(t, active.Close())
	require.NoError(t, baseline.Close())

	exactRoot := filepath.Join(t.TempDir(), "exact")
	exact, err := NewLocalNativeRecordingRepository(t.Context(), exactRoot, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: initialBytes})
	require.NoError(t, err)
	exactActive, err := exact.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.Equal(t, initialBytes, exact.repository.quota.usage)
	require.ErrorContains(t, exactActive.Close(), "spool limit")
	require.NoError(t, exact.Close())

	rejectedRoot := filepath.Join(t.TempDir(), "rejected")
	rejected, err := NewLocalNativeRecordingRepository(t.Context(), rejectedRoot, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: initialBytes - 1})
	require.NoError(t, err)
	_, err = rejected.CreateActive(t.Context(), header, metadata, 300)
	require.ErrorContains(t, err, "spool limit")
	require.Equal(t, uint64(0), rejected.repository.quota.usage)
	entries, err := os.ReadDir(rejected.repository.workPath)
	require.NoError(t, err)
	require.Empty(t, entries)
	require.NoError(t, rejected.Close())
}

func TestLocalRepositoriesRecoverAtExactSpoolLimit(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "clear"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, header, metadata := castTestValues(t, true)
			var recipient *bfcrypto.AgeSshRecipient
			if encrypted {
				recipient, _ = newBECastTestEncryption(t)
			}
			repository, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			active, err := repository.CreateActive(t.Context(), header, metadata, 300)
			require.NoError(t, err)
			require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("recover at exact quota\r\n")))
			require.NoError(t, active.Close())
			maximum := repository.repository.quota.usage
			require.NoError(t, repository.Close())

			restarted, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: maximum})
			require.NoError(t, err)
			require.Len(t, restarted.StartupRecoveries(), 1)
			require.LessOrEqual(t, restarted.repository.quota.usage, maximum)
			requireLocalTestQuotaMatchesFiles(t, root, restarted.repository.quota)
			require.NoError(t, restarted.Close())
		})
	}
}

func TestLocalRepositoryRecoversAfterReserveActivationCrash(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("crash after reserve activation\r\n")))
	require.NoError(t, active.Close())
	maximum := repository.repository.quota.usage
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	content, err := openActiveLocalFile(filepath.Join(activeDirectory, "recording.bcast"))
	require.NoError(t, err)
	output := accountLocalFile(content, repository.repository.quota)
	require.NoError(t, activateLocalRecoveryReserve(filepath.Join(activeDirectory, localRecoveryReserveName), output))
	require.NoFileExists(t, filepath.Join(activeDirectory, localRecoveryReserveName))
	require.NoError(t, content.Close())
	require.NoError(t, repository.Close())

	restarted, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: maximum})
	require.NoError(t, err)
	require.Len(t, restarted.StartupRecoveries(), 1)
	require.LessOrEqual(t, restarted.repository.quota.usage, maximum)
	requireLocalTestQuotaMatchesFiles(t, root, restarted.repository.quota)
	require.NoError(t, restarted.Close())
}

func TestLocalRepositoryRecoversInterruptedReserveCleanup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.Close())
	maximum := repository.repository.quota.usage
	require.NoError(t, repository.Close())
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	reservePath := filepath.Join(activeDirectory, localRecoveryReserveName)
	require.NoError(t, os.Rename(reservePath, reservePath+localRetentionTombstone))

	restarted, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: maximum})
	require.NoError(t, err)
	require.Len(t, restarted.StartupRecoveries(), 1)
	requireLocalTestQuotaMatchesFiles(t, root, restarted.repository.quota)
	require.NoError(t, restarted.Close())
}

func TestLocalRepositoryInvalidSealPreservesRecoveryReserve(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	_, err = active.Seal(0, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(-time.Second)}, nil)
	require.Error(t, err)
	reservePath := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String(), localRecoveryReserveName)
	require.FileExists(t, reservePath)
	require.Error(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("cannot continue\r\n")))
	require.Error(t, active.Close())
	require.NoError(t, repository.Close())
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

func TestLocalQuotaAllowsLifecycleSuccessorAtExactRecoveredLimit(t *testing.T) {
	for _, sizes := range []struct {
		name                 string
		published, temporary int
	}{
		{name: "larger successor", published: 8, temporary: 13},
		{name: "smaller successor", published: 13, temporary: 8},
	} {
		t.Run(sizes.name, func(t *testing.T) {
			delivery := filepath.Join(t.TempDir(), localDeliveryDirectory)
			state := filepath.Join(delivery, "producer", "artifact")
			require.NoError(t, os.MkdirAll(state, localDirectoryMode))
			target := filepath.Join(state, "receipt.lifecycle")
			temporary := filepath.Join(state, "receipt.lifecycle.tmp")
			require.NoError(t, os.WriteFile(target, make([]byte, sizes.published), localFileMode))
			require.NoError(t, os.WriteFile(temporary, make([]byte, sizes.temporary), localFileMode))
			maximum := uint64(sizes.temporary)
			physical := uint64(sizes.published + sizes.temporary)
			usage, recovered, err := inventoryLocalFilesWithReceiptRecovery(delivery)
			require.NoError(t, err)
			require.Equal(t, physical, usage)
			require.Equal(t, uint64(min(sizes.published, sizes.temporary)), recovered)

			_, err = newLocalQuota(maximum, delivery)
			require.ErrorContains(t, err, "exceeding")
			_, err = newLocalQuotaWithReceiptRecovery(recovered-1, true, delivery)
			require.ErrorContains(t, err, "exceeding")
			quota, err := newLocalQuotaWithReceiptRecovery(maximum, true, delivery)
			require.NoError(t, err)
			require.Equal(t, physical, quota.usage)
			require.ErrorContains(t, quota.reserve(0), "would be exceeded")
			require.ErrorContains(t, quota.validateMaximum(), "exceeding")
			require.Equal(t, physical, quota.usage)
		})
	}
}

func TestLocalQuotaRequiresReceiptRecoveryToReachLimit(t *testing.T) {
	root := t.TempDir()
	delivery := filepath.Join(root, localDeliveryDirectory)
	state := filepath.Join(delivery, "producer", "artifact")
	require.NoError(t, os.MkdirAll(state, localDirectoryMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.json"), make([]byte, 8), localFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.tmp"), make([]byte, 9), localFileMode))

	quota, err := newLocalQuotaWithReceiptRecovery(8, true, delivery)
	require.NoError(t, err)
	require.Equal(t, uint64(17), quota.usage)
	require.ErrorContains(t, quota.validateMaximum(), "exceeding its 8-byte limit")
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

func TestLocalRepositoryValidatesQuotaAfterReceiptCleanupRecovery(t *testing.T) {
	for _, cleanup := range []bool{true, false} {
		name := "cleanup"
		if !cleanup {
			name = "still over limit"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, _, _ := castTestValues(t, true)
			initial, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			require.NoError(t, initial.Close())
			state := filepath.Join(root, localDeliveryDirectory, "producer", "artifact")
			require.NoError(t, os.MkdirAll(state, localDirectoryMode))
			marker := filepath.Join(state, "receipt.tmp.cleanup")
			require.NoError(t, os.WriteFile(marker, make([]byte, 9), localFileMode))
			preparer := &localReceiptCleanupRecoveryTestPreparer{path: marker, cleanup: cleanup}

			repository, err := NewLocalNativeRecordingRepositoryWithArtifactPreparer(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: 1}, preparer)
			if !cleanup {
				require.ErrorContains(t, err, "exceeding its 1-byte limit")
				require.True(t, preparer.recovered)
				return
			}
			require.NoError(t, err)
			require.True(t, preparer.recovered)
			require.Zero(t, repository.repository.quota.usage)
			require.NoError(t, repository.Close())
		})
	}
}

func TestLocalRepositoryRejectsUnrecoveredLifecycleTemporaryAfterQuotaValidation(t *testing.T) {
	for _, name := range []string{"receipt.lifecycle.tmp", "receipt.lifecycle.tmp.cleanup"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, _, _ := castTestValues(t, true)
			initial, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			require.NoError(t, initial.Close())
			state := filepath.Join(root, localDeliveryDirectory, "producer", "artifact")
			require.NoError(t, os.MkdirAll(state, localDirectoryMode))
			path := filepath.Join(state, name)
			require.NoError(t, os.WriteFile(path, make([]byte, 9), localFileMode))
			preparer := &localReceiptCleanupRecoveryTestPreparer{path: path}

			_, err = NewLocalNativeRecordingRepositoryWithArtifactPreparer(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: 1}, preparer)
			require.ErrorContains(t, err, "exceeding its 1-byte limit")
			require.True(t, preparer.recovered)
			require.FileExists(t, path)
		})
	}
}

type localReceiptCleanupRecoveryTestPreparer struct {
	quota     *localQuota
	path      string
	cleanup   bool
	recovered bool
}

func (this *localReceiptCleanupRecoveryTestPreparer) BindSealedArtifactQuota(quota audit.RemoteArtifactReceiptQuota) {
	this.quota = quota.(*localQuota)
}

func (this *localReceiptCleanupRecoveryTestPreparer) RecoverSealedArtifactState(context.Context) error {
	this.recovered = true
	if !this.cleanup {
		return nil
	}
	info, err := os.Lstat(this.path)
	if err != nil {
		return err
	}
	if err := os.Remove(this.path); err != nil {
		return err
	}
	return this.quota.reconcile(0, info.Size(), 0)
}

func (*localReceiptCleanupRecoveryTestPreparer) Prepare(context.Context, audit.RemoteArtifact, time.Time) error {
	return nil
}

func (*localReceiptCleanupRecoveryTestPreparer) Require(context.Context, audit.RemoteArtifact) error {
	return nil
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
	initial, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: 1 << 20})
	require.NoError(t, err)
	require.NoError(t, initial.Close())
	delivery := filepath.Join(root, localDeliveryDirectory)
	state := filepath.Join(delivery, "producer", "artifact")
	require.NoError(t, os.MkdirAll(state, localDirectoryMode))
	target := filepath.Join(state, "receipt.json")
	require.NoError(t, os.WriteFile(target, make([]byte, 8), localFileMode))
	require.NoError(t, os.WriteFile(filepath.Join(state, "receipt.tmp"), make([]byte, 9), localFileMode))
	preparer := &localReceiptQuotaRecoveryTestPreparer{target: target}

	repository, err := NewLocalNativeRecordingRepositoryWithArtifactPreparer(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: 9}, preparer)
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

func TestLocalQuotaFileConsumesReservedBytesAtTheHardLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recording")
	require.NoError(t, os.WriteFile(path, make([]byte, 7), localFileMode))
	file, err := os.OpenFile(path, os.O_RDWR, localFileMode)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	quota := &localQuota{maximum: 10, usage: 10}
	accounted := accountLocalFile(file, quota)
	require.NoError(t, accounted.adoptReservedBytes(3))
	_, err = accounted.Seek(0, 2)
	require.NoError(t, err)
	written, err := accounted.Write([]byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, 3, written)
	require.Equal(t, uint64(10), quota.usage)
	require.Zero(t, accounted.reserved)
	written, err = accounted.Write([]byte{4})
	require.Zero(t, written)
	require.ErrorContains(t, err, "would be exceeded")
}

func TestLocalRepositoryStartupOverLimitPreservesData(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	repository, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, repository.Close())
	payload := []byte("preserve over-limit quarantine data")
	path := filepath.Join(root, localQuarantineDirectory, "content")
	require.NoError(t, os.WriteFile(path, payload, localFileMode))

	_, err = NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: uint64(len(payload) - 1)})
	require.ErrorContains(t, err, "exceeding")
	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, payload, after)
}

func TestLocalRepositoriesFailClosedOnGrowth(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "clear"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, header, metadata := castTestValues(t, true)
			var recipient *bfcrypto.AgeSshRecipient
			if encrypted {
				recipient, _ = newBECastTestEncryption(t)
			}
			repository, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			t.Cleanup(func() { _ = repository.Close() })
			active, err := repository.CreateActive(t.Context(), header, metadata, 1)
			require.NoError(t, err)
			require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("growth")))
			repository.repository.quota.maximum = repository.repository.quota.usage
			err = active.Checkpoint()
			require.ErrorContains(t, err, "spool limit")
		})
	}
}

func TestLocalRepositoryRecoveryAccountsTruncateAndAppend(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	initial, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := initial.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("interrupted\r\n")))
	require.NoError(t, active.Close())
	require.NoError(t, initial.Close())
	content := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String(), "recording.bcast")
	file, err := os.OpenFile(content, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	partialDescriptor := []byte{0x42, 0x46, 0x52}
	_, err = file.Write(partialDescriptor)
	require.NoError(t, err)
	require.NoError(t, file.Close())

	repository, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Len(t, repository.StartupRecoveries(), 1)
	require.True(t, repository.StartupRecoveries()[0].Truncated)
	requireLocalTestQuotaMatchesFiles(t, root, repository.repository.quota)
	require.NoError(t, repository.Close())
}

func TestLocalRepositorySealKeepsQuotaInSync(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
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

	requireLocalTestQuotaMatchesFiles(t, root, repository.repository.quota)
	require.NoError(t, active.Close())
	require.NoError(t, repository.Close())
}
