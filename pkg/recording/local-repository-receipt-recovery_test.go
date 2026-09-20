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
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestLocalCastZstdRepositoryRecoversAfterDurableReceiptBeforePublication(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	crashErr := stderrors.New("injected crash after durable receipt")
	preparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity, failAfterPrepare: crashErr}
	repository, err := NewLocalCastZstdRepositoryWithArtifactPreparer(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions, preparer)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = repository.Close()
		_ = preparer.Close()
	})
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("durable receipt before publication\r\n")))
	require.NoError(t, active.Checkpoint())
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	headInfo, err := os.Lstat(filepath.Join(activeDirectory, localHeadFileName))
	require.NoError(t, err)
	reserveInfo, err := os.Lstat(filepath.Join(activeDirectory, localRecoveryReserveName))
	require.NoError(t, err)

	_, err = active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, sealedArtifactUint32(0))
	require.ErrorIs(t, err, crashErr)
	require.Equal(t, 1, preparer.prepareCalls)
	require.NoError(t, preparer.prepared.ValidateContext(t.Context()))
	require.NoError(t, preparer.Require(t.Context(), preparer.prepared))
	require.DirExists(t, activeDirectory)
	require.FileExists(t, filepath.Join(activeDirectory, localCastZstdContentFileName))
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, preparer.prepared.FileName()))
	require.NoDirExists(t, filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp"))
	requireLocalTestQuotaMatchesFiles(t, root, repository.repository.quota)
	crashUsage := repository.repository.quota.usage
	receiptPath, receiptBefore, receiptInfoBefore := localDurableReceiptTestSnapshot(t, root, identity)
	preparedFileName := preparer.prepared.FileName()
	preparedDigest := preparer.prepared.Digest()
	preparedSize := preparer.prepared.Size()

	require.ErrorIs(t, repository.Close(), crashErr)
	require.NoError(t, preparer.Close())
	require.DirExists(t, activeDirectory)
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, preparedFileName))
	require.Equal(t, receiptBefore, localDurableReceiptTestRead(t, receiptPath))

	restartedPreparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity}
	restarted, err := NewLocalCastZstdRepositoryWithArtifactPreparer(t.Context(), root, identity, CastZstdVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: crashUsage}, restartedPreparer)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = restarted.Close()
		_ = restartedPreparer.Close()
	})
	recoveries := restarted.StartupRecoveries()
	require.Len(t, recoveries, 1)
	require.Equal(t, metadata.RecordingId, recoveries[0].Summary.RecordingId)
	require.Equal(t, CastStatusCompleted, recoveries[0].Summary.Status)
	require.False(t, recoveries[0].Truncated)
	require.True(t, recoveries[0].AlreadySealed)
	require.Equal(t, 1, restartedPreparer.prepareCalls)
	require.NoDirExists(t, activeDirectory)
	require.FileExists(t, filepath.Join(root, localSealedDirectory, preparedFileName))
	sealed, err := restarted.OpenSealed(t.Context(), metadata.RecordingId)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Close() })
	remote, err := sealed.RemoteArtifact()
	require.NoError(t, err)
	require.Equal(t, preparedFileName, remote.FileName())
	require.Equal(t, preparedDigest, remote.Digest())
	require.Equal(t, preparedSize, remote.Size())
	require.NoError(t, restartedPreparer.Require(t.Context(), remote))
	requireLocalTestQuotaMatchesFiles(t, root, restarted.repository.quota)
	require.Equal(t, crashUsage-uint64(headInfo.Size())-uint64(reserveInfo.Size()), restarted.repository.quota.usage)
	localDurableReceiptTestRequireUnchanged(t, receiptPath, receiptBefore, receiptInfoBefore)
}

func TestLocalBECastRepositoryRecoversAfterDurableReceiptBeforePublication(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	crashErr := stderrors.New("injected crash after durable receipt")
	preparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity, failAfterPrepare: crashErr}
	repository, err := NewLocalBECastRepositoryWithArtifactPreparer(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions, preparer)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = repository.Close()
		_ = preparer.Close()
	})
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("durable encrypted receipt before publication\r\n")))
	require.NoError(t, active.Checkpoint())
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	headInfo, err := os.Lstat(filepath.Join(activeDirectory, localHeadFileName))
	require.NoError(t, err)
	reserveInfo, err := os.Lstat(filepath.Join(activeDirectory, localRecoveryReserveName))
	require.NoError(t, err)

	_, err = active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, sealedArtifactUint32(0))
	require.ErrorIs(t, err, crashErr)
	require.Equal(t, 1, preparer.prepareCalls)
	require.NoError(t, preparer.prepared.ValidateContext(t.Context()))
	require.NoError(t, preparer.Require(t.Context(), preparer.prepared))
	require.DirExists(t, activeDirectory)
	require.FileExists(t, filepath.Join(activeDirectory, localBECastContentFileName))
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, preparer.prepared.FileName()))
	require.NoDirExists(t, filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp"))
	requireLocalTestQuotaMatchesFiles(t, root, repository.repository.quota)
	crashUsage := repository.repository.quota.usage
	receiptPath, receiptBefore, receiptInfoBefore := localDurableReceiptTestSnapshot(t, root, identity)
	preparedFileName := preparer.prepared.FileName()
	preparedDigest := preparer.prepared.Digest()
	preparedSize := preparer.prepared.Size()

	require.ErrorIs(t, repository.Close(), crashErr)
	require.NoError(t, preparer.Close())
	require.DirExists(t, activeDirectory)
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, preparedFileName))
	require.Equal(t, receiptBefore, localDurableReceiptTestRead(t, receiptPath))

	restartedPreparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity}
	restarted, err := NewLocalBECastRepositoryWithArtifactPreparer(t.Context(), root, identity, recipient, BECastVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: crashUsage}, restartedPreparer)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = restarted.Close()
		_ = restartedPreparer.Close()
	})
	recoveries := restarted.StartupRecoveries()
	require.Len(t, recoveries, 1)
	require.Equal(t, metadata.RecordingId, recoveries[0].Summary.RecordingId)
	require.Equal(t, CastStatusCompleted, recoveries[0].Summary.Status)
	require.False(t, recoveries[0].Truncated)
	require.True(t, recoveries[0].AlreadySealed)
	require.Equal(t, 1, restartedPreparer.prepareCalls)
	require.NoDirExists(t, activeDirectory)
	require.FileExists(t, filepath.Join(root, localSealedDirectory, preparedFileName))
	sealed, err := restarted.OpenSealed(t.Context(), metadata.RecordingId)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Close() })
	remote, err := sealed.RemoteArtifact()
	require.NoError(t, err)
	require.Equal(t, preparedFileName, remote.FileName())
	require.Equal(t, preparedDigest, remote.Digest())
	require.Equal(t, preparedSize, remote.Size())
	require.NoError(t, restartedPreparer.Require(t.Context(), remote))
	requireLocalTestQuotaMatchesFiles(t, root, restarted.repository.quota)
	require.Equal(t, crashUsage-uint64(headInfo.Size())-uint64(reserveInfo.Size()), restarted.repository.quota.usage)
	localDurableReceiptTestRequireUnchanged(t, receiptPath, receiptBefore, receiptInfoBefore)
}

type localDurableReceiptCrashPreparer struct {
	directory        string
	identity         *audit.Identity
	quota            audit.RemoteArtifactReceiptQuota
	receipts         *audit.RemoteArtifactReceipts
	failAfterPrepare error
	prepared         audit.RemoteArtifact
	prepareCalls     int
}

func (this *localDurableReceiptCrashPreparer) BindSealedArtifactQuota(quota audit.RemoteArtifactReceiptQuota) {
	this.quota = quota
}

func (this *localDurableReceiptCrashPreparer) RecoverSealedArtifactState(ctx context.Context) error {
	receipts, err := this.get()
	if err != nil {
		return err
	}
	return receipts.Recover(ctx)
}

func (this *localDurableReceiptCrashPreparer) Prepare(ctx context.Context, artifact audit.RemoteArtifact, sealedAt time.Time) error {
	receipts, err := this.get()
	if err != nil {
		return err
	}
	if err := receipts.Prepare(ctx, artifact, sealedAt); err != nil {
		return err
	}
	this.prepared = artifact
	this.prepareCalls++
	return this.failAfterPrepare
}

func (this *localDurableReceiptCrashPreparer) Require(ctx context.Context, artifact audit.RemoteArtifact) error {
	receipts, err := this.get()
	if err != nil {
		return err
	}
	return receipts.Require(ctx, artifact)
}

func (this *localDurableReceiptCrashPreparer) Close() error {
	if this == nil || this.receipts == nil {
		return nil
	}
	return this.receipts.Close()
}

func (this *localDurableReceiptCrashPreparer) get() (*audit.RemoteArtifactReceipts, error) {
	if this.receipts != nil {
		return this.receipts, nil
	}
	receipts, err := audit.NewRemoteArtifactReceipts(this.directory, this.identity, configuration.AuditlogName("security"), nil, this.quota)
	if err != nil {
		return nil, err
	}
	this.receipts = receipts
	return receipts, nil
}

func localDurableReceiptTestSnapshot(t *testing.T, root string, identity *audit.Identity) (string, []byte, os.FileInfo) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, localDeliveryDirectory, identity.ProducerId().String(), "*", "receipt.json"))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	path := matches[0]
	payload := localDurableReceiptTestRead(t, path)
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.NoFileExists(t, filepath.Join(filepath.Dir(path), "receipt.tmp"))
	return path, payload, info
}

func localDurableReceiptTestRead(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	require.NoError(t, err)
	return payload
}

func localDurableReceiptTestRequireUnchanged(t *testing.T, path string, before []byte, beforeInfo os.FileInfo) {
	t.Helper()
	require.Equal(t, before, localDurableReceiptTestRead(t, path))
	afterInfo, err := os.Lstat(path)
	require.NoError(t, err)
	require.True(t, os.SameFile(beforeInfo, afterInfo))
	require.NoFileExists(t, filepath.Join(filepath.Dir(path), "receipt.tmp"))
}
