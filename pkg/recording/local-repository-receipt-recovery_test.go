package recording

import (
	"context"
	"crypto/sha256"
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
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
	fileName := metadata.RecordingId.String() + localCastZstdSealedSuffix
	receipts, err := preparer.get()
	require.NoError(t, err)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, metadata.StartedAt, localLifecycleTestStartedEvent(metadata)))
	require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, localLifecycleTestCompletedEvent(metadata)))
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("durable receipt before publication\r\n")))
	require.NoError(t, active.Checkpoint())
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	_, err = active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, sealedArtifactUint32(0))
	require.ErrorIs(t, err, crashErr)
	require.Equal(t, 1, preparer.prepareCalls)
	require.False(t, preparer.interrupted)
	pendingBeforePublish, err := preparer.receipts.PendingLifecycle(t.Context())
	require.NoError(t, err)
	require.Empty(t, pendingBeforePublish)
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
	require.False(t, restartedPreparer.interrupted)
	require.Equal(t, recoveries[0].Summary.Digest, restartedPreparer.recordingDigest)
	pending, err := restartedPreparer.receipts.PendingLifecycle(t.Context())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, audit.EventNameSessionRecordingCompleted, pending[0].Event.Name)
	require.Equal(t, recoveries[0].Summary.Digest.String(), pending[0].Event.RecordingDigest)
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
	localDurableReceiptTestRequireUnchanged(t, receiptPath, receiptBefore, receiptInfoBefore)
}

func TestLocalCastZstdRepositoryPromotesLifecycleAfterPublishedRecovery(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	promotionErr := stderrors.New("injected crash before lifecycle promotion")
	preparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity, failBeforePromote: promotionErr}
	repository, err := NewLocalCastZstdRepositoryWithArtifactPreparer(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions, preparer)
	require.NoError(t, err)
	fileName := metadata.RecordingId.String() + localCastZstdSealedSuffix
	receipts, err := preparer.get()
	require.NoError(t, err)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, metadata.StartedAt, localLifecycleTestStartedEvent(metadata)))
	require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, localLifecycleTestCompletedEvent(metadata)))
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("published before promotion\r\n")))

	_, err = active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, sealedArtifactUint32(0))
	require.ErrorIs(t, err, promotionErr)
	require.Empty(t, mustLocalPendingLifecycle(t, preparer.receipts))
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	require.DirExists(t, activeDirectory)
	require.FileExists(t, filepath.Join(root, localSealedDirectory, fileName))
	require.ErrorIs(t, repository.Close(), promotionErr)
	require.NoError(t, preparer.Close())

	restartedPreparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity}
	restarted, err := NewLocalCastZstdRepositoryWithArtifactPreparer(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions, restartedPreparer)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, restarted.Close())
		require.NoError(t, restartedPreparer.Close())
	})
	require.Empty(t, restarted.StartupRecoveries())
	require.NoDirExists(t, activeDirectory)
	pending := mustLocalPendingLifecycle(t, restartedPreparer.receipts)
	require.Len(t, pending, 1)
	require.Equal(t, audit.EventNameSessionRecordingCompleted, pending[0].Event.Name)
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
	fileName := metadata.RecordingId.String() + localBECastSealedSuffix
	receipts, err := preparer.get()
	require.NoError(t, err)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, metadata.StartedAt, localLifecycleTestStartedEvent(metadata)))
	require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, localLifecycleTestCompletedEvent(metadata)))
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("durable encrypted receipt before publication\r\n")))
	require.NoError(t, active.Checkpoint())
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
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
	localDurableReceiptTestRequireUnchanged(t, receiptPath, receiptBefore, receiptInfoBefore)
}

func TestLocalNativeRecordingRepositoryRecoversAfterDurableReceiptBeforePublication(t *testing.T) {
	for _, tc := range []struct {
		name, suffix string
		encrypted    bool
	}{
		{name: "clear", suffix: ".bcast"},
		{name: "encrypted-cbor", suffix: ".becast", encrypted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, header, metadata := castTestValues(t, true)
			var recipient *bfcrypto.AgeSshRecipient
			if tc.encrypted {
				recipient, _ = newBECastTestEncryption(t)
			}
			crashErr := stderrors.New("injected crash after durable receipt")
			preparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity, failAfterPrepare: crashErr}
			repository, err := NewLocalNativeRecordingRepositoryWithArtifactPreparer(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions, preparer)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = repository.Close()
				_ = preparer.Close()
			})
			fileName := metadata.RecordingId.String() + tc.suffix
			receipts, err := preparer.get()
			require.NoError(t, err)
			require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, metadata.StartedAt, localLifecycleTestStartedEvent(metadata)))
			require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, localLifecycleTestCompletedEvent(metadata)))
			active, err := repository.CreateActive(t.Context(), header, metadata, 300)
			require.NoError(t, err)
			activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
			contentPath := filepath.Join(activeDirectory, "recording"+tc.suffix)
			require.FileExists(t, filepath.Join(activeDirectory, localNativeHeadFileName))
			require.NoFileExists(t, filepath.Join(activeDirectory, localHeadFileName))
			require.FileExists(t, contentPath)
			require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("native durable receipt before publication\r\n")))
			require.NoError(t, active.Checkpoint())
			_, err = active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, sealedArtifactUint32(0))
			require.ErrorIs(t, err, crashErr)
			require.Equal(t, 1, preparer.prepareCalls)
			require.False(t, preparer.interrupted)
			require.Empty(t, mustLocalPendingLifecycle(t, preparer.receipts))
			require.NoError(t, preparer.prepared.ValidateContext(t.Context()))
			require.NoError(t, preparer.Require(t.Context(), preparer.prepared))
			require.Equal(t, fileName, preparer.prepared.FileName())
			require.FileExists(t, filepath.Join(activeDirectory, localNativeHeadFileName))
			contents, err := os.ReadFile(contentPath)
			require.NoError(t, err)
			require.Equal(t, int64(len(contents)), preparer.prepared.Size())
			require.Equal(t, ArtifactDigest(sha256.Sum256(contents)), preparer.prepared.Digest())
			require.NoFileExists(t, filepath.Join(root, localSealedDirectory, fileName))
			workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
			require.NoDirExists(t, workDirectory)
			requireLocalTestQuotaMatchesFiles(t, root, repository.repository.quota)
			crashUsage := repository.repository.quota.usage
			receiptPath, receiptBefore, receiptInfoBefore := localDurableReceiptTestSnapshot(t, root, identity)

			require.ErrorIs(t, repository.Close(), crashErr)
			require.NoError(t, preparer.Close())
			require.DirExists(t, activeDirectory)
			require.NoFileExists(t, filepath.Join(root, localSealedDirectory, fileName))
			localDurableReceiptTestRequireUnchanged(t, receiptPath, receiptBefore, receiptInfoBefore)

			restartedPreparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity}
			restarted, err := NewLocalNativeRecordingRepositoryWithArtifactPreparer(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: crashUsage}, restartedPreparer)
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
			require.False(t, restartedPreparer.interrupted)
			require.Equal(t, recoveries[0].Summary.Digest, restartedPreparer.recordingDigest)
			pending := mustLocalPendingLifecycle(t, restartedPreparer.receipts)
			require.Len(t, pending, 1)
			require.Equal(t, audit.EventNameSessionRecordingCompleted, pending[0].Event.Name)
			require.Equal(t, recoveries[0].Summary.Digest.String(), pending[0].Event.RecordingDigest)
			require.NoDirExists(t, activeDirectory)
			require.NoDirExists(t, workDirectory)
			sealedPath := filepath.Join(root, localSealedDirectory, fileName)
			require.FileExists(t, sealedPath)
			sealedContents, err := os.ReadFile(sealedPath)
			require.NoError(t, err)
			require.Equal(t, contents, sealedContents)
			sealed, err := restarted.OpenSealed(t.Context(), metadata.RecordingId)
			require.NoError(t, err)
			t.Cleanup(func() { _ = sealed.Close() })
			remote, err := sealed.RemoteArtifact()
			require.NoError(t, err)
			require.Equal(t, fileName, remote.FileName())
			require.Equal(t, int64(len(sealedContents)), remote.Size())
			require.Equal(t, ArtifactDigest(sha256.Sum256(sealedContents)), remote.Digest())
			require.Equal(t, preparer.prepared.Digest(), remote.Digest())
			require.NoError(t, restartedPreparer.Require(t.Context(), remote))
			requireLocalTestQuotaMatchesFiles(t, root, restarted.repository.quota)
			localDurableReceiptTestRequireUnchanged(t, receiptPath, receiptBefore, receiptInfoBefore)
		})
	}
}

func TestLocalNativeRecordingRepositoryPromotesLifecycleAfterPublishedRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, suffix string
		encrypted    bool
	}{
		{name: "clear", suffix: ".bcast"},
		{name: "encrypted-cbor", suffix: ".becast", encrypted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, header, metadata := castTestValues(t, true)
			var recipient *bfcrypto.AgeSshRecipient
			if tc.encrypted {
				recipient, _ = newBECastTestEncryption(t)
			}
			promotionErr := stderrors.New("injected crash before lifecycle promotion")
			preparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity, failBeforePromote: promotionErr}
			repository, err := NewLocalNativeRecordingRepositoryWithArtifactPreparer(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions, preparer)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = repository.Close()
				_ = preparer.Close()
			})
			fileName := metadata.RecordingId.String() + tc.suffix
			receipts, err := preparer.get()
			require.NoError(t, err)
			require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, metadata.StartedAt, localLifecycleTestStartedEvent(metadata)))
			require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, localLifecycleTestCompletedEvent(metadata)))
			active, err := repository.CreateActive(t.Context(), header, metadata, 300)
			require.NoError(t, err)
			activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
			require.FileExists(t, filepath.Join(activeDirectory, localNativeHeadFileName))
			require.FileExists(t, filepath.Join(activeDirectory, "recording"+tc.suffix))
			require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("native published before promotion\r\n")))
			_, err = active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, sealedArtifactUint32(0))
			require.ErrorIs(t, err, promotionErr)
			require.Equal(t, 1, preparer.prepareCalls)
			require.Equal(t, 1, preparer.promoteCalls)
			require.Empty(t, mustLocalPendingLifecycle(t, preparer.receipts))
			sealedPath := filepath.Join(root, localSealedDirectory, fileName)
			require.DirExists(t, activeDirectory)
			require.FileExists(t, filepath.Join(activeDirectory, localNativeHeadFileName))
			require.NoFileExists(t, filepath.Join(activeDirectory, "recording"+tc.suffix))
			contents, err := os.ReadFile(sealedPath)
			require.NoError(t, err)
			require.Equal(t, fileName, preparer.prepared.FileName())
			require.Equal(t, int64(len(contents)), preparer.prepared.Size())
			require.Equal(t, ArtifactDigest(sha256.Sum256(contents)), preparer.prepared.Digest())
			workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
			require.NoDirExists(t, workDirectory)
			requireLocalTestQuotaMatchesFiles(t, root, repository.repository.quota)
			crashUsage := repository.repository.quota.usage
			receiptPath, receiptBefore, receiptInfoBefore := localDurableReceiptTestSnapshot(t, root, identity)
			require.ErrorIs(t, repository.Close(), promotionErr)
			require.NoError(t, preparer.Close())

			restartedPreparer := &localDurableReceiptCrashPreparer{directory: root, identity: identity}
			restarted, err := NewLocalNativeRecordingRepositoryWithArtifactPreparer(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, LocalRepositoryOptions{MaximumSpoolBytes: crashUsage}, restartedPreparer)
			require.NoError(t, err)
			t.Cleanup(func() {
				_ = restarted.Close()
				_ = restartedPreparer.Close()
			})
			require.Empty(t, restarted.StartupRecoveries())
			require.Equal(t, 0, restartedPreparer.prepareCalls)
			require.Equal(t, 1, restartedPreparer.promoteCalls)
			require.NoDirExists(t, activeDirectory)
			require.NoDirExists(t, workDirectory)
			pending := mustLocalPendingLifecycle(t, restartedPreparer.receipts)
			require.Len(t, pending, 1)
			require.Equal(t, audit.EventNameSessionRecordingCompleted, pending[0].Event.Name)
			sealed, err := restarted.OpenSealed(t.Context(), metadata.RecordingId)
			require.NoError(t, err)
			t.Cleanup(func() { _ = sealed.Close() })
			remote, err := sealed.RemoteArtifact()
			require.NoError(t, err)
			require.Equal(t, fileName, remote.FileName())
			require.Equal(t, int64(len(contents)), remote.Size())
			require.Equal(t, ArtifactDigest(sha256.Sum256(contents)), remote.Digest())
			require.NoError(t, restartedPreparer.Require(t.Context(), remote))
			sealedContents, err := os.ReadFile(sealedPath)
			require.NoError(t, err)
			require.Equal(t, contents, sealedContents)
			require.Equal(t, sealed.Summary().Digest.String(), pending[0].Event.RecordingDigest)
			requireLocalTestQuotaMatchesFiles(t, root, restarted.repository.quota)
			localDurableReceiptTestRequireUnchanged(t, receiptPath, receiptBefore, receiptInfoBefore)
		})
	}
}

type localDurableReceiptCrashPreparer struct {
	directory         string
	identity          *audit.Identity
	quota             audit.RemoteArtifactReceiptQuota
	receipts          *audit.RemoteArtifactReceipts
	failAfterPrepare  error
	prepared          audit.RemoteArtifact
	prepareCalls      int
	recordingDigest   CastDigest
	interrupted       bool
	failBeforePromote error
	promoteCalls      int
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

func (this *localDurableReceiptCrashPreparer) PrepareLifecycle(ctx context.Context, artifact audit.RemoteArtifact, sealedAt time.Time, recordingDigest CastDigest, interrupted bool) error {
	receipts, err := this.get()
	if err != nil {
		return err
	}
	if err := receipts.PrepareLifecycle(ctx, artifact, sealedAt, recordingDigest.String(), interrupted); err != nil {
		return err
	}
	this.prepared = artifact
	this.recordingDigest = recordingDigest
	this.interrupted = interrupted
	this.prepareCalls++
	return this.failAfterPrepare
}

func (this *localDurableReceiptCrashPreparer) PromoteLifecycle(ctx context.Context, artifact audit.RemoteArtifact) error {
	this.promoteCalls++
	if this.failBeforePromote != nil {
		return this.failBeforePromote
	}
	receipts, err := this.get()
	if err != nil {
		return err
	}
	return receipts.PromoteLifecycle(ctx, artifact)
}

func mustLocalPendingLifecycle(t *testing.T, receipts *audit.RemoteArtifactReceipts) []audit.RemoteArtifactLifecycleEvent {
	t.Helper()
	pending, err := receipts.PendingLifecycle(t.Context())
	require.NoError(t, err)
	return pending
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

func localLifecycleTestStartedEvent(metadata CastMetadata) audit.Event {
	pty := metadata.Pty
	return audit.Event{
		Name:         audit.EventNameSessionRecordingStarted,
		Domain:       audit.EventDomainSession,
		Flow:         metadata.Flow.String(),
		ConnectionId: metadata.ConnectionId.String(),
		SessionId:    metadata.SessionId.String(),
		OperationId:  metadata.OperationId.String(),
		RecordingId:  metadata.RecordingId.String(),
		SessionTask:  metadata.Task,
		Pty:          &pty,
	}
}

func localLifecycleTestCompletedEvent(metadata CastMetadata) audit.Event {
	duration := int64(2000)
	exitCode := 0
	event := localLifecycleTestStartedEvent(metadata)
	event.Name = audit.EventNameSessionRecordingCompleted
	event.Outcome = audit.EventOutcomeSuccess
	event.Pty = nil
	event.DurationMillis = &duration
	event.ExitCode = &exitCode
	return event
}
