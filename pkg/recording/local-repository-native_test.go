package recording

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestLocalNativeRecordingRepositorySeal(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "clear"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, header, metadata := castTestValues(t, true)
			var recipient *bfcrypto.AgeSshRecipient
			var identities *bfcrypto.AgeSshIdentities
			if encrypted {
				recipient, identities = newBECastTestEncryption(t)
			}
			repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			active, err := repo.CreateActive(t.Context(), header, metadata, 0)
			require.NoError(t, err)
			activeDir := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
			require.FileExists(t, filepath.Join(activeDir, localNativeHeadFileName))
			require.NoFileExists(t, filepath.Join(activeDir, localHeadFileName))
			require.FileExists(t, filepath.Join(activeDir, "recording"+repo.repository.format.sealedSuffix()))
			require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("native repository output\r\n")))
			require.NoError(t, active.WriteResize(1100*time.Millisecond, 100, 30))
			require.NoError(t, active.WriteMarker(1200*time.Millisecond, "checkpoint"))
			require.NoError(t, active.Checkpoint())
			result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}
			summary, err := active.Seal(2*time.Second, result, sealedArtifactUint32(0))
			require.NoError(t, err)
			require.Equal(t, CastStatusCompleted, summary.Status)
			ids, err := repo.ListSealed(t.Context())
			require.NoError(t, err)
			require.Equal(t, []Id{metadata.RecordingId}, ids)
			artifact, err := repo.OpenSealed(t.Context(), metadata.RecordingId)
			require.NoError(t, err)
			require.Equal(t, metadata.RecordingId.String()+repo.repository.format.sealedSuffix(), artifact.FileName())
			require.Equal(t, summary, artifact.Summary())
			contents, err := os.ReadFile(filepath.Join(root, localSealedDirectory, artifact.FileName()))
			require.NoError(t, err)
			require.True(t, bytes.HasPrefix(contents, []byte(nativeformat.RecordingMagic)))
			verification, err := VerifyNativeRecordingFull(bytes.NewReader(contents), int64(len(contents)), identities, NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
			require.NoError(t, err)
			require.Equal(t, [32]byte(summary.Digest), verification.Seal.CastDigest)
			require.NoError(t, artifact.Close())
			requireLocalTestQuotaMatchesFiles(t, root, repo.repository.quota)
			require.NoError(t, repo.Close())
		})
	}
}

func TestLocalNativeRecordingRepositoryRecovery(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, work := range []bool{false, true} {
			name := "clear-active"
			if encrypted {
				name = "encrypted-active"
			}
			if work {
				name += "-work"
			}
			t.Run(name, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "recordings")
				identity, header, metadata := castTestValues(t, true)
				var recipient *bfcrypto.AgeSshRecipient
				var identities *bfcrypto.AgeSshIdentities
				if encrypted {
					recipient, identities = newBECastTestEncryption(t)
				}
				repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
				require.NoError(t, err)
				active, err := repo.CreateActive(t.Context(), header, metadata, 0)
				require.NoError(t, err)
				require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("recover me")))
				require.NoError(t, active.Close())
				require.NoError(t, repo.Close())
				if work {
					from := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
					to := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
					require.NoError(t, os.Rename(from, to))
				}
				reopened, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
				require.NoError(t, err)
				recoveries := reopened.StartupRecoveries()
				require.Len(t, recoveries, 1)
				require.Equal(t, CastStatusIncomplete, recoveries[0].Summary.Status)
				require.False(t, recoveries[0].AlreadySealed)
				artifact, err := reopened.OpenSealed(t.Context(), metadata.RecordingId)
				require.NoError(t, err)
				contents, err := os.ReadFile(filepath.Join(root, localSealedDirectory, artifact.FileName()))
				require.NoError(t, err)
				_, err = VerifyNativeRecordingFull(bytes.NewReader(contents), int64(len(contents)), identities, NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
				require.NoError(t, err)
				require.NoError(t, artifact.Close())
				requireLocalTestQuotaMatchesFiles(t, root, reopened.repository.quota)
				require.NoError(t, reopened.Close())
			})
		}
	}
}

func TestLocalNativeRecordingRepositoryRejectsOtherFormats(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	legacy, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, legacy.Close())
	_, err = NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.ErrorContains(t, err, "different or malformed format")

	other := filepath.Join(t.TempDir(), "recordings")
	clear, err := NewLocalNativeRecordingRepository(t.Context(), other, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoError(t, clear.Close())
	recipient, _ := newBECastTestEncryption(t)
	_, err = NewLocalNativeRecordingRepository(t.Context(), other, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.ErrorContains(t, err, "different or malformed format")
}

func TestLocalNativeRecordingRepositoryQuota(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	options := LocalRepositoryOptions{MaximumSpoolBytes: uint64(localRecoveryReserveSize) + 1}
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, options)
	require.NoError(t, err)
	_, err = repo.CreateActive(t.Context(), header, metadata, 0)
	require.ErrorContains(t, err, "spool limit")
	requireLocalTestQuotaMatchesFiles(t, root, repo.repository.quota)
	require.NoError(t, repo.Close())
}

func TestLocalNativeRecordingRepositoryQuotaOnCommittedFrame(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repo.CreateActive(t.Context(), header, metadata, 0)
	require.NoError(t, err)
	requireLocalTestQuotaMatchesFiles(t, root, repo.repository.quota)
	repo.repository.quota.maximum = repo.repository.quota.usage + 1
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("cannot commit past quota")))
	require.ErrorContains(t, active.Checkpoint(), "spool limit")
	requireLocalTestQuotaMatchesFiles(t, root, repo.repository.quota)
	require.Error(t, repo.Close())
}

func TestLocalNativeRecordingRepositoryWrongRecipientDoesNotMutateActive(t *testing.T) {
	for _, work := range []bool{false, true} {
		name := "active"
		if work {
			name = "work"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "recordings")
			identity, header, metadata := castTestValues(t, true)
			recipient, _ := newBECastTestEncryption(t)
			repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			active, err := repo.CreateActive(t.Context(), header, metadata, 0)
			require.NoError(t, err)
			require.NoError(t, active.Close())
			require.NoError(t, repo.Close())
			directory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
			if work {
				workDir := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
				require.NoError(t, os.Rename(directory, workDir))
				directory = workDir
			}
			path := filepath.Join(directory, "recording.becast")
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			other, _ := newBECastTestEncryptionWithByte(t, 0x71)
			_, err = NewLocalNativeRecordingRepository(t.Context(), root, identity, other, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.ErrorContains(t, err, "recipient")
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestLocalNativeRecordingRepositoryOpensSealedAfterRecipientRotation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	oldRecipient, _ := newBECastTestEncryption(t)
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, oldRecipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repo.CreateActive(t.Context(), header, metadata, 0)
	require.NoError(t, err)
	result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}
	_, err = active.Seal(time.Second, result, sealedArtifactUint32(0))
	require.NoError(t, err)
	require.NoError(t, repo.Close())

	newRecipient, _ := newBECastTestEncryptionWithByte(t, 0x71)
	reopened, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, newRecipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	artifact, err := reopened.OpenSealed(t.Context(), metadata.RecordingId)
	require.NoError(t, err)
	require.Equal(t, oldRecipient.Fingerprint(), artifact.Summary().RecipientFingerprint)
	require.NoError(t, artifact.Close())
	require.NoError(t, reopened.Close())
}

func TestLocalNativeRecordingRepositoryCompletesPublishedRecoveryAfterRecipientRotation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	oldRecipient, _ := newBECastTestEncryption(t)
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, oldRecipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repo.CreateActive(t.Context(), header, metadata, 0)
	require.NoError(t, err)
	activeDir := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	head, err := os.ReadFile(filepath.Join(activeDir, localNativeHeadFileName))
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("published before cleanup")))
	_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
	require.NoError(t, err)
	require.NoError(t, repo.Close())

	// Simulate a crash after publication, before the active head was removed.
	require.NoError(t, os.Mkdir(activeDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(activeDir, localNativeHeadFileName), head, 0600))
	sealedPath := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+".becast")
	before, err := os.ReadFile(sealedPath)
	require.NoError(t, err)
	newRecipient, _ := newBECastTestEncryptionWithByte(t, 0x71)
	reopened, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, newRecipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.NoDirExists(t, activeDir)
	artifact, err := reopened.OpenSealed(t.Context(), metadata.RecordingId)
	require.NoError(t, err)
	require.Equal(t, oldRecipient.Fingerprint(), artifact.Summary().RecipientFingerprint)
	require.NoError(t, artifact.Close())
	after, err := os.ReadFile(sealedPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.NoError(t, reopened.Close())
}

func TestLocalNativeRecordingRepositoryVerifiesOldSealedCheckpoint(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	metadata.StartedAt = time.Date(2012, time.January, 1, 0, 0, 0, 0, time.UTC)
	header.Timestamp = metadata.StartedAt.Unix()
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repo.CreateActive(t.Context(), header, metadata, 0)
	require.NoError(t, err)
	result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}
	_, err = active.Seal(time.Second, result, sealedArtifactUint32(0))
	require.NoError(t, err)
	require.NoError(t, repo.Close())
	reopened, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	artifact, err := reopened.OpenSealed(t.Context(), metadata.RecordingId)
	require.NoError(t, err)
	require.NoError(t, artifact.Close())
	require.NoError(t, reopened.Close())
}

func TestLocalNativeRecordingRepositoryQuarantinesInvalidWorkBeforeWrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repo.CreateActive(t.Context(), header, metadata, 0)
	require.NoError(t, err)
	require.NoError(t, active.Close())
	require.NoError(t, repo.Close())
	name := metadata.RecordingId.String() + ".tmp"
	work := filepath.Join(root, localWorkDirectory, name)
	require.NoError(t, os.Rename(filepath.Join(root, localActiveDirectory, metadata.RecordingId.String()), work))
	path := filepath.Join(work, "recording.bcast")
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = file.WriteAt([]byte("bad!"), 0)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	reopened, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Empty(t, reopened.StartupRecoveries())
	quarantined, err := os.ReadFile(filepath.Join(root, localQuarantineDirectory, name, "recording.bcast"))
	require.NoError(t, err)
	require.Equal(t, before, quarantined)
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+".bcast"))
	require.NoError(t, reopened.Close())
}
