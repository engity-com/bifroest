package recording

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestLocalBECastRepositoryCreateCheckpointAndSeal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	recipient, identities := newBECastTestEncryption(t)
	repository, err := NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("encrypted repository output\r\n")))
	require.NoError(t, active.WriteResize(1200*time.Millisecond, 132, 43))
	require.NoError(t, active.WriteMarker(1400*time.Millisecond, "checkpoint"))
	require.NoError(t, active.Checkpoint())
	exitStatus := uint32(0)
	summary, err := active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, &exitStatus)
	require.NoError(t, err)
	require.Equal(t, CastStatusCompleted, summary.Status)

	sealedPath := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localBECastSealedSuffix)
	file, err := openSealedLocalFile(sealedPath)
	require.NoError(t, err)
	info, err := file.Stat()
	require.NoError(t, err)
	verification, err := VerifyBECast(file, info.Size(), BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, summary, verification.Summary)
	var plaintext bytes.Buffer
	decrypted, err := DecryptBECast(file, info.Size(), identities, &plaintext, BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, summary, decrypted.Summary)
	require.Contains(t, plaintext.String(), "encrypted repository output")
	require.NoError(t, file.Close())
	_, err = os.Lstat(filepath.Join(root, localActiveDirectory, metadata.RecordingId.String()))
	require.ErrorIs(t, err, os.ErrNotExist)
	activeEntries, err := os.ReadDir(filepath.Join(root, localActiveDirectory))
	require.NoError(t, err)
	require.Empty(t, activeEntries)
	sealedEntries, err := os.ReadDir(filepath.Join(root, localSealedDirectory))
	require.NoError(t, err)
	require.Len(t, sealedEntries, 1)
	require.Equal(t, metadata.RecordingId.String()+localBECastSealedSuffix, sealedEntries[0].Name())
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localCastZstdSealedSuffix))
}

func TestLocalBECastRepositoryRecoversClosedActive(t *testing.T) {
	root, identity, recipient, identities, metadata := closedActiveLocalBECastTestRepository(t)
	reopened, err := NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	recoveries := reopened.StartupRecoveries()
	require.Len(t, recoveries, 1)
	require.Equal(t, metadata.RecordingId, recoveries[0].Summary.RecordingId)
	require.Equal(t, CastStatusIncomplete, recoveries[0].Summary.Status)
	require.False(t, recoveries[0].Truncated)
	require.False(t, recoveries[0].AlreadySealed)
	require.NoError(t, reopened.Close())

	sealedPath := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localBECastSealedSuffix)
	file, err := openSealedLocalFile(sealedPath)
	require.NoError(t, err)
	info, err := file.Stat()
	require.NoError(t, err)
	outer, err := VerifyBECast(file, info.Size(), BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, recoveries[0].Summary, outer.Summary)
	var plaintext bytes.Buffer
	verification, err := DecryptBECast(file, info.Size(), identities, &plaintext, BECastVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.NoError(t, err)
	require.Equal(t, CastStatusIncomplete, verification.Cast.Result.Status)
	require.Equal(t, startupRecoveryReason, verification.Cast.Result.Reason)
	require.NoError(t, file.Close())
}

func TestLocalBECastRepositoryRecoversCommittedWorkDirectory(t *testing.T) {
	root, identity, recipient, _, metadata := closedActiveLocalBECastTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))

	repository, err := NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Len(t, repository.StartupRecoveries(), 1)
	require.NoError(t, repository.Close())
	require.NoDirExists(t, workDirectory)
	require.NoDirExists(t, activeDirectory)
	require.FileExists(t, filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localBECastSealedSuffix))
}

func TestLocalBECastRepositoryWrongRecipientFailsWithoutMutation(t *testing.T) {
	root, identity, _, _, metadata := closedActiveLocalBECastTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	contentPath := filepath.Join(activeDirectory, localBECastContentFileName)
	headPath := filepath.Join(activeDirectory, localHeadFileName)
	contentBefore, err := os.ReadFile(contentPath)
	require.NoError(t, err)
	headBefore, err := os.ReadFile(headPath)
	require.NoError(t, err)
	wrongRecipient, _ := newBECastTestEncryptionWithByte(t, 0x71)

	_, err = NewLocalBECastRepository(t.Context(), root, identity, wrongRecipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.ErrorContains(t, err, "recipient does not match")
	contentAfter, readErr := os.ReadFile(contentPath)
	require.NoError(t, readErr)
	headAfter, readErr := os.ReadFile(headPath)
	require.NoError(t, readErr)
	require.Equal(t, contentBefore, contentAfter)
	require.Equal(t, headBefore, headAfter)
	require.NoDirExists(t, filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp"))
	require.NoFileExists(t, filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localBECastSealedSuffix))
}

func TestLocalBECastRepositoryWrongRecipientLeavesCommittedWorkUnchanged(t *testing.T) {
	root, identity, _, _, metadata := closedActiveLocalBECastTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	contentPath := filepath.Join(workDirectory, localBECastContentFileName)
	headPath := filepath.Join(workDirectory, localHeadFileName)
	contentBefore, err := os.ReadFile(contentPath)
	require.NoError(t, err)
	headBefore, err := os.ReadFile(headPath)
	require.NoError(t, err)
	wrongRecipient, _ := newBECastTestEncryptionWithByte(t, 0x71)

	_, err = NewLocalBECastRepository(t.Context(), root, identity, wrongRecipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.ErrorContains(t, err, "recipient does not match")
	require.True(t, bferrors.Config.IsErr(err))
	require.DirExists(t, workDirectory)
	require.NoDirExists(t, activeDirectory)
	require.NoDirExists(t, filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp"))
	contentAfter, readErr := os.ReadFile(contentPath)
	require.NoError(t, readErr)
	headAfter, readErr := os.ReadFile(headPath)
	require.NoError(t, readErr)
	require.Equal(t, contentBefore, contentAfter)
	require.Equal(t, headBefore, headAfter)
}

func TestLocalBECastRepositoryAllowsRecipientChanges(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	firstRecipient, _ := newBECastTestEncryption(t)
	first, err := NewLocalBECastRepository(t.Context(), root, identity, firstRecipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := first.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	exitStatus := uint32(0)
	_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &exitStatus)
	require.NoError(t, err)
	require.NoError(t, first.Close())

	secondRecipient, _ := newBECastTestEncryptionWithByte(t, 0x71)
	second, err := NewLocalBECastRepository(t.Context(), root, identity, secondRecipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	metadata.RecordingId, err = NewId()
	require.NoError(t, err)
	active, err = second.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	summary, err := active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &exitStatus)
	require.NoError(t, err)
	require.Equal(t, secondRecipient.Fingerprint(), summary.RecipientFingerprint)
	require.NoError(t, second.Close())
}

func TestLocalBECastRepositoryQuarantinesInvalidCommittedWork(t *testing.T) {
	root, identity, recipient, _, metadata := closedActiveLocalBECastTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	require.NoError(t, os.Rename(activeDirectory, workDirectory))
	replaceLocalBECastTestHead(t, workDirectory, func(head audit.SessionRecordingBECastHead) audit.SessionRecordingBECastHead {
		head.Signature = append([]byte(nil), head.Signature...)
		head.Signature[0] ^= 1
		return head
	})

	repository, err := NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	require.Empty(t, repository.StartupRecoveries())
	require.NoError(t, repository.Close())
	require.NoDirExists(t, workDirectory)
	require.FileExists(t, filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp", localBECastContentFileName))
}

func TestLocalBECastRepositoryRestrictiveLimitsDoNotQuarantineValidWork(t *testing.T) {
	root, identity, recipient, _, metadata := closedActiveLocalBECastTestRepository(t)
	activeDirectory := filepath.Join(root, localActiveDirectory, metadata.RecordingId.String())
	workDirectory := filepath.Join(root, localWorkDirectory, metadata.RecordingId.String()+".tmp")
	contentPath := filepath.Join(activeDirectory, localBECastContentFileName)
	contentBefore, err := os.ReadFile(contentPath)
	require.NoError(t, err)
	require.NoError(t, os.Rename(activeDirectory, workDirectory))

	_, err = NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{
		MaximumContainerBytes: 1,
		MaximumCastBytes:      1,
		MaximumChunks:         1,
	}, localRepositoryTestOptions)
	require.Error(t, err)
	require.NoDirExists(t, workDirectory)
	require.DirExists(t, activeDirectory)
	require.NoDirExists(t, filepath.Join(root, localQuarantineDirectory, metadata.RecordingId.String()+".tmp"))
	contentAfter, readErr := os.ReadFile(contentPath)
	require.NoError(t, readErr)
	require.Equal(t, contentBefore, contentAfter)
}

func TestLocalBECastWorkValidationTreatsReadFailureAsOperational(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	var output bytes.Buffer
	writer, err := NewBECastWriter(&output, identity, recipient, header, metadata, 300)
	require.NoError(t, err)
	head, err := writer.Checkpoint()
	require.NoError(t, err)
	format := &localBECastFormat{
		identity:  identity,
		recipient: recipient,
		options: BECastVerifyOptions{
			ExpectedProducerId: identity.ProducerId(),
		},
	}

	err = format.verifyWorkCheckpointReader(localReadFailure{}, int64(output.Len()), head, t.Context())
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.False(t, isInvalidLocalArtifact(err))
}

func TestLocalBECastScanOptionsNormalizeLimits(t *testing.T) {
	ctx := t.Context()
	for _, current := range []struct {
		name     string
		input    BECastVerifyOptions
		expected BECastVerifyOptions
	}{
		{
			name: "zero",
			expected: BECastVerifyOptions{
				MaximumContainerBytes: DefaultMaximumBECastBytes,
				MaximumCastBytes:      DefaultMaximumCastBytes,
				MaximumChunks:         DefaultMaximumBECastChunks,
			},
		},
		{
			name:  "restrictive",
			input: BECastVerifyOptions{MaximumContainerBytes: 1, MaximumCastBytes: 1, MaximumChunks: 1},
			expected: BECastVerifyOptions{
				MaximumContainerBytes: DefaultMaximumBECastBytes,
				MaximumCastBytes:      DefaultMaximumCastBytes,
				MaximumChunks:         DefaultMaximumBECastChunks,
			},
		},
		{
			name: "elevated",
			input: BECastVerifyOptions{
				MaximumContainerBytes: DefaultMaximumBECastBytes + 1,
				MaximumCastBytes:      DefaultMaximumCastBytes + 2,
				MaximumChunks:         DefaultMaximumBECastChunks + 3,
			},
			expected: BECastVerifyOptions{
				MaximumContainerBytes: DefaultMaximumBECastBytes + 1,
				MaximumCastBytes:      DefaultMaximumCastBytes + 2,
				MaximumChunks:         DefaultMaximumBECastChunks + 3,
			},
		},
	} {
		t.Run(current.name, func(t *testing.T) {
			options, err := (&localBECastFormat{options: current.input}).workScanOptions(ctx)
			require.NoError(t, err)
			current.expected.Context = ctx
			require.Equal(t, current.expected, options)
		})
	}
}

func TestLocalBECastPublishedScanOptionsUseVerificationLimit(t *testing.T) {
	options, err := (&localBECastFormat{}).scanOptions(t.Context())
	require.NoError(t, err)
	require.Equal(t, DefaultMaximumBECastBytes, options.MaximumContainerBytes)
}

func TestLocalBECastRecoveryOptionsUseRepositoryDefaultLimit(t *testing.T) {
	ctx := t.Context()
	for _, current := range []struct {
		name     string
		input    int64
		expected int64
	}{
		{name: "default", expected: int64(32 << 30)},
		{name: "restrictive", input: 1, expected: 1},
		{name: "elevated", input: DefaultMaximumBECastBytes + 1, expected: DefaultMaximumBECastBytes + 1},
	} {
		t.Run(current.name, func(t *testing.T) {
			options, err := (&localBECastFormat{options: BECastVerifyOptions{MaximumContainerBytes: current.input}}).recoveryOptions(ctx)
			require.NoError(t, err)
			require.Equal(t, current.expected, options.MaximumContainerBytes)
			require.Equal(t, ctx, options.Context)
		})
	}
}

func TestLocalBECastScanOptionsRejectNegativeLimits(t *testing.T) {
	for _, options := range []BECastVerifyOptions{{MaximumContainerBytes: -1}, {MaximumCastBytes: -1}} {
		_, err := (&localBECastFormat{options: options}).scanOptions(t.Context())
		require.Error(t, err)
		require.True(t, bferrors.Config.IsErr(err))
		require.False(t, isInvalidLocalArtifact(err))
	}
}

func TestLocalBECastNilReceivers(t *testing.T) {
	var repository *LocalBECastRepository
	require.Nil(t, repository.StartupRecoveries())
	_, err := repository.CreateActive(t.Context(), CastHeader{}, CastMetadata{}, 0)
	require.Error(t, err)
	require.NoError(t, repository.Close())
	var active *ActiveBECast
	require.Error(t, active.WriteOutput(0, OutputStreamStdout, nil))
	require.Error(t, active.WriteResize(0, 1, 1))
	require.Error(t, active.WriteMarker(0, "marker"))
	require.Error(t, active.Checkpoint())
	_, err = active.Seal(0, CastResult{}, nil)
	require.Error(t, err)
	require.NoError(t, active.Close())
}

func TestNewLocalBECastRepositoryRejectsNilDependencies(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, _, _ := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	for _, current := range []struct {
		identity  *audit.Identity
		recipient *crypto.AgeSshRecipient
	}{
		{recipient: recipient},
		{identity: identity},
	} {
		_, err := NewLocalBECastRepository(t.Context(), root, current.identity, current.recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
		require.Error(t, err)
		require.True(t, bferrors.Config.IsErr(err))
	}
}

func closedActiveLocalBECastTestRepository(t *testing.T) (string, *audit.Identity, *crypto.AgeSshRecipient, *crypto.AgeSshIdentities, CastMetadata) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	recipient, identities := newBECastTestEncryption(t)
	repository, err := NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("interrupted encrypted output\r\n")))
	require.NoError(t, active.Close())
	require.NoError(t, repository.Close())
	return root, identity, recipient, identities, metadata
}

func replaceLocalBECastTestHead(t *testing.T, directory string, mutate func(audit.SessionRecordingBECastHead) audit.SessionRecordingBECastHead) {
	t.Helper()
	path := filepath.Join(directory, localHeadFileName)
	payload, err := loadLocalHead(path, maximumCastBECastHeadBytes)
	require.NoError(t, err)
	head, err := decodeBECastHead(payload)
	require.NoError(t, err)
	payload, err = encodeBECastHead(mutate(head))
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))
	require.NoError(t, writeLocalHead(directory, payload, nil))
}
