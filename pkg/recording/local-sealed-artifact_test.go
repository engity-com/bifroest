package recording

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLocalCastZstdRepositoryListsAndOpensSealedArtifacts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })

	ids := []Id{metadata.RecordingId}
	for index := 0; index < 2; index++ {
		current := metadata
		if index > 0 {
			current.RecordingId, err = NewId()
			require.NoError(t, err)
			ids = append(ids, current.RecordingId)
		}
		active, err := repository.CreateActive(t.Context(), header, current, 300)
		require.NoError(t, err)
		require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("sealed artifact\r\n")))
		_, err = active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: current.StartedAt.Add(2 * time.Second)}, sealedArtifactUint32(0))
		require.NoError(t, err)
	}

	sort.Slice(ids, func(left, right int) bool { return ids[left].String() < ids[right].String() })
	listed, err := repository.ListSealed(t.Context())
	require.NoError(t, err)
	require.Equal(t, ids, listed)

	artifact, err := repository.OpenSealed(t.Context(), metadata.RecordingId)
	require.NoError(t, err)
	require.Equal(t, metadata.RecordingId, artifact.RecordingId())
	require.Equal(t, identity.ProducerId(), artifact.ProducerId())
	require.Equal(t, metadata.RecordingId.String()+localCastZstdSealedSuffix, artifact.FileName())
	require.Positive(t, artifact.Size())
	require.Equal(t, CastStatusCompleted, artifact.Summary().Status)
	require.False(t, artifact.ArtifactDigest().IsZero())

	payload, err := io.ReadAll(artifact.Reader())
	require.NoError(t, err)
	require.Len(t, payload, int(artifact.Size()))
	expectedDigest := ArtifactDigest(sha256.Sum256(payload))
	require.Equal(t, expectedDigest, artifact.ArtifactDigest())
	remoteArtifact, err := artifact.RemoteArtifact()
	require.NoError(t, err)
	require.Equal(t, artifact.ProducerId(), remoteArtifact.ProducerId())
	require.Equal(t, artifact.FileName(), remoteArtifact.FileName())
	require.Equal(t, artifact.ArtifactDigest(), remoteArtifact.Digest())
	require.NoError(t, remoteArtifact.Validate())
	digestText, err := artifact.ArtifactDigest().MarshalText()
	require.NoError(t, err)
	var decodedDigest ArtifactDigest
	require.NoError(t, decodedDigest.UnmarshalText(digestText))
	require.Equal(t, artifact.ArtifactDigest(), decodedDigest)
	require.Error(t, decodedDigest.UnmarshalText([]byte(strings.ToUpper(strings.Repeat("ab", sha256.Size)))))

	second, err := repository.OpenSealed(t.Context(), metadata.RecordingId)
	require.NoError(t, err)
	require.NoError(t, artifact.Close())
	require.NoError(t, artifact.Close())
	_, err = artifact.RemoteArtifact()
	require.ErrorContains(t, err, "closed")
	_, err = artifact.ReadAt(make([]byte, 1), 0)
	require.ErrorContains(t, err, "closed")
	secondPayload, err := io.ReadAll(second.Reader())
	require.NoError(t, err)
	require.Equal(t, payload, secondPayload)
	require.NoError(t, second.Close())
}

func TestLocalBECastRepositoryListsAndOpensSealedArtifacts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	repository, err := NewLocalBECastRepository(t.Context(), root, identity, recipient, BECastVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	require.NoError(t, active.WriteOutput(time.Second, OutputStreamTerminal, []byte("encrypted artifact\r\n")))
	summary, err := active.Seal(2*time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(2 * time.Second)}, sealedArtifactUint32(7))
	require.NoError(t, err)

	listed, err := repository.ListSealed(t.Context())
	require.NoError(t, err)
	require.Equal(t, []Id{metadata.RecordingId}, listed)
	artifact, err := repository.OpenSealed(t.Context(), metadata.RecordingId)
	require.NoError(t, err)
	defer func() { require.NoError(t, artifact.Close()) }()
	require.Equal(t, metadata.RecordingId.String()+localBECastSealedSuffix, artifact.FileName())
	require.Equal(t, summary, artifact.Summary())
	payload, err := io.ReadAll(artifact.Reader())
	require.NoError(t, err)
	require.Equal(t, ArtifactDigest(sha256.Sum256(payload)), artifact.ArtifactDigest())
}

func TestLocalRepositorySealedArtifactAccessFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "recordings")
	identity, header, metadata := castTestValues(t, true)
	repository, err := NewLocalCastZstdRepository(t.Context(), root, identity, CastZstdVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	active, err := repository.CreateActive(t.Context(), header, metadata, 300)
	require.NoError(t, err)
	_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
	require.NoError(t, err)

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = repository.ListSealed(canceled)
	require.ErrorIs(t, err, context.Canceled)
	_, err = repository.OpenSealed(canceled, metadata.RecordingId)
	require.ErrorIs(t, err, context.Canceled)
	repository.repository.mutex.Lock()
	waiting, stopWaiting := context.WithTimeout(t.Context(), 20*time.Millisecond)
	_, err = repository.ListSealed(waiting)
	stopWaiting()
	repository.repository.mutex.Unlock()
	require.ErrorIs(t, err, context.DeadlineExceeded)

	wrongId, err := NewId()
	require.NoError(t, err)
	originalPath := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+localCastZstdSealedSuffix)
	wrongPath := filepath.Join(root, localSealedDirectory, wrongId.String()+localCastZstdSealedSuffix)
	require.NoError(t, os.Rename(originalPath, wrongPath))
	_, err = repository.OpenSealed(t.Context(), wrongId)
	require.ErrorContains(t, err, "does not match its file name")

	require.NoError(t, repository.Close())
	_, err = repository.ListSealed(t.Context())
	require.ErrorContains(t, err, "closed")
	_, err = repository.OpenSealed(t.Context(), metadata.RecordingId)
	require.ErrorContains(t, err, "closed")
}

func sealedArtifactUint32(value uint32) *uint32 { return &value }
