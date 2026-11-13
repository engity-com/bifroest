package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/uuidtext"
	"github.com/stretchr/testify/require"
)

func TestRecordingReceiptNameLookupPreservesSignedLegacyLifecycleAndRejectsAliases(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	receipts, err := NewRemoteArtifactReceipts(root, identity, "security", nil, &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	defer receipts.Close()
	legacy := "6ba7b830-9dad-4d1f-80b4-00c04fd430c8.bcast"
	id, err := uuidtext.Parse(strings.TrimSuffix(legacy, ".bcast"))
	require.NoError(t, err)
	current := uuidtext.Format(id) + ".bcast"
	name, exists, err := receipts.ResolveRecordingFileName(current)
	require.NoError(t, err)
	require.False(t, exists)
	require.Equal(t, current, name)
	currentDirectory := filepath.Join(receipts.store.producerDirectory, remoteArtifactReceiptStateName(current))
	require.NoDirExists(t, currentDirectory, "a lookup must not create receipt state")
	started := remoteArtifactLifecycleTestStartedEvent(legacy)
	at := time.Now().UTC().Add(-time.Minute)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), legacy, at, started))
	legacyDirectory := filepath.Join(receipts.store.producerDirectory, remoteArtifactReceiptStateName(legacy))
	path := filepath.Join(legacyDirectory, remoteArtifactLifecycleFileName)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, input := range []string{legacy, current} {
		name, exists, err = receipts.ResolveRecordingFileName(input)
		require.NoError(t, err)
		require.True(t, exists)
		require.Equal(t, legacy, name)
	}
	base58, err := evidence.NormalizeEventIDs(started)
	require.NoError(t, err)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), legacy, at, base58))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after, "equivalent notation is idempotent, not a signature rewrite")
	terminal := remoteArtifactLifecycleTestCompletedEvent(base58)
	require.NoError(t, receipts.StageLifecycle(t.Context(), legacy, terminal))
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), legacy, []byte("public test recording bytes"))
	require.NoError(t, receipts.PrepareLifecycle(t.Context(), artifact, at.Add(5*time.Second), strings.Repeat("a", 64), false))
	require.NoError(t, receipts.PromoteLifecycle(t.Context(), artifact))
	pending := mustPendingRemoteArtifactLifecycle(t, receipts)
	require.Len(t, pending, 1)
	require.Equal(t, legacy, pending[0].FileName)
	require.NoError(t, receipts.CompleteLifecycle(t.Context(), pending[0]))
	require.NoDirExists(t, currentDirectory)
	require.NoError(t, os.Mkdir(currentDirectory, 0700))
	_, _, err = receipts.ResolveRecordingFileName(current)
	require.ErrorContains(t, err, "ambiguous")
	for _, input := range []string{"../" + current, "not-an-id.bcast", current + ".tmp"} {
		_, _, err = receipts.ResolveRecordingFileName(input)
		require.Error(t, err)
	}
}
