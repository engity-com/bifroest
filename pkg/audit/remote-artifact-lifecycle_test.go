package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRemoteArtifactLifecycleOutboxBindsArtifactAndBlocksRetention(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", quota)
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	fileName := "6ba7b830-9dad-4d1f-80b4-00c04fd430c8.bcast"
	lifecyclePath := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(fileName), remoteArtifactLifecycleFileName)
	assertOutboxFields := func(keys ...string) {
		t.Helper()
		payload, err := os.ReadFile(lifecyclePath)
		require.NoError(t, err)
		var stored struct {
			Event map[string]json.RawMessage `json:"event"`
		}
		require.NoError(t, json.Unmarshal(payload, &stored))
		require.Len(t, stored.Event, len(keys))
		for _, key := range keys {
			require.Contains(t, stored.Event, key)
		}
		require.Equal(t, json.RawMessage(`"recording-test"`), stored.Event["flow"])
	}
	startedAt := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	started := remoteArtifactLifecycleTestStartedEvent(fileName)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, startedAt, started))
	assertOutboxFields("name", "domain", "flow", "connectionId", "sessionId", "operationId", "recordingId", "sessionTask", "pty")
	terminal := remoteArtifactLifecycleTestCompletedEvent(started)
	require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, terminal))
	terminalFields := []string{"name", "domain", "outcome", "flow", "connectionId", "sessionId", "operationId", "recordingId", "sessionTask", "durationMillis", "exitCode"}
	assertOutboxFields(terminalFields...)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), fileName, []byte("sealed recording"))
	sealedAt := startedAt.Add(5 * time.Second)
	recordingDigest := strings.Repeat("a", 64)
	require.NoError(t, receipts.PrepareLifecycle(t.Context(), artifact, sealedAt, recordingDigest, false))
	preparedFields := append(terminalFields, "recordingDigest")
	assertOutboxFields(preparedFields...)
	require.Empty(t, mustPendingRemoteArtifactLifecycle(t, receipts))
	lifecyclePrepared, err := receipts.LifecyclePrepared(t.Context(), fileName)
	require.NoError(t, err)
	require.True(t, lifecyclePrepared)
	prepared, exists, err := store.loadLifecycleLocked(fileName, nil)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, remoteArtifactLifecycleStatePrepared, prepared.State)
	require.Equal(t, artifact.Digest(), prepared.ArtifactDigest)
	require.Equal(t, recordingDigest, prepared.Event.RecordingDigest)

	candidates, err := receipts.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	require.Empty(t, candidates)
	receipt, exists, err := store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	forged := remoteArtifactRetentionCandidate(receipt, false, false)
	require.ErrorContains(t, receipts.MarkRetentionDeleting(t.Context(), forged, sealedAt), "unfinished session Recording lifecycle")

	require.NoError(t, receipts.PromoteLifecycle(t.Context(), artifact))
	assertOutboxFields(preparedFields...)
	pending, err := receipts.PendingLifecycle(t.Context())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, artifact.Digest(), pending[0].ArtifactDigest)
	require.Equal(t, recordingDigest, pending[0].Event.RecordingDigest)
	require.NotEqual(t, artifact.Digest().String(), pending[0].Event.RecordingDigest)
	require.Equal(t, terminal.Name, pending[0].Event.Name)

	candidates, err = receipts.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	require.Empty(t, candidates)

	require.NoError(t, receipts.CompleteLifecycle(t.Context(), pending[0]))
	require.NoFileExists(t, lifecyclePath)
	require.Empty(t, mustPendingRemoteArtifactLifecycle(t, receipts))
	lifecyclePrepared, err = receipts.LifecyclePrepared(t.Context(), fileName)
	require.NoError(t, err)
	require.False(t, lifecyclePrepared)
	candidates, err = receipts.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
}

func TestRemoteArtifactLifecycleRejectsTamperingAndAcceptsLegacyReceipt(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })

	legacy := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b831-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("legacy"))
	sealedAt := time.Date(2026, 9, 21, 11, 0, 0, 0, time.UTC)
	require.NoError(t, receipts.Prepare(t.Context(), legacy, sealedAt))
	require.Empty(t, mustPendingRemoteArtifactLifecycle(t, receipts))
	candidates, err := receipts.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	require.Len(t, candidates, 1)

	fileName := "6ba7b832-9dad-4d1f-80b4-00c04fd430c8.bcast"
	started := remoteArtifactLifecycleTestStartedEvent(fileName)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, sealedAt, started))
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(fileName))
	path := filepath.Join(directory, remoteArtifactLifecycleFileName)
	payload, err := os.ReadFile(path)
	require.NoError(t, err)
	var marker remoteArtifactLifecycle
	require.NoError(t, json.Unmarshal(payload, &marker))
	marker.Event.Flow = "tampered"
	payload, err = json.Marshal(marker)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, payload, journalFileMode))
	_, err = receipts.PendingLifecycle(t.Context())
	require.ErrorContains(t, err, "cannot verify session Recording lifecycle state")
}

func TestRemoteArtifactLifecycleRecoversSignedTemporarySuccessor(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", quota)
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store}
	fileName := "6ba7b833-9dad-4d1f-80b4-00c04fd430c8.becast"
	startedAt := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	started := remoteArtifactLifecycleTestStartedEvent(fileName)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, startedAt, started))
	marker, exists, err := store.loadLifecycleLocked(fileName, nil)
	require.NoError(t, err)
	require.True(t, exists)
	content := marker.remoteArtifactLifecycleContent
	content.State = remoteArtifactLifecycleStateStaged
	content.Event = remoteArtifactLifecycleTestCompletedEvent(started)
	_, payload, err := signRemoteArtifactLifecycle(identity, content)
	require.NoError(t, err)
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(fileName))
	temporary := filepath.Join(directory, remoteArtifactLifecycleTempName)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, payload))
	usage, err := remoteArtifactReceiptStateUsage(directory)
	require.NoError(t, err)
	quota.usage = uint64(usage)
	require.NoError(t, receipts.Close())

	restartedStore, err := newRemoteArtifactReceiptStore(root, identity, "security", quota)
	require.NoError(t, err)
	restarted := &RemoteArtifactReceipts{store: restartedStore}
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	require.NoError(t, restarted.Recover(t.Context()))
	recovered, exists, err := restartedStore.loadLifecycleLocked(fileName, nil)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, remoteArtifactLifecycleStateStaged, recovered.State)
	require.NoFileExists(t, temporary)
}

func TestRemoteArtifactLifecycleRecoversPreparedPromotionSuccessor(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", quota)
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	fileName := "6ba7b846-9dad-4d1f-80b4-00c04fd430c8.bcast"
	startedAt := time.Date(2026, 9, 21, 12, 30, 0, 0, time.UTC)
	started := remoteArtifactLifecycleTestStartedEvent(fileName)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, startedAt, started))
	require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, remoteArtifactLifecycleTestCompletedEvent(started)))
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), fileName, []byte("prepared promotion"))
	require.NoError(t, receipts.PrepareLifecycle(t.Context(), artifact, startedAt.Add(time.Second), strings.Repeat("f", 64), false))
	prepared, exists, err := store.loadLifecycleLocked(fileName, nil)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, remoteArtifactLifecycleStatePrepared, prepared.State)
	content := prepared.remoteArtifactLifecycleContent
	content.State = remoteArtifactLifecycleStatePending
	_, payload, err := signRemoteArtifactLifecycle(identity, content)
	require.NoError(t, err)
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(fileName))
	temporary := filepath.Join(directory, remoteArtifactLifecycleTempName)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, payload))
	usage, err := remoteArtifactReceiptStateUsage(directory)
	require.NoError(t, err)
	quota.usage = uint64(usage)
	require.NoError(t, receipts.Close())

	restartedStore, err := newRemoteArtifactReceiptStore(root, identity, "security", quota)
	require.NoError(t, err)
	restarted := &RemoteArtifactReceipts{store: restartedStore}
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	require.NoError(t, restarted.Recover(t.Context()))
	pending := mustPendingRemoteArtifactLifecycle(t, restarted)
	require.Len(t, pending, 1)
	require.Equal(t, remoteArtifactLifecycleStatePending, mustRemoteArtifactLifecycle(t, restartedStore, fileName).State)
	require.NoFileExists(t, temporary)
}

func TestRemoteArtifactLifecycleCleansOrphanedPreCreateIntent(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	fileName := "6ba7b837-9dad-4d1f-80b4-00c04fd430c8.bcast"
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, time.Now().UTC(), remoteArtifactLifecycleTestStartedEvent(fileName)))
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(fileName))
	require.DirExists(t, directory)
	require.NoError(t, receipts.CleanupOrphanedLifecycles(t.Context()))
	require.NoDirExists(t, directory)
}

func TestRemoteArtifactLifecycleRecoveryOverwritesStagedTerminalEvent(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	fileName := "6ba7b838-9dad-4d1f-80b4-00c04fd430c8.bcast"
	startedAt := time.Date(2026, 9, 21, 13, 0, 0, 0, time.UTC)
	started := remoteArtifactLifecycleTestStartedEvent(fileName)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, startedAt, started))
	require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, remoteArtifactLifecycleTestCompletedEvent(started)))
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), fileName, []byte("recovered recording"))
	recordingDigest := strings.Repeat("b", 64)
	require.NoError(t, receipts.PrepareLifecycle(t.Context(), artifact, startedAt.Add(7*time.Second), recordingDigest, true))
	require.Empty(t, mustPendingRemoteArtifactLifecycle(t, receipts))
	prepared, exists, err := store.loadLifecycleLocked(fileName, nil)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, remoteArtifactLifecycleStatePrepared, prepared.State)
	require.Equal(t, EventNameSessionRecordingIncomplete, prepared.Event.Name)
	require.NoError(t, receipts.PromoteLifecycle(t.Context(), artifact))
	pending := mustPendingRemoteArtifactLifecycle(t, receipts)
	require.Len(t, pending, 1)
	require.Equal(t, EventNameSessionRecordingIncomplete, pending[0].Event.Name)
	require.Equal(t, EventOutcomeFailure, pending[0].Event.Outcome)
	require.Equal(t, EventReasonStartupRecovery, pending[0].Event.Reason)
	require.Equal(t, recordingDigest, pending[0].Event.RecordingDigest)
	require.Equal(t, int64(7000), *pending[0].Event.DurationMillis)
	require.Nil(t, pending[0].Event.ExitCode)
}

func TestRemoteArtifactLifecycleRejectsDiscardAndCleanupOfNonIntentState(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	fileName := "6ba7b839-9dad-4d1f-80b4-00c04fd430c8.bcast"
	started := remoteArtifactLifecycleTestStartedEvent(fileName)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, time.Now().UTC(), started))
	require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, remoteArtifactLifecycleTestCompletedEvent(started)))

	require.ErrorContains(t, receipts.DiscardLifecycle(t.Context(), fileName), "cannot discard non-intent")
	require.ErrorContains(t, receipts.CleanupOrphanedLifecycles(t.Context()), "non-intent session Recording lifecycle")
	marker, exists, err := store.loadLifecycleLocked(fileName, nil)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, remoteArtifactLifecycleStateStaged, marker.State)
}

func TestRemoteArtifactLifecycleCleanupRejectsPendingStateWithoutReceipt(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	fileName := "6ba7b841-9dad-4d1f-80b4-00c04fd430c8.bcast"
	startedAt := time.Now().UTC()
	started := remoteArtifactLifecycleTestStartedEvent(fileName)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, startedAt, started))
	require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, remoteArtifactLifecycleTestCompletedEvent(started)))
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), fileName, []byte("pending without receipt"))
	require.NoError(t, receipts.PrepareLifecycle(t.Context(), artifact, startedAt.Add(time.Second), strings.Repeat("c", 64), false))
	require.NoError(t, receipts.PromoteLifecycle(t.Context(), artifact))
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(fileName))
	require.NoError(t, os.Remove(filepath.Join(directory, remoteArtifactReceiptFileName)))

	require.ErrorContains(t, receipts.CleanupOrphanedLifecycles(t.Context()), "non-intent session Recording lifecycle")
	require.FileExists(t, filepath.Join(directory, remoteArtifactLifecycleFileName))
}

func TestRemoteArtifactLifecycleOperationsRejectClosedStore(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	fileName := "6ba7b840-9dad-4d1f-80b4-00c04fd430c8.bcast"
	startedAt := time.Now().UTC()
	started := remoteArtifactLifecycleTestStartedEvent(fileName)
	require.NoError(t, receipts.BeginLifecycle(t.Context(), fileName, startedAt, started))
	require.NoError(t, receipts.StageLifecycle(t.Context(), fileName, remoteArtifactLifecycleTestCompletedEvent(started)))
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), fileName, []byte("closed store"))
	require.NoError(t, receipts.PrepareLifecycle(t.Context(), artifact, startedAt.Add(time.Second), strings.Repeat("d", 64), false))
	require.NoError(t, receipts.PromoteLifecycle(t.Context(), artifact))
	pending := mustPendingRemoteArtifactLifecycle(t, receipts)[0]
	require.NoError(t, receipts.Close())

	require.ErrorContains(t, receipts.CompleteLifecycle(t.Context(), pending), "store is closed")
	require.ErrorContains(t, receipts.DiscardLifecycle(t.Context(), fileName), "store is closed")
	require.ErrorContains(t, receipts.CleanupOrphanedLifecycles(t.Context()), "store is closed")
}

func TestRemoteArtifactLifecyclePrepareRequiresMarkerBeforeReceipt(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	fileName := "6ba7b845-9dad-4d1f-80b4-00c04fd430c8.bcast"
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), fileName, []byte("missing lifecycle"))

	require.ErrorContains(t, receipts.PrepareLifecycle(t.Context(), artifact, time.Now().UTC(), strings.Repeat("e", 64), false), "lifecycle state")
	_, exists, err := store.load(artifact)
	require.NoError(t, err)
	require.False(t, exists)
}

func TestRemoteArtifactLifecycleRejectsUnreleasedSuffixAndInvalidRecordingId(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	fileName := "6ba7b847-9dad-4d1f-80b4-00c04fd430c8.cast.zst"
	require.ErrorContains(t, receipts.BeginLifecycle(t.Context(), fileName, time.Now().UTC(), remoteArtifactLifecycleTestStartedEvent(fileName)), "does not match its artifact name")
	fileName = "invalid-id.bcast"
	started := remoteArtifactLifecycleTestStartedEvent("6ba7b847-9dad-4d1f-80b4-00c04fd430c8.bcast")
	started.RecordingId = "invalid-id"
	require.ErrorContains(t, receipts.BeginLifecycle(t.Context(), fileName, time.Now().UTC(), started), "illegal audit event recording ID")
}

func remoteArtifactLifecycleTestStartedEvent(fileName string) Event {
	recordingId := fileName[:36]
	pty := true
	return Event{
		Name:         EventNameSessionRecordingStarted,
		Domain:       EventDomainSession,
		Flow:         "recording-test",
		ConnectionId: "6ba7b834-9dad-4d1f-80b4-00c04fd430c8",
		SessionId:    "6ba7b835-9dad-4d1f-80b4-00c04fd430c8",
		OperationId:  "6ba7b836-9dad-4d1f-80b4-00c04fd430c8",
		RecordingId:  recordingId,
		SessionTask:  SessionTaskShell,
		Pty:          &pty,
	}
}

func remoteArtifactLifecycleTestCompletedEvent(started Event) Event {
	duration := int64(5000)
	exitCode := 0
	started.Name = EventNameSessionRecordingCompleted
	started.Outcome = EventOutcomeSuccess
	started.Pty = nil
	started.DurationMillis = &duration
	started.ExitCode = &exitCode
	return started
}

func mustPendingRemoteArtifactLifecycle(t *testing.T, receipts *RemoteArtifactReceipts) []RemoteArtifactLifecycleEvent {
	t.Helper()
	pending, err := receipts.PendingLifecycle(t.Context())
	require.NoError(t, err)
	return pending
}

func mustRemoteArtifactLifecycle(t *testing.T, store *remoteArtifactReceiptStore, fileName string) remoteArtifactLifecycle {
	t.Helper()
	marker, exists, err := store.loadLifecycleLocked(fileName, nil)
	require.NoError(t, err)
	require.True(t, exists)
	return marker
}
