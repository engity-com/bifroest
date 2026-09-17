package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestRemoteArtifactReceiptV2Golden(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)
	privateKey, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	identity, err := NewIdentity(privateKey)
	require.NoError(t, err)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b810-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("sealed recording\n"))
	fingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("archive destination")))
	targets := &RemoteArtifactTargets{entries: []remoteArtifactTargetEntry{{
		scope: RemoteTargetScope{Auditlog: "security", Target: "archive"}, destinationFingerprint: fingerprint,
	}}}
	_, payload, err := newRemoteArtifactReceipt(identity, "security", artifact, time.Date(2026, 9, 16, 10, 11, 12, 123456789, time.UTC), targets)
	require.NoError(t, err)
	expected := fmt.Sprintf(`{"schema":"bifroest.session-recording-remote-delivery-receipt/v2","producerId":"95b9aca00d322047048950d19cc5aece6fa757edd9104a5521446a168792b298","auditlog":"security","fileName":"6ba7b810-9dad-4d1f-80b4-00c04fd430c8.cast.zst","artifactDigest":"8f378e26270fb650fc2348c00c5eaa5eec5619701fcc9df7a37339c72a94f99e","size":17,"sealedAt":"2026-09-16T10:11:12.123456789Z","targets":[{"target":"archive","destinationFingerprint":"455f66aa923a6e606b41cc026d282910db49378997342add8b68a5fa8406569c"}],"publicKey":"AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4","statePadding":"%s","signature":"USkKoxu1wImQOjga1px9WFsz1IkIXp6ZN4c1hzS0Ab1ehU5UCd6Qq/Xe66Zz+jmeBO5amMjgolYpPqg9uf8gAA=="}`, strings.Repeat("0", remoteArtifactReceiptStateReserveBytes))
	require.Equal(t, expected, string(payload))
}

func TestRemoteArtifactReceiptIsCanonicalSignedAndRetainedAfterAllTargets(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b810-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("sealed recording"))
	firstFingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("first destination")))
	secondFingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("second destination")))
	targets := &RemoteArtifactTargets{entries: []remoteArtifactTargetEntry{
		{scope: RemoteTargetScope{Auditlog: "security", Target: "first"}, destinationFingerprint: firstFingerprint},
		{scope: RemoteTargetScope{Auditlog: "security", Target: "second"}, destinationFingerprint: secondFingerprint},
	}}
	sealedAt := time.Date(2026, 9, 16, 10, 0, 0, 123, time.UTC)
	receipt, payload, err := newRemoteArtifactReceipt(identity, "security", artifact, sealedAt, targets)
	require.NoError(t, err)

	decoded, err := decodeRemoteArtifactReceipt(payload, identity, "security", artifact.FileName())
	require.NoError(t, err)
	require.Equal(t, receipt, decoded)
	require.Equal(t, sealedAt, mustParseRemoteArtifactReceiptTime(t, decoded.SealedAt))
	require.Len(t, decoded.Targets, 2)
	_, ready := decoded.retentionStartedAt()
	require.False(t, ready)

	firstAt := sealedAt.Add(time.Minute)
	decoded, _, changed, err := acknowledgeRemoteArtifactReceipt(identity, decoded, targets.entries[0], firstAt)
	require.NoError(t, err)
	require.True(t, changed)
	decoded, _ = remoteArtifactReceiptTestMarkSuccessAudited(t, identity, decoded, 0, firstAt)
	_, ready = decoded.retentionStartedAt()
	require.False(t, ready)

	secondAt := sealedAt.Add(2 * time.Minute)
	decoded, _, changed, err = acknowledgeRemoteArtifactReceipt(identity, decoded, targets.entries[1], secondAt)
	require.NoError(t, err)
	require.True(t, changed)
	decoded, payload = remoteArtifactReceiptTestMarkSuccessAudited(t, identity, decoded, 1, secondAt)
	retentionStartedAt, ready := decoded.retentionStartedAt()
	require.True(t, ready)
	require.Equal(t, secondAt, retentionStartedAt)

	unchanged, samePayload, changed, err := acknowledgeRemoteArtifactReceipt(identity, decoded, targets.entries[1], secondAt.Add(time.Hour))
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, decoded, unchanged)
	require.JSONEq(t, string(payload), string(samePayload))

	otherFingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("changed destination")))
	_, _, _, err = acknowledgeRemoteArtifactReceipt(identity, decoded, remoteArtifactTargetEntry{
		scope:                  targets.entries[0].scope,
		destinationFingerprint: otherFingerprint,
	}, secondAt)
	require.ErrorContains(t, err, "different destination")

	var tampered remoteArtifactReceipt
	require.NoError(t, json.Unmarshal(payload, &tampered))
	tampered.Size++
	tamperedPayload, err := json.Marshal(tampered)
	require.NoError(t, err)
	_, err = decodeRemoteArtifactReceipt(tamperedPayload, identity, "security", artifact.FileName())
	require.ErrorContains(t, err, "illegal audit signature")
}

func TestRemoteArtifactReceiptWithoutTargetsStartsRetentionAtSeal(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b811-9dad-4d1f-80b4-00c04fd430c8.becast", []byte("encrypted recording"))
	sealedAt := time.Date(2026, 9, 16, 11, 0, 0, 0, time.UTC)
	receipt, _, err := newRemoteArtifactReceipt(identity, "security", artifact, sealedAt, nil)
	require.NoError(t, err)
	retentionStartedAt, ready := receipt.retentionStartedAt()
	require.True(t, ready)
	require.Equal(t, sealedAt, retentionStartedAt)
}

func TestRemoteArtifactReceiptPersistsDeliveryAuditOutboxAcrossRestart(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b821-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("recording"))
	entry := remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("archive"), nil)
	targets := remoteArtifactDeliveryTestTargets(entry)
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	sealedAt := time.Now().UTC().Add(-time.Minute)
	_, err = store.initialize(artifact, sealedAt, targets)
	require.NoError(t, err)

	failed, pending, err := store.beginDeliveryFailure(t.Context(), artifact.FileName(), entry, ErrorCategoryNetwork, sealedAt.Add(time.Second))
	require.NoError(t, err)
	require.True(t, pending)
	require.Equal(t, RemoteArtifactDeliveryAuditFailed, failed.State)
	require.Equal(t, ErrorCategoryNetwork, failed.ErrorCategory)
	require.NotEmpty(t, failed.OperationId)
	status, err := store.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetFailureAuditPending, status)

	require.NoError(t, store.completeDeliveryAudit(t.Context(), failed, sealedAt.Add(2*time.Second)))
	status, err = store.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetPending, status)
	_, pending, err = store.beginDeliveryFailure(t.Context(), artifact.FileName(), entry, ErrorCategorySystem, sealedAt.Add(3*time.Second))
	require.NoError(t, err)
	require.False(t, pending)

	acknowledgedAt := sealedAt.Add(4 * time.Second)
	acknowledged, err := store.acknowledge(t.Context(), artifact, entry, acknowledgedAt)
	require.NoError(t, err)
	_, ready := acknowledged.retentionStartedAt()
	require.False(t, ready)
	status, err = store.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetSuccessAuditPending, status)
	require.NoError(t, store.close())

	restarted, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.close()) })
	succeeded, pending, err := restarted.pendingDeliveryAudit(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.True(t, pending)
	require.Equal(t, RemoteArtifactDeliveryAuditSucceeded, succeeded.State)
	require.Equal(t, failed.OperationId, succeeded.OperationId)
	require.NoError(t, restarted.completeDeliveryAudit(t.Context(), succeeded, acknowledgedAt.Add(time.Second)))
	status, err = restarted.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetAcknowledged, status)
	completed, exists, err := restarted.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	retentionStartedAt, ready := completed.retentionStartedAt()
	require.True(t, ready)
	require.Equal(t, acknowledgedAt, retentionStartedAt)
}

func TestRemoteArtifactReceiptStoreRecoversOnlyMonotonicAcknowledgement(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b812-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("recording"))
	fingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("destination")))
	targets := &RemoteArtifactTargets{entries: []remoteArtifactTargetEntry{{
		scope: RemoteTargetScope{Auditlog: "security", Target: "archive"}, destinationFingerprint: fingerprint,
	}}}
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	sealedAt := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	initial, err := store.initialize(artifact, sealedAt, targets)
	require.NoError(t, err)

	loaded, exists, err := store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, initial, loaded)
	wrongArtifact := artifact
	wrongArtifact.digest[0]++
	_, _, err = store.load(wrongArtifact)
	require.ErrorContains(t, err, "different artifact")

	acknowledgedAt := sealedAt.Add(time.Minute)
	next, payload, changed, err := acknowledgeRemoteArtifactReceipt(identity, initial, targets.entries[0], acknowledgedAt)
	require.NoError(t, err)
	require.True(t, changed)
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, payload))

	require.NoError(t, (&RemoteArtifactReceipts{store: store}).Recover(t.Context()))
	recovered, exists, err := store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, next, recovered)
	require.NoFileExists(t, temporary)

	conflictingContent := recovered.remoteArtifactReceiptContent
	conflictingContent.Targets = append([]remoteArtifactReceiptTarget(nil), recovered.Targets...)
	conflictingContent.Targets[0].AcknowledgedAt = sealedAt.Add(2 * time.Minute).Format(time.RFC3339Nano)
	_, conflictingPayload, err := signRemoteArtifactReceipt(identity, conflictingContent)
	require.NoError(t, err)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, conflictingPayload))
	_, _, err = store.load(artifact)
	require.ErrorContains(t, err, "conflicts with its published receipt")
}

func TestRemoteArtifactReceiptStoreRecoversMonotonicDeliveryAuditState(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b822-9dad-4d1f-80b4-00c04fd430c8.becast", []byte("recording"))
	entry := remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("archive"), nil)
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	sealedAt := time.Now().UTC().Add(-time.Minute)
	initial, err := store.initialize(artifact, sealedAt, remoteArtifactDeliveryTestTargets(entry))
	require.NoError(t, err)

	content := initial.remoteArtifactReceiptContent
	content.Targets = append([]remoteArtifactReceiptTarget(nil), initial.Targets...)
	content.Targets[0].AuditOperationId = "6d05798f-b877-4191-8aa0-4576a30411ad"
	content.Targets[0].FailedAt = sealedAt.Add(time.Second).Format(time.RFC3339Nano)
	content.Targets[0].FailureErrorCategory = ErrorCategoryNetwork
	expected, payload, err := signRemoteArtifactReceipt(identity, content)
	require.NoError(t, err)
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, payload))
	require.NoError(t, (&RemoteArtifactReceipts{store: store}).Recover(t.Context()))
	recovered, exists, err := store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, expected, recovered)
	require.NoFileExists(t, temporary)

	conflicting := recovered.remoteArtifactReceiptContent
	conflicting.Targets = append([]remoteArtifactReceiptTarget(nil), recovered.Targets...)
	conflicting.Targets[0].FailedAt = sealedAt.Add(2 * time.Second).Format(time.RFC3339Nano)
	_, payload, err = signRemoteArtifactReceipt(identity, conflicting)
	require.NoError(t, err)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, payload))
	_, _, err = store.load(artifact)
	require.ErrorContains(t, err, "conflicts with its published receipt")
}

func TestRemoteArtifactReceiptsAcknowledgePersistsTarget(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b816-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("recording"))
	targets := &RemoteArtifactTargets{entries: []remoteArtifactTargetEntry{{
		scope:                  RemoteTargetScope{Auditlog: "security", Target: "archive"},
		destinationFingerprint: remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("destination"))),
	}}}
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", quota)
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: targets}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	sealedAt := time.Date(2026, 9, 16, 12, 30, 0, 0, time.UTC)
	require.NoError(t, receipts.Prepare(context.Background(), artifact, sealedAt))
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	usage, err := remoteArtifactReceiptStateUsage(directory)
	require.NoError(t, err)
	require.Equal(t, uint64(usage), quota.usage)

	acknowledgedAt := sealedAt.Add(time.Minute)
	require.NoError(t, receipts.Acknowledge(context.Background(), artifact, "archive", acknowledgedAt))
	receipt, exists, err := store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, acknowledgedAt.Format(time.RFC3339Nano), receipt.Targets[0].AcknowledgedAt)
	usage, err = remoteArtifactReceiptStateUsage(directory)
	require.NoError(t, err)
	require.Equal(t, uint64(usage), quota.usage)
	require.Equal(t, quota.usage, quota.peak)
	require.ErrorContains(t, receipts.Acknowledge(context.Background(), artifact, "missing", acknowledgedAt), "is not configured")
}

func TestRemoteArtifactReceiptRetentionRequiresEveryAcknowledgementAndRemovesState(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b819-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("recording"))
	targets := &RemoteArtifactTargets{entries: []remoteArtifactTargetEntry{
		{scope: RemoteTargetScope{Auditlog: "security", Target: "first"}, destinationFingerprint: remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("first")))},
		{scope: RemoteTargetScope{Auditlog: "security", Target: "second"}, destinationFingerprint: remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("second")))},
	}}
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", quota)
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: targets}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	sealedAt := time.Date(2026, 9, 16, 14, 0, 0, 0, time.UTC)
	require.NoError(t, receipts.Prepare(t.Context(), artifact, sealedAt))
	require.NoError(t, receipts.Acknowledge(t.Context(), artifact, "first", sealedAt.Add(time.Minute)))
	completeRemoteArtifactReceiptTestSuccess(t, store, artifact.FileName(), targets.entries[0], sealedAt.Add(time.Minute))
	candidates, err := receipts.ListRetentionCandidates(t.Context(), sealedAt.Add(time.Hour))
	require.NoError(t, err)
	require.Empty(t, candidates)

	acknowledgedAt := sealedAt.Add(2 * time.Minute)
	require.NoError(t, receipts.Acknowledge(t.Context(), artifact, "second", acknowledgedAt))
	completeRemoteArtifactReceiptTestSuccess(t, store, artifact.FileName(), targets.entries[1], acknowledgedAt)
	candidates, err = receipts.ListRetentionCandidates(t.Context(), acknowledgedAt.Add(-time.Nanosecond))
	require.NoError(t, err)
	require.Empty(t, candidates)
	candidates, err = receipts.ListRetentionCandidates(t.Context(), acknowledgedAt)
	require.NoError(t, err)
	require.Equal(t, []RemoteArtifactRetentionCandidate{{
		FileName:           artifact.FileName(),
		ArtifactDigest:     artifact.Digest(),
		Size:               artifact.Size(),
		RetentionStartedAt: acknowledgedAt,
	}}, candidates)

	require.Error(t, receipts.RemoveRetentionCandidate(t.Context(), candidates[0], acknowledgedAt.Add(-time.Nanosecond)))
	require.ErrorContains(t, receipts.RemoveRetentionCandidate(t.Context(), candidates[0], acknowledgedAt), "has not started")
	forged := candidates[0]
	forged.DeletionStarted = true
	require.Error(t, receipts.MarkRetentionDeleting(t.Context(), forged, acknowledgedAt.Add(-time.Nanosecond)))
	quota.maximum = quota.usage
	require.NoError(t, receipts.MarkRetentionDeleting(t.Context(), candidates[0], acknowledgedAt))
	candidates, err = receipts.ListRetentionCandidates(t.Context(), acknowledgedAt)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.True(t, candidates[0].DeletionStarted)
	require.NoError(t, receipts.RemoveRetentionCandidate(t.Context(), candidates[0], acknowledgedAt))
	require.Zero(t, quota.usage)
	_, err = os.Stat(filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName())))
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestRemoteArtifactReceiptRetentionWithoutTargetsStartsWhenSealed(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b820-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("recording"))
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	sealedAt := time.Date(2026, 9, 16, 14, 30, 0, 0, time.UTC)
	require.NoError(t, receipts.Prepare(t.Context(), artifact, sealedAt))

	candidates, err := receipts.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, sealedAt, candidates[0].RetentionStartedAt)
}

func TestRemoteArtifactReceiptAuditTransitionsAtStableQuotaLimit(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b818-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("recording"))
	targets := &RemoteArtifactTargets{entries: []remoteArtifactTargetEntry{{
		scope:                  RemoteTargetScope{Auditlog: "security", Target: "archive"},
		destinationFingerprint: remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("destination"))),
	}}}
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", quota)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	sealedAt := time.Date(2026, 9, 16, 12, 45, 0, 0, time.UTC)
	initial, err := store.initialize(artifact, sealedAt, targets)
	require.NoError(t, err)
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	initialUsage, err := remoteArtifactReceiptStateUsage(directory)
	require.NoError(t, err)
	require.Equal(t, quota.usage, uint64(initialUsage))
	quota.maximum = quota.usage

	assertStableUsage := func() {
		t.Helper()
		usage, err := remoteArtifactReceiptStateUsage(directory)
		require.NoError(t, err)
		require.Equal(t, initialUsage, usage)
		require.Equal(t, quota.maximum, quota.usage)
		require.Equal(t, quota.usage, quota.peak)
	}

	failed, pending, err := store.beginDeliveryFailure(t.Context(), artifact.FileName(), targets.entries[0], ErrorCategoryNetwork, sealedAt.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, pending)
	assertStableUsage()
	require.NoError(t, store.completeDeliveryAudit(t.Context(), failed, sealedAt.Add(2*time.Minute)))
	assertStableUsage()

	_, err = store.acknowledge(t.Context(), artifact, targets.entries[0], sealedAt.Add(3*time.Minute))
	require.NoError(t, err)
	assertStableUsage()
	succeeded, pending, err := store.pendingDeliveryAudit(t.Context(), artifact.FileName(), targets.entries[0])
	require.NoError(t, err)
	require.True(t, pending)
	require.Equal(t, RemoteArtifactDeliveryAuditSucceeded, succeeded.State)
	require.NoError(t, store.completeDeliveryAudit(t.Context(), succeeded, sealedAt.Add(4*time.Minute)))
	assertStableUsage()

	completed, exists, err := store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	_, ready := completed.retentionStartedAt()
	require.True(t, ready)
	require.NotEqual(t, initial, completed)
}

func remoteArtifactReceiptTestMarkSuccessAudited(t *testing.T, identity *Identity, receipt remoteArtifactReceipt, index int, auditedAt time.Time) (remoteArtifactReceipt, []byte) {
	t.Helper()
	content := receipt.remoteArtifactReceiptContent
	content.Targets = append([]remoteArtifactReceiptTarget(nil), receipt.Targets...)
	content.Targets[index].SuccessAuditedAt = auditedAt.Format(time.RFC3339Nano)
	updated, payload, err := signRemoteArtifactReceipt(identity, content)
	require.NoError(t, err)
	return updated, payload
}

func completeRemoteArtifactReceiptTestSuccess(t *testing.T, store *remoteArtifactReceiptStore, fileName string, entry remoteArtifactTargetEntry, auditedAt time.Time) {
	t.Helper()
	event, pending, err := store.pendingDeliveryAudit(t.Context(), fileName, entry)
	require.NoError(t, err)
	require.True(t, pending)
	require.Equal(t, RemoteArtifactDeliveryAuditSucceeded, event.State)
	require.NoError(t, store.completeDeliveryAudit(t.Context(), event, auditedAt))
}

func TestRemoteArtifactReceiptsRejectsReceiptBeyondQuota(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b817-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("recording"))
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })

	_, err = store.initialize(artifact, time.Now().UTC(), nil)
	require.ErrorContains(t, err, "quota exceeded")
}

func TestRemoteArtifactReceiptStoreRejectsIncompleteInitialTemporary(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b813-9dad-4d1f-80b4-00c04fd430c8.becast", []byte("recording"))
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	require.NoError(t, ensureJournalDirectory(directory, true))
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, []byte("{")))

	_, _, err = store.load(artifact)
	require.ErrorContains(t, err, "cannot decode remote artifact delivery receipt")
	require.FileExists(t, temporary)
}

func TestRemoteArtifactReceiptRecoveryIgnoresEmptyUnpublishedState(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	state := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName("unpublished.cast.zst"))
	require.NoError(t, ensureJournalDirectory(state, true))

	require.NoError(t, (&RemoteArtifactReceipts{store: store}).Recover(t.Context()))
	require.DirExists(t, state)
}

func TestRemoteArtifactReceiptStateNamesAvoidFilesystemAliases(t *testing.T) {
	lower := remoteArtifactReceiptStateName("recording.cast.zst")
	upper := remoteArtifactReceiptStateName("RECORDING.cast.zst")
	require.NotEqual(t, lower, upper)
	require.Len(t, lower, 64)
	require.True(t, isRemoteArtifactReceiptStateName(lower))
	require.False(t, isRemoteArtifactReceiptStateName("CON"))
	require.False(t, isRemoteArtifactReceiptStateName("."+lower))
}

func TestRemoteArtifactReceiptStoreLockIsExclusive(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	first, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	_, err = newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.ErrorContains(t, err, "already locked")
	require.NoError(t, first.close())
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b815-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("recording"))
	_, err = first.initialize(artifact, time.Now().UTC(), nil)
	require.ErrorContains(t, err, "closed")
	second, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	require.NoError(t, second.close())
}

func TestRemoteArtifactReceiptKeepsSelectionAcrossConfigurationChanges(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b814-9dad-4d1f-80b4-00c04fd430c8.cast.zst", []byte("recording"))
	firstFingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("first")))
	secondFingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("second")))
	originalTargets := &RemoteArtifactTargets{entries: []remoteArtifactTargetEntry{{
		scope: RemoteTargetScope{Auditlog: "security", Target: "first"}, destinationFingerprint: firstFingerprint,
	}}}
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	sealedAt := time.Date(2026, 9, 16, 13, 0, 0, 0, time.UTC)
	original, err := store.initialize(artifact, sealedAt, originalTargets)
	require.NoError(t, err)
	require.NoError(t, store.close())

	changedTargets := &RemoteArtifactTargets{entries: []remoteArtifactTargetEntry{
		{scope: RemoteTargetScope{Auditlog: "security", Target: "second"}, destinationFingerprint: secondFingerprint},
		{scope: RemoteTargetScope{Auditlog: "security", Target: "first"}, destinationFingerprint: firstFingerprint},
	}}
	reopened, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.close()) })
	retained, err := reopened.initialize(artifact, sealedAt.Add(time.Hour), changedTargets)
	require.NoError(t, err)
	require.Equal(t, original, retained)
	require.Len(t, retained.Targets, 1)
	require.Equal(t, configuration.AuditlogTargetName("first"), retained.Targets[0].Target)
}

func newRemoteArtifactReceiptTestArtifact(t *testing.T, producerId ProducerId, fileName string, content []byte) RemoteArtifact {
	t.Helper()
	digest := ArtifactDigest(sha256.Sum256(content))
	artifact, err := NewRemoteArtifact(producerId, fileName, digest, int64(len(content)), bytes.NewReader(content))
	require.NoError(t, err)
	return artifact
}

func mustParseRemoteArtifactReceiptTime(t *testing.T, value string) time.Time {
	t.Helper()
	result, err := parseRemoteArtifactReceiptTime(value)
	require.NoError(t, err)
	return result
}

func writeRemoteArtifactReceiptTestFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	if err != nil {
		return err
	}
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

type remoteArtifactReceiptTestQuota struct {
	maximum uint64
	usage   uint64
	peak    uint64
}

func (this *remoteArtifactReceiptTestQuota) Reserve(bytes uint64) error {
	if bytes > this.maximum-this.usage {
		return fmt.Errorf("quota exceeded")
	}
	this.usage += bytes
	this.peak = max(this.peak, this.usage)
	return nil
}

func (this *remoteArtifactReceiptTestQuota) Reconcile(reserved uint64, before, after int64) error {
	if after >= before {
		this.usage -= reserved - uint64(after-before)
	} else {
		this.usage -= reserved + uint64(before-after)
	}
	return nil
}
