package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestRemoteArtifactReceiptV2Golden(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)
	privateKey, err := bfcrypto.PrivateKeyFromSdk(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	identity, err := NewIdentity(privateKey)
	require.NoError(t, err)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b810-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("sealed recording\n"))
	fingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("archive destination")))
	targets := &RemoteArtifactTargets{entries: []remoteArtifactTargetEntry{{
		scope: RemoteTargetScope{Auditlog: "security", Target: "archive"}, destinationFingerprint: fingerprint,
	}}}
	_, payload, err := newRemoteArtifactReceipt(identity, "security", artifact, time.Date(2026, 9, 16, 10, 11, 12, 123456789, time.UTC), targets)
	require.NoError(t, err)
	expected := fmt.Sprintf(`{"schema":"bifroest.session-recording-remote-delivery-receipt/v2","producerId":"95b9aca00d322047048950d19cc5aece6fa757edd9104a5521446a168792b298","auditlog":"security","fileName":"6ba7b810-9dad-4d1f-80b4-00c04fd430c8.bcast","artifactDigest":"8f378e26270fb650fc2348c00c5eaa5eec5619701fcc9df7a37339c72a94f99e","size":17,"sealedAt":"2026-09-16T10:11:12.123456789Z","targets":[{"target":"archive","destinationFingerprint":"455f66aa923a6e606b41cc026d282910db49378997342add8b68a5fa8406569c"}],"publicKey":"AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4","statePadding":"%s","signature":"YpZyd/aIH+JwnV4Oqc6Qwku2aAVF7+wUZ3XEk9w/rmpQhVO9cBnpJO85PfutW+vZbDbCjfj9Jg25JrSiJbB6CQ=="}`, strings.Repeat("0", remoteArtifactReceiptStateReserveBytes))
	require.Equal(t, expected, string(payload))
}

func TestRemoteArtifactReceiptIsCanonicalSignedAndRetainedAfterAllTargets(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b810-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("sealed recording"))
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
	decoded, _, changed, err := acknowledgeRemoteArtifactReceipt(identity, decoded, targets.entries[0], firstAt, uuid.NewRandom)
	require.NoError(t, err)
	require.True(t, changed)
	decoded, _ = remoteArtifactReceiptTestMarkSuccessAudited(t, identity, decoded, 0, firstAt)
	_, ready = decoded.retentionStartedAt()
	require.False(t, ready)

	secondAt := sealedAt.Add(2 * time.Minute)
	decoded, _, changed, err = acknowledgeRemoteArtifactReceipt(identity, decoded, targets.entries[1], secondAt, uuid.NewRandom)
	require.NoError(t, err)
	require.True(t, changed)
	decoded, payload = remoteArtifactReceiptTestMarkSuccessAudited(t, identity, decoded, 1, secondAt)
	retentionStartedAt, ready := decoded.retentionStartedAt()
	require.True(t, ready)
	require.Equal(t, secondAt, retentionStartedAt)

	unchanged, samePayload, changed, err := acknowledgeRemoteArtifactReceipt(identity, decoded, targets.entries[1], secondAt.Add(time.Hour), uuid.NewRandom)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, decoded, unchanged)
	require.JSONEq(t, string(payload), string(samePayload))

	otherFingerprint := remoteDeliveryDestinationFingerprint(sha256.Sum256([]byte("changed destination")))
	_, _, _, err = acknowledgeRemoteArtifactReceipt(identity, decoded, remoteArtifactTargetEntry{
		scope:                  targets.entries[0].scope,
		destinationFingerprint: otherFingerprint,
	}, secondAt, uuid.NewRandom)
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

func TestRemoteArtifactReceiptUnauditedWithoutTargetsSurvivesRestartAndRetention(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b850-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("unaudited recording"))
	sealedAt := time.Now().UTC().Add(-time.Minute)
	receipts, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
	require.NoError(t, err)
	require.NoError(t, receipts.PrepareLifecycle(t.Context(), artifact, sealedAt, strings.Repeat("a", 64), false))
	require.NoError(t, receipts.Require(t.Context(), artifact))
	directory := filepath.Join(receipts.store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	require.NoFileExists(t, filepath.Join(directory, remoteArtifactLifecycleFileName))
	loaded, exists, err := receipts.store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	require.True(t, loaded.Unaudited)
	require.Empty(t, loaded.Targets)
	require.NoError(t, receipts.PromoteLifecycle(t.Context(), artifact))
	require.Empty(t, mustPendingRemoteArtifactLifecycle(t, receipts))
	require.NoError(t, receipts.Close())

	restarted, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	require.NoError(t, restarted.Recover(t.Context()))
	signed, err := restarted.ListSigned(t.Context())
	require.NoError(t, err)
	require.Equal(t, []RemoteArtifactSignedReceipt{{FileName: artifact.FileName()}}, signed)
	candidates, err := restarted.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, sealedAt, candidates[0].RetentionStartedAt)
	require.Empty(t, candidates[0].AuditOperationId)
	require.NoError(t, restarted.MarkRetentionDeleting(t.Context(), candidates[0], sealedAt))
	signed, err = restarted.ListSigned(t.Context())
	require.NoError(t, err)
	require.True(t, signed[0].RetentionDeletionStarted)
	candidates, err = restarted.ListRetentionCandidates(t.Context(), time.Time{})
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	completed, err := restarted.MarkRetentionCompleted(t.Context(), candidates[0], time.Time{})
	require.NoError(t, err)
	require.Empty(t, completed.AuditOperationId)
	require.NoError(t, restarted.RemoveRetentionCandidate(t.Context(), completed, time.Time{}))
	require.NoDirExists(t, directory)
}

func TestRemoteArtifactReceiptUnauditedAckAndTemporaryRecovery(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	entry := remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("archive"), nil)
	targets := remoteArtifactDeliveryTestTargets(entry)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b851-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("ack recovery"))
	sealedAt := time.Now().UTC().Add(-time.Minute)
	receipts, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", targets, quota)
	require.NoError(t, err)
	require.NoError(t, receipts.Prepare(t.Context(), artifact, sealedAt))
	initial, exists, err := receipts.store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	_, ready := initial.retentionStartedAt()
	require.False(t, ready)
	ackAt := sealedAt.Add(time.Second)
	updated, payload, changed, err := acknowledgeRemoteArtifactReceipt(identity, initial, entry, ackAt, func() (uuid.UUID, error) {
		return uuid.Nil, fmt.Errorf("UUID generator must not be used without audit")
	})
	require.NoError(t, err)
	require.True(t, changed)
	require.Empty(t, updated.Targets[0].AuditOperationId)
	require.Empty(t, updated.Targets[0].SuccessAuditedAt)
	directory := filepath.Join(receipts.store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, payload))
	usage, err := remoteArtifactReceiptStateUsage(directory)
	require.NoError(t, err)
	quota.usage = uint64(usage)
	require.NoError(t, receipts.Close())

	restarted, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", targets, quota)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	require.NoError(t, restarted.Recover(t.Context()))
	require.NoFileExists(t, temporary)
	status, err := restarted.store.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetAcknowledged, status)
	candidates, err := restarted.ListRetentionCandidates(t.Context(), ackAt)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, ackAt, candidates[0].RetentionStartedAt)
}

func TestRemoteArtifactReceiptUnauditedRestartCleansTornTemporary(t *testing.T) {
	for _, published := range []bool{true, false} {
		t.Run(fmt.Sprintf("published=%t", published), func(t *testing.T) {
			_, identity := newJournalTestIdentity(t)
			root := t.TempDir()
			quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b85b-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("surviving crash"))
			receipts, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			require.NoError(t, err)
			if published {
				require.NoError(t, receipts.Prepare(t.Context(), artifact, time.Now().UTC().Add(-time.Minute)))
			}
			directory := filepath.Join(receipts.store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
			if !published {
				require.NoError(t, ensureRemoteArtifactReceiptDirectory(directory))
			}
			publishedPath := filepath.Join(directory, remoteArtifactReceiptFileName)
			var original []byte
			if published {
				original, err = os.ReadFile(publishedPath)
				require.NoError(t, err)
			}
			temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
			require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, []byte(`{"schema":`)))
			usage, err := remoteArtifactReceiptStateUsage(directory)
			require.NoError(t, err)
			quota.usage = uint64(usage)
			require.NoError(t, receipts.Close())

			restarted, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			require.NoError(t, err)
			require.NoError(t, restarted.Recover(t.Context()))
			require.NoFileExists(t, temporary)
			if published {
				actual, err := os.ReadFile(publishedPath)
				require.NoError(t, err)
				require.Equal(t, original, actual)
			}
			if published {
				require.NoError(t, restarted.Require(t.Context(), artifact))
			} else {
				require.NoDirExists(t, directory)
			}
			require.NoError(t, restarted.Close())
			reopened, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, reopened.Close()) })
			require.NoError(t, reopened.Recover(t.Context()))
		})
	}
}

func TestRemoteArtifactReceiptUnauditedRestartRejectsSignedAuditedTemporary(t *testing.T) {
	for _, published := range []bool{true, false} {
		t.Run(fmt.Sprintf("published=%t", published), func(t *testing.T) {
			_, identity := newJournalTestIdentity(t)
			root := t.TempDir()
			quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b85c-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("opposite mode"))
			receipts, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			require.NoError(t, err)
			if published {
				require.NoError(t, receipts.Prepare(t.Context(), artifact, time.Now().UTC()))
			}
			directory := filepath.Join(receipts.store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
			if !published {
				require.NoError(t, ensureRemoteArtifactReceiptDirectory(directory))
			}
			publishedPath := filepath.Join(directory, remoteArtifactReceiptFileName)
			var original []byte
			if published {
				original, err = os.ReadFile(publishedPath)
				require.NoError(t, err)
			}
			_, auditedPayload, err := newRemoteArtifactReceipt(identity, "security", artifact, time.Now().UTC(), nil)
			require.NoError(t, err)
			temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
			require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, auditedPayload))
			require.NoError(t, receipts.Close())
			_, err = NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			require.ErrorContains(t, err, "mode")
			require.FileExists(t, temporary)
			if published {
				actual, err := os.ReadFile(publishedPath)
				require.NoError(t, err)
				require.Equal(t, original, actual)
			}
		})
	}
}

func TestRemoteArtifactReceiptUnauditedRestartRejectsUnreadableTemporary(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b85e-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("unreadable temp"))
	receipts, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
	require.NoError(t, err)
	require.NoError(t, receipts.Prepare(t.Context(), artifact, time.Now().UTC()))
	directory := filepath.Join(receipts.store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	require.NoError(t, os.Mkdir(temporary, journalDirectoryMode))
	require.NoError(t, receipts.Close())
	_, err = NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
	require.ErrorContains(t, err, "not a regular file")
	require.DirExists(t, temporary)
	require.FileExists(t, filepath.Join(directory, remoteArtifactReceiptFileName))
}

func TestRemoteArtifactReceiptUnauditedRestartRejectsCorruptPublishedReceipt(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b85d-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("published corruption"))
	receipts, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
	require.NoError(t, err)
	require.NoError(t, receipts.Prepare(t.Context(), artifact, time.Now().UTC()))
	path := filepath.Join(receipts.store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()), remoteArtifactReceiptFileName)
	payload, err := os.ReadFile(path)
	require.NoError(t, err)
	var corrupted remoteArtifactReceipt
	require.NoError(t, json.Unmarshal(payload, &corrupted))
	corrupted.Signature[0] ^= 1
	payload, err = json.Marshal(corrupted)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, payload, journalFileMode))
	require.NoError(t, receipts.Close())
	_, err = NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
	require.ErrorContains(t, err, "cannot verify")
	actual, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, payload, actual)
}

func TestRemoteArtifactReceiptRejectsModeSwitchWithState(t *testing.T) {
	for _, unaudited := range []bool{false, true} {
		t.Run(fmt.Sprintf("unaudited=%t", unaudited), func(t *testing.T) {
			_, identity := newJournalTestIdentity(t)
			root := t.TempDir()
			quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b852-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("mode switch"))
			var receipts *RemoteArtifactReceipts
			var err error
			if unaudited {
				receipts, err = NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			} else {
				receipts, err = NewRemoteArtifactReceipts(root, identity, "security", nil, quota)
			}
			require.NoError(t, err)
			require.NoError(t, receipts.Prepare(t.Context(), artifact, time.Now().UTC()))
			require.NoError(t, receipts.Close())
			if unaudited {
				_, err = NewRemoteArtifactReceipts(root, identity, "security", nil, quota)
			} else {
				_, err = NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			}
			require.ErrorContains(t, err, "mode")
		})
	}
}

func TestRemoteArtifactReceiptUnauditedRecoveryRejectsTamperedModeAndHistoricalReceipt(t *testing.T) {
	for _, state := range []string{remoteArtifactReceiptFileName, remoteArtifactReceiptRetentionFileName, remoteArtifactReceiptCompletedFileName} {
		t.Run(state, func(t *testing.T) {
			_, identity := newJournalTestIdentity(t)
			root := t.TempDir()
			quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b856-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("historical mode"))
			sealedAt := time.Now().UTC().Add(-time.Minute)
			receipts, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			require.NoError(t, err)
			require.NoError(t, receipts.Prepare(t.Context(), artifact, sealedAt))
			if state != remoteArtifactReceiptFileName {
				candidates, err := receipts.ListRetentionCandidates(t.Context(), sealedAt)
				require.NoError(t, err)
				require.Len(t, candidates, 1)
				require.NoError(t, receipts.MarkRetentionDeleting(t.Context(), candidates[0], sealedAt))
				if state == remoteArtifactReceiptCompletedFileName {
					candidates, err = receipts.ListRetentionCandidates(t.Context(), sealedAt)
					require.NoError(t, err)
					_, err = receipts.MarkRetentionCompleted(t.Context(), candidates[0], sealedAt)
					require.NoError(t, err)
				}
			}
			directory := filepath.Join(receipts.store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
			path := filepath.Join(directory, state)
			payload, err := os.ReadFile(path)
			require.NoError(t, err)
			var forged remoteArtifactReceipt
			require.NoError(t, json.Unmarshal(payload, &forged))
			forged.Unaudited = false
			payload, err = json.Marshal(forged)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, payload, journalFileMode))
			require.ErrorContains(t, receipts.Recover(t.Context()), "cannot verify")
			require.NoError(t, receipts.Close())
			_, err = NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			require.ErrorContains(t, err, "mode")
		})
	}
}

func TestRemoteArtifactReceiptRejectsModeSwitchWithHistoricalReceipt(t *testing.T) {
	for _, state := range []string{remoteArtifactReceiptRetentionFileName, remoteArtifactReceiptCompletedFileName} {
		t.Run(state, func(t *testing.T) {
			_, identity := newJournalTestIdentity(t)
			root := t.TempDir()
			quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b85a-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("retained mode"))
			sealedAt := time.Now().UTC().Add(-time.Minute)
			receipts, err := NewRemoteArtifactReceiptsWithoutAudit(root, identity, "security", nil, quota)
			require.NoError(t, err)
			require.NoError(t, receipts.Prepare(t.Context(), artifact, sealedAt))
			candidates, err := receipts.ListRetentionCandidates(t.Context(), sealedAt)
			require.NoError(t, err)
			require.Len(t, candidates, 1)
			require.NoError(t, receipts.MarkRetentionDeleting(t.Context(), candidates[0], sealedAt))
			if state == remoteArtifactReceiptCompletedFileName {
				candidates, err = receipts.ListRetentionCandidates(t.Context(), sealedAt)
				require.NoError(t, err)
				_, err = receipts.MarkRetentionCompleted(t.Context(), candidates[0], sealedAt)
				require.NoError(t, err)
			}
			require.NoError(t, receipts.Close())
			_, err = NewRemoteArtifactReceipts(root, identity, "security", nil, quota)
			require.ErrorContains(t, err, "mode")
		})
	}
}

func TestRemoteArtifactReceiptUnauditedRejectsAuditStateEvenWhenSigned(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b857-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("no fabricated audit"))
	entry := remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("archive"), nil)
	targets := remoteArtifactDeliveryTestTargets(entry)
	receipt, _, err := newRemoteArtifactReceipt(identity, "security", artifact, time.Now().UTC(), targets, true)
	require.NoError(t, err)
	content := receipt.remoteArtifactReceiptContent
	content.Targets = append([]remoteArtifactReceiptTarget(nil), content.Targets...)
	content.Targets[0].AuditOperationId = uuid.NewString()
	_, _, err = signRemoteArtifactReceipt(identity, content)
	require.ErrorContains(t, err, "contains audit state")
}

func TestRemoteArtifactReceiptUnauditedEnforcesQuota(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	receipts, err := NewRemoteArtifactReceiptsWithoutAudit(t.TempDir(), identity, "security", nil, &remoteArtifactReceiptTestQuota{maximum: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b858-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("quota"))
	require.Error(t, receipts.PrepareLifecycle(t.Context(), artifact, time.Now().UTC(), "", false))
	_, exists, err := receipts.store.load(artifact)
	require.NoError(t, err)
	require.False(t, exists)
}

func TestRemoteArtifactReceiptPersistsDeliveryAuditOutboxAcrossRestart(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b821-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
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

func TestRemoteArtifactReceiptPropagatesAuditOperationIdGenerationFailures(t *testing.T) {
	for _, operation := range []string{"acknowledge", "failure"} {
		t.Run(operation, func(t *testing.T) {
			_, identity := newJournalTestIdentity(t)
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b824-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
			entry := remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("archive"), nil)
			store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, store.close()) })
			sealedAt := time.Now().UTC().Add(-time.Minute)
			initial, err := store.initialize(artifact, sealedAt, remoteArtifactDeliveryTestTargets(entry))
			require.NoError(t, err)
			injected := fmt.Errorf("injected UUID generation failure")
			store.newUUID = func() (uuid.UUID, error) { return uuid.Nil, injected }

			if operation == "acknowledge" {
				_, err = store.acknowledge(t.Context(), artifact, entry, sealedAt.Add(time.Second))
			} else {
				var pending bool
				_, pending, err = store.beginDeliveryFailure(t.Context(), artifact.FileName(), entry, ErrorCategoryNetwork, sealedAt.Add(time.Second))
				require.False(t, pending)
			}
			require.ErrorIs(t, err, injected)
			require.True(t, bferrors.System.IsErr(err))
			require.ErrorContains(t, err, "cannot generate remote artifact delivery audit operation ID")
			unchanged, exists, loadErr := store.load(artifact)
			require.NoError(t, loadErr)
			require.True(t, exists)
			require.Equal(t, initial, unchanged)

			store.newUUID = uuid.NewRandom
			if operation == "acknowledge" {
				updated, retryErr := store.acknowledge(t.Context(), artifact, entry, sealedAt.Add(time.Second))
				require.NoError(t, retryErr)
				require.NotEmpty(t, updated.Targets[0].AcknowledgedAt)
				require.NotEmpty(t, updated.Targets[0].AuditOperationId)
			} else {
				event, pending, retryErr := store.beginDeliveryFailure(t.Context(), artifact.FileName(), entry, ErrorCategoryNetwork, sealedAt.Add(time.Second))
				require.NoError(t, retryErr)
				require.True(t, pending)
				require.Equal(t, RemoteArtifactDeliveryAuditFailed, event.State)
				require.NotEmpty(t, event.OperationId)
			}
		})
	}
}

func TestRemoteArtifactReceiptStoreRecoversOnlyMonotonicAcknowledgement(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b812-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
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
	next, payload, changed, err := acknowledgeRemoteArtifactReceipt(identity, initial, targets.entries[0], acknowledgedAt, uuid.NewRandom)
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
	targets := remoteArtifactDeliveryTestTargets(entry)
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", quota)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	sealedAt := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	initial, payload, err := newRemoteArtifactReceipt(identity, "security", artifact, sealedAt, targets)
	require.NoError(t, err)
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	target := filepath.Join(directory, remoteArtifactReceiptFileName)
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	require.NoFileExists(t, target)
	initial = recoverRemoteArtifactReceiptTestTemporary(t, store, artifact, initial, payload)
	status, err := store.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetPending, status)

	content := initial.remoteArtifactReceiptContent
	content.Targets = append([]remoteArtifactReceiptTarget(nil), initial.Targets...)
	operationId := "6d05798f-b877-4191-8aa0-4576a30411ad"
	failedAt := sealedAt.Add(time.Second)
	content.Targets[0].AuditOperationId = operationId
	content.Targets[0].FailedAt = failedAt.Format(time.RFC3339Nano)
	content.Targets[0].FailureErrorCategory = ErrorCategoryNetwork
	failurePending, payload, err := signRemoteArtifactReceipt(identity, content)
	require.NoError(t, err)
	failurePending = recoverRemoteArtifactReceiptTestTemporary(t, store, artifact, failurePending, payload)
	status, err = store.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetFailureAuditPending, status)
	failed, pending, err := store.pendingDeliveryAudit(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.True(t, pending)
	require.Equal(t, RemoteArtifactDeliveryAuditFailed, failed.State)
	require.Equal(t, operationId, failed.OperationId)
	require.Equal(t, ErrorCategoryNetwork, failed.ErrorCategory)

	content = failurePending.remoteArtifactReceiptContent
	content.Targets = append([]remoteArtifactReceiptTarget(nil), failurePending.Targets...)
	failureAuditedAt := sealedAt.Add(2 * time.Second)
	content.Targets[0].FailureAuditedAt = failureAuditedAt.Format(time.RFC3339Nano)
	failureCompleted, payload, err := signRemoteArtifactReceipt(identity, content)
	require.NoError(t, err)
	failureCompleted = recoverRemoteArtifactReceiptTestTemporary(t, store, artifact, failureCompleted, payload)
	require.Equal(t, operationId, failureCompleted.Targets[0].AuditOperationId)
	require.Equal(t, failedAt.Format(time.RFC3339Nano), failureCompleted.Targets[0].FailedAt)
	require.Equal(t, ErrorCategoryNetwork, failureCompleted.Targets[0].FailureErrorCategory)
	require.Equal(t, failureAuditedAt.Format(time.RFC3339Nano), failureCompleted.Targets[0].FailureAuditedAt)
	status, err = store.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetPending, status)
	_, pending, err = store.pendingDeliveryAudit(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.False(t, pending)

	acknowledgedAt := sealedAt.Add(3 * time.Second)
	successPending, payload, changed, err := acknowledgeRemoteArtifactReceipt(identity, failureCompleted, entry, acknowledgedAt, uuid.NewRandom)
	require.NoError(t, err)
	require.True(t, changed)
	successPending = recoverRemoteArtifactReceiptTestTemporary(t, store, artifact, successPending, payload)
	require.Equal(t, operationId, successPending.Targets[0].AuditOperationId)
	require.Equal(t, failureCompleted.Targets[0].FailedAt, successPending.Targets[0].FailedAt)
	require.Equal(t, failureCompleted.Targets[0].FailureAuditedAt, successPending.Targets[0].FailureAuditedAt)
	require.Equal(t, acknowledgedAt.Format(time.RFC3339Nano), successPending.Targets[0].AcknowledgedAt)
	require.Empty(t, successPending.Targets[0].SuccessAuditedAt)
	status, err = store.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetSuccessAuditPending, status)
	succeeded, pending, err := store.pendingDeliveryAudit(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.True(t, pending)
	require.Equal(t, RemoteArtifactDeliveryAuditSucceeded, succeeded.State)
	require.Equal(t, operationId, succeeded.OperationId)

	successAuditedAt := sealedAt.Add(4 * time.Second)
	successCompleted, successPayload := remoteArtifactReceiptTestMarkSuccessAudited(t, identity, successPending, 0, successAuditedAt)
	successCompleted = recoverRemoteArtifactReceiptTestTemporary(t, store, artifact, successCompleted, successPayload)
	status, err = store.targetStatus(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.Equal(t, remoteArtifactReceiptTargetAcknowledged, status)
	_, pending, err = store.pendingDeliveryAudit(t.Context(), artifact.FileName(), entry)
	require.NoError(t, err)
	require.False(t, pending)
	retentionStartedAt, ready := successCompleted.retentionStartedAt()
	require.True(t, ready)
	require.Equal(t, acknowledgedAt, retentionStartedAt)

	conflicting := successCompleted.remoteArtifactReceiptContent
	conflicting.Targets = append([]remoteArtifactReceiptTarget(nil), successCompleted.Targets...)
	conflicting.Targets[0].FailureErrorCategory = ErrorCategorySystem
	_, conflictingPayload, err := signRemoteArtifactReceipt(identity, conflicting)
	require.NoError(t, err)
	targetInfo, err := os.Lstat(target)
	require.NoError(t, err)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, conflictingPayload))
	_, _, err = store.load(artifact)
	require.ErrorContains(t, err, "conflicts with its published receipt")
	require.Equal(t, successPayload, remoteArtifactReceiptTestReadFile(t, target))
	afterTargetInfo, statErr := os.Lstat(target)
	require.NoError(t, statErr)
	require.True(t, os.SameFile(targetInfo, afterTargetInfo))
	require.Equal(t, conflictingPayload, remoteArtifactReceiptTestReadFile(t, temporary))
}

func TestRemoteArtifactReceiptStoreRecoversRetentionTemporary(t *testing.T) {
	for _, test := range []struct {
		name      string
		published bool
		conflict  bool
	}{
		{name: "temporary only"},
		{name: "identical published", published: true},
		{name: "conflicting published", published: true, conflict: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, identity := newJournalTestIdentity(t)
			root := t.TempDir()
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b823-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
			sealedAt := time.Date(2026, 9, 16, 13, 0, 0, 0, time.UTC)
			receipt, payload, err := newRemoteArtifactReceipt(identity, "security", artifact, sealedAt, nil)
			require.NoError(t, err)
			quota := &remoteArtifactReceiptTestQuota{maximum: uint64(len(payload))}
			store, err := newRemoteArtifactReceiptStore(root, identity, "security", quota)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, store.close()) })
			receipts := &RemoteArtifactReceipts{store: store}
			directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
			require.NoError(t, ensureJournalDirectory(directory, true))
			publishedPath := filepath.Join(directory, remoteArtifactReceiptRetentionFileName)
			temporaryPath := filepath.Join(directory, remoteArtifactReceiptRetentionTempName)
			if test.published {
				require.NoError(t, writeRemoteArtifactReceiptTestFile(publishedPath, payload))
			}
			temporaryPayload := payload
			if test.conflict {
				content := receipt.remoteArtifactReceiptContent
				content.SealedAt = sealedAt.Add(time.Second).Format(time.RFC3339Nano)
				_, temporaryPayload, err = signRemoteArtifactReceipt(identity, content)
				require.NoError(t, err)
			}
			require.NoError(t, writeRemoteArtifactReceiptTestFile(temporaryPath, temporaryPayload))
			before, err := remoteArtifactReceiptStateUsage(directory)
			require.NoError(t, err)
			quota.usage = uint64(before)
			quota.peak = quota.usage
			temporaryInfo, err := func() (os.FileInfo, error) {
				temporaryFile, openErr := os.Open(temporaryPath)
				if openErr != nil {
					return nil, openErr
				}
				info, statErr := temporaryFile.Stat()
				if closeErr := temporaryFile.Close(); statErr == nil {
					statErr = closeErr
				}
				return info, statErr
			}()
			require.NoError(t, err)
			var publishedInfo os.FileInfo
			if test.published {
				publishedInfo, err = os.Lstat(publishedPath)
				require.NoError(t, err)
			}
			requireConflictUnchanged := func() {
				require.Equal(t, payload, remoteArtifactReceiptTestReadFile(t, publishedPath))
				afterPublishedInfo, statErr := os.Lstat(publishedPath)
				require.NoError(t, statErr)
				require.True(t, os.SameFile(publishedInfo, afterPublishedInfo))
				require.Equal(t, temporaryPayload, remoteArtifactReceiptTestReadFile(t, temporaryPath))
				afterTemporaryInfo, statErr := os.Lstat(temporaryPath)
				require.NoError(t, statErr)
				require.True(t, os.SameFile(temporaryInfo, afterTemporaryInfo))
				after, usageErr := remoteArtifactReceiptStateUsage(directory)
				require.NoError(t, usageErr)
				require.Equal(t, before, after)
				require.Equal(t, uint64(before), quota.usage)
				require.Equal(t, uint64(before), quota.peak)
			}

			recoverErr := receipts.Recover(t.Context())
			if test.conflict {
				require.ErrorContains(t, recoverErr, "conflicts with its published receipt")
				requireConflictUnchanged()
				_, candidateErr := receipts.ListRetentionCandidates(t.Context(), sealedAt)
				require.ErrorContains(t, candidateErr, "conflicts with its published receipt")
				requireConflictUnchanged()
				return
			}

			require.NoError(t, recoverErr)
			require.NoFileExists(t, temporaryPath)
			require.Equal(t, payload, remoteArtifactReceiptTestReadFile(t, publishedPath))
			afterPublishedInfo, err := os.Lstat(publishedPath)
			require.NoError(t, err)
			if test.published {
				require.True(t, os.SameFile(publishedInfo, afterPublishedInfo))
			} else {
				require.True(t, os.SameFile(temporaryInfo, afterPublishedInfo))
			}
			after, err := remoteArtifactReceiptStateUsage(directory)
			require.NoError(t, err)
			require.Equal(t, uint64(after), quota.usage)
			candidates, err := receipts.ListRetentionCandidates(t.Context(), sealedAt)
			require.NoError(t, err)
			require.Equal(t, []RemoteArtifactRetentionCandidate{{
				FileName:           artifact.FileName(),
				ArtifactDigest:     artifact.Digest(),
				Size:               artifact.Size(),
				RetentionStartedAt: sealedAt,
				DeletionStarted:    true,
				AuditOperationId:   remoteArtifactRetentionOperationId(receipt),
			}}, candidates)
			require.Equal(t, uint64(before), quota.peak)
		})
	}
}

func TestRemoteArtifactReceiptsAcknowledgePersistsTarget(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b816-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
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
	require.Equal(t, quota.usage*2, quota.peak)
	require.ErrorContains(t, receipts.Acknowledge(context.Background(), artifact, "missing", acknowledgedAt), "is not configured")
}

func TestRemoteArtifactReceiptRetentionRequiresEveryAcknowledgementAndRemovesState(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b819-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
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
	receipt, exists, err := store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, []RemoteArtifactRetentionCandidate{{
		FileName:           artifact.FileName(),
		ArtifactDigest:     artifact.Digest(),
		Size:               artifact.Size(),
		RetentionStartedAt: acknowledgedAt,
		AuditOperationId:   remoteArtifactRetentionOperationId(receipt),
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
	operationId := candidates[0].AuditOperationId
	usageBeforeCompletion := quota.usage
	completed, err := receipts.MarkRetentionCompleted(t.Context(), candidates[0], acknowledgedAt)
	require.NoError(t, err)
	require.True(t, completed.CompletionPending)
	require.Equal(t, operationId, completed.AuditOperationId)
	require.Equal(t, usageBeforeCompletion, quota.usage)
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	require.NoFileExists(t, filepath.Join(directory, remoteArtifactReceiptRetentionFileName))
	require.FileExists(t, filepath.Join(directory, remoteArtifactReceiptCompletedFileName))
	candidates, err = receipts.ListRetentionCandidates(t.Context(), acknowledgedAt)
	require.NoError(t, err)
	require.Equal(t, []RemoteArtifactRetentionCandidate{completed}, candidates)
	require.NoError(t, receipts.RemoveRetentionCandidate(t.Context(), candidates[0], acknowledgedAt))
	require.Zero(t, quota.usage)
	_, err = os.Stat(directory)
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestRemoteArtifactRetentionCompletionSurvivesRestart(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b823-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
	sealedAt := time.Date(2026, 9, 16, 15, 0, 0, 0, time.UTC)
	store, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	require.NoError(t, receipts.Prepare(t.Context(), artifact, sealedAt))
	candidates, err := receipts.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.NoError(t, receipts.MarkRetentionDeleting(t.Context(), candidates[0], sealedAt))
	candidates, err = receipts.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	completed, err := receipts.MarkRetentionCompleted(t.Context(), candidates[0], sealedAt)
	require.NoError(t, err)
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	require.NoError(t, receipts.Close())

	restartedStore, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	restarted := &RemoteArtifactReceipts{store: restartedStore, targets: &RemoteArtifactTargets{}}
	t.Cleanup(func() { require.NoError(t, restarted.Close()) })
	require.NoError(t, restarted.Recover(t.Context()))
	candidates, err = restarted.ListRetentionCandidates(t.Context(), time.Time{})
	require.NoError(t, err)
	require.Equal(t, []RemoteArtifactRetentionCandidate{completed}, candidates)
	require.NoError(t, restarted.RemoveRetentionCandidate(t.Context(), candidates[0], time.Time{}))
	require.NoDirExists(t, directory)
}

func TestRemoteArtifactReceiptRetentionWithoutTargetsStartsWhenSealed(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b820-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
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

func TestRemoteArtifactReceiptsListSignedRequiresDurableRetentionMarker(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b825-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
	sealedAt := time.Now().UTC().Add(-time.Minute)
	require.NoError(t, receipts.Prepare(t.Context(), artifact, sealedAt))
	want := []RemoteArtifactSignedReceipt{{FileName: artifact.FileName()}}
	listed, err := receipts.ListSigned(t.Context())
	require.NoError(t, err)
	require.Equal(t, want, listed) // No targets makes retention eligible, not started.

	candidates, err := receipts.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.NoError(t, receipts.MarkRetentionDeleting(t.Context(), candidates[0], sealedAt))
	want[0].RetentionDeletionStarted = true
	listed, err = receipts.ListSigned(t.Context())
	require.NoError(t, err)
	require.Equal(t, want, listed)
	candidates, err = receipts.ListRetentionCandidates(t.Context(), sealedAt)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	_, err = receipts.MarkRetentionCompleted(t.Context(), candidates[0], sealedAt)
	require.NoError(t, err)
	listed, err = receipts.ListSigned(t.Context())
	require.NoError(t, err)
	require.Equal(t, want, listed)
}

func TestRemoteArtifactReceiptsListSignedDoesNotTreatAcknowledgementAsDeletion(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
	require.NoError(t, err)
	targets := remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("archive"), nil))
	receipts := &RemoteArtifactReceipts{store: store, targets: targets}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b827-9dad-4d1f-80b4-00c04fd430c8.becast", []byte("recording"))
	sealedAt := time.Now().UTC().Add(-time.Minute)
	require.NoError(t, receipts.Prepare(t.Context(), artifact, sealedAt))
	require.NoError(t, receipts.Acknowledge(t.Context(), artifact, "archive", sealedAt.Add(time.Second)))
	listed, err := receipts.ListSigned(t.Context())
	require.NoError(t, err)
	require.Equal(t, []RemoteArtifactSignedReceipt{{FileName: artifact.FileName()}}, listed)
}

func TestRemoteArtifactReceiptsListSignedRejectsMissingReceipt(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
	require.NoError(t, err)
	receipts := &RemoteArtifactReceipts{store: store, targets: &RemoteArtifactTargets{}}
	t.Cleanup(func() { require.NoError(t, receipts.Close()) })
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b826-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
	started := remoteArtifactLifecycleTestStartedEvent(artifact.FileName())
	sealing := time.Now().UTC()
	require.NoError(t, receipts.BeginLifecycle(t.Context(), artifact.FileName(), sealing, started))
	require.NoError(t, receipts.StageLifecycle(t.Context(), artifact.FileName(), remoteArtifactLifecycleTestCompletedEvent(started)))
	require.NoError(t, receipts.PrepareLifecycle(t.Context(), artifact, sealing, strings.Repeat("a", 64), false))
	listed, err := receipts.ListSigned(t.Context())
	require.NoError(t, err)
	require.Equal(t, []RemoteArtifactSignedReceipt{{FileName: artifact.FileName()}}, listed)
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	require.NoError(t, os.Remove(filepath.Join(directory, remoteArtifactReceiptFileName)))
	_, err = receipts.ListSigned(t.Context())
	require.ErrorContains(t, err, "delivery receipt for \""+artifact.FileName()+"\" is missing")
}

func TestRemoteArtifactReceiptAuditTransitionsWithReplacementHeadroom(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b818-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
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
	quota.maximum = quota.usage + uint64(initialUsage)

	assertStableUsage := func() {
		t.Helper()
		usage, err := remoteArtifactReceiptStateUsage(directory)
		require.NoError(t, err)
		require.Equal(t, initialUsage, usage)
		require.Equal(t, uint64(initialUsage), quota.usage)
		require.Equal(t, quota.maximum, quota.peak)
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

func TestWriteRemoteArtifactReceiptReservesReplacementHeadroom(t *testing.T) {
	directory := t.TempDir()
	fileName := "recording.bcast"
	target := filepath.Join(directory, remoteArtifactReceiptFileName)
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	initialPayload := []byte("first receipt")
	replacementPayload := []byte("next receipt!")
	require.Len(t, replacementPayload, len(initialPayload))
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}

	require.NoError(t, writeRemoteArtifactReceipt(directory, fileName, initialPayload, quota))
	initialUsage := quota.usage
	require.Equal(t, uint64(len(initialPayload)), initialUsage)
	require.Equal(t, initialPayload, remoteArtifactReceiptTestReadFile(t, target))
	require.Equal(t, 1, quota.reconciles)

	quota.maximum = initialUsage + uint64(len(replacementPayload)) - 1
	err := writeRemoteArtifactReceipt(directory, fileName, replacementPayload, quota)
	require.ErrorContains(t, err, "quota exceeded")
	require.Equal(t, initialPayload, remoteArtifactReceiptTestReadFile(t, target))
	require.NoFileExists(t, temporary)
	require.Equal(t, initialUsage, quota.usage)
	require.Equal(t, initialUsage, quota.peak)
	require.Equal(t, 1, quota.reconciles)

	quota.maximum++
	require.NoError(t, writeRemoteArtifactReceipt(directory, fileName, replacementPayload, quota))
	require.Equal(t, replacementPayload, remoteArtifactReceiptTestReadFile(t, target))
	require.NoFileExists(t, temporary)
	require.Equal(t, initialUsage, quota.usage)
	require.Equal(t, quota.maximum, quota.peak)
	require.Equal(t, 2, quota.reconciles)
}

func TestWriteRemoteArtifactReceiptReconcilesReservationAfterCreateFailure(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "receipt")
	require.NoError(t, os.Mkdir(directory, journalDirectoryMode))
	payload := []byte("receipt")
	quota := &remoteArtifactReceiptTestQuota{maximum: uint64(len(payload))}
	quota.onReserve = func() { require.NoError(t, os.Remove(directory)) }

	err := writeRemoteArtifactReceipt(directory, "recording.bcast", payload, quota)
	require.ErrorContains(t, err, "cannot create temporary")
	require.Equal(t, uint64(len(payload)), quota.peak)
	require.Zero(t, quota.usage)
	require.Equal(t, 1, quota.reconciles)
}

func TestWriteRemoteArtifactReceiptRecoversFromPersistenceFailures(t *testing.T) {
	tests := []struct {
		name              string
		replacementStored bool
		inject            func(*testing.T, *remoteArtifactReceiptWriteOperations, error)
	}{
		{
			name: "write",
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.write = func(*os.File, []byte) (int, error) { return 0, injected }
			},
		},
		{
			name: "short write",
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, _ error) {
				operations.write = func(file *os.File, value []byte) (int, error) { return file.Write(value[:1]) }
			},
		},
		{
			name: "file sync",
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.sync = func(*os.File) error { return injected }
			},
		},
		{
			name: "close",
			inject: func(t *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.close = func(file *os.File) error {
					require.NoError(t, file.Close())
					return injected
				}
			},
		},
		{
			name: "replace",
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.replace = func(string, string) error { return injected }
			},
		},
		{
			name:              "replace after publication",
			replacementStored: true,
			inject: func(t *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				replace := operations.replace
				operations.replace = func(source, target string) error {
					require.NoError(t, replace(source, target))
					return injected
				}
			},
		},
		{
			name:              "directory sync",
			replacementStored: true,
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.syncDirectory = func(string) error { return injected }
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, remoteArtifactReceiptFileName)
			temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
			initialPayload := []byte("first receipt")
			replacementPayload := []byte("next receipt!")
			quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
			require.NoError(t, writeRemoteArtifactReceipt(directory, "recording.bcast", initialPayload, quota))
			initialUsage := quota.usage

			operations := defaultRemoteArtifactReceiptWriteOperations()
			injected := fmt.Errorf("injected %s failure", test.name)
			test.inject(t, &operations, injected)
			closeFile := operations.close
			closed := false
			operations.close = func(file *os.File) error {
				closed = true
				return closeFile(file)
			}
			err := writeRemoteArtifactReceiptWithOperations(directory, "recording.bcast", replacementPayload, quota, operations)
			if test.name == "short write" {
				require.ErrorIs(t, err, io.ErrShortWrite)
			} else {
				require.ErrorContains(t, err, injected.Error())
			}
			require.True(t, closed)
			require.NoFileExists(t, temporary)
			usage, usageErr := remoteArtifactReceiptStateUsage(directory)
			require.NoError(t, usageErr)
			require.Equal(t, initialUsage, uint64(usage))
			require.Equal(t, initialUsage, quota.usage)
			require.Equal(t, initialUsage+uint64(len(replacementPayload)), quota.peak)
			require.Equal(t, 2, quota.reconciles)
			if test.replacementStored {
				require.Equal(t, replacementPayload, remoteArtifactReceiptTestReadFile(t, target))
			} else {
				require.Equal(t, initialPayload, remoteArtifactReceiptTestReadFile(t, target))
			}

			require.NoError(t, writeRemoteArtifactReceipt(directory, "recording.bcast", replacementPayload, quota))
			require.Equal(t, replacementPayload, remoteArtifactReceiptTestReadFile(t, target))
			require.NoFileExists(t, temporary)
			require.Equal(t, initialUsage, quota.usage)
			require.Equal(t, 3, quota.reconciles)
		})
	}
}

func TestRestoreRemoteArtifactReceiptCleansPersistenceFailures(t *testing.T) {
	tests := []struct {
		name              string
		replacementStored bool
		inject            func(*testing.T, *remoteArtifactReceiptWriteOperations, error)
	}{
		{
			name: "write",
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.write = func(*os.File, []byte) (int, error) { return 0, injected }
			},
		},
		{
			name: "short write",
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, _ error) {
				operations.write = func(file *os.File, value []byte) (int, error) { return file.Write(value[:1]) }
			},
		},
		{
			name: "file sync",
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.sync = func(*os.File) error { return injected }
			},
		},
		{
			name: "close",
			inject: func(t *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.close = func(file *os.File) error {
					require.NoError(t, file.Close())
					return injected
				}
			},
		},
		{
			name: "replace",
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.replace = func(string, string) error { return injected }
			},
		},
		{
			name:              "replace after publication",
			replacementStored: true,
			inject: func(t *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				replace := operations.replace
				operations.replace = func(source, target string) error {
					require.NoError(t, replace(source, target))
					return injected
				}
			},
		},
		{
			name:              "directory sync",
			replacementStored: true,
			inject: func(_ *testing.T, operations *remoteArtifactReceiptWriteOperations, injected error) {
				operations.syncDirectory = func(string) error { return injected }
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, remoteArtifactReceiptRetentionFileName)
			temporary := filepath.Join(directory, remoteArtifactReceiptRetentionTempName)
			payload := []byte("retention receipt")
			operations := defaultRemoteArtifactReceiptWriteOperations()
			injected := fmt.Errorf("injected %s failure", test.name)
			test.inject(t, &operations, injected)
			closeFile := operations.close
			closed := false
			operations.close = func(file *os.File) error {
				closed = true
				return closeFile(file)
			}

			err := restoreRemoteArtifactReceiptFileWithOperations(target, directory, payload, operations)
			if test.name == "short write" {
				require.ErrorIs(t, err, io.ErrShortWrite)
			} else {
				require.ErrorContains(t, err, injected.Error())
			}
			require.True(t, closed)
			require.NoFileExists(t, temporary)
			if test.replacementStored {
				require.Equal(t, payload, remoteArtifactReceiptTestReadFile(t, target))
			} else {
				require.NoFileExists(t, target)
			}

			require.NoError(t, restoreRemoteArtifactReceiptFile(target, directory, payload))
			require.NoFileExists(t, temporary)
			require.Equal(t, payload, remoteArtifactReceiptTestReadFile(t, target))
		})
	}
}

func TestReceiptTemporaryCleanupJoinsWriteAndCloseFailures(t *testing.T) {
	for _, restore := range []bool{false, true} {
		name := "write"
		if restore {
			name = "restore"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			writeErr := fmt.Errorf("injected write failure")
			closeErr := fmt.Errorf("injected close failure")
			operations := defaultRemoteArtifactReceiptWriteOperations()
			operations.write = func(*os.File, []byte) (int, error) { return 0, writeErr }
			operations.close = func(file *os.File) error {
				require.NoError(t, file.Close())
				return closeErr
			}
			var err error
			if restore {
				err = restoreRemoteArtifactReceiptFileWithOperations(filepath.Join(directory, remoteArtifactReceiptRetentionFileName), directory, []byte("receipt"), operations)
			} else {
				err = writeRemoteArtifactReceiptWithOperations(directory, "recording.bcast", []byte("receipt"), nil, operations)
			}
			require.ErrorIs(t, err, writeErr)
			require.ErrorIs(t, err, closeErr)
			require.NoFileExists(t, filepath.Join(directory, remoteArtifactReceiptTempFileName))
			require.NoFileExists(t, filepath.Join(directory, remoteArtifactReceiptRetentionTempName))
		})
	}
}

func TestRestoreRemoteArtifactReceiptCleansUncertainCreateFailure(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "receipt")
	require.NoError(t, os.Mkdir(directory, journalDirectoryMode))
	require.NoError(t, os.Remove(directory))

	err := restoreRemoteArtifactReceiptFile(filepath.Join(directory, remoteArtifactReceiptRetentionFileName), directory, []byte("receipt"))
	require.ErrorContains(t, err, "cannot create temporary")
	require.NoFileExists(t, filepath.Join(directory, remoteArtifactReceiptRetentionTempName))
}

func TestMutateRemoteArtifactReceiptStateReconcilesFailedMutation(t *testing.T) {
	directory := t.TempDir()
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, []byte("receipt")))
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20, usage: uint64(len("receipt"))}
	injected := fmt.Errorf("injected mutation failure")

	err := mutateRemoteArtifactReceiptState(directory, quota, func() error {
		require.NoError(t, os.Remove(temporary))
		return injected
	})
	require.ErrorIs(t, err, injected)
	require.Zero(t, quota.usage)
}

func TestWriteRemoteArtifactReceiptInvalidatesQuotaAfterFinalInventoryFailure(t *testing.T) {
	directory := t.TempDir()
	payload := []byte("receipt")
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	injected := fmt.Errorf("injected final inventory failure")
	operations := defaultRemoteArtifactReceiptWriteOperations()
	stateUsage := operations.stateUsage
	usageCalls := 0
	operations.stateUsage = func(directory string) (int64, error) {
		usageCalls++
		if usageCalls == 2 {
			return 0, injected
		}
		return stateUsage(directory)
	}

	err := writeRemoteArtifactReceiptWithOperations(directory, "recording.bcast", payload, quota, operations)
	require.ErrorIs(t, err, injected)
	require.ErrorIs(t, quota.invalidated, injected)
	require.Equal(t, uint64(len(payload)), quota.usage)
	require.Zero(t, quota.reconciles)
	require.ErrorIs(t, quota.Reserve(0), injected)
	require.FileExists(t, filepath.Join(directory, remoteArtifactReceiptFileName))
}

func TestRemoteArtifactReceiptQuotaAdapterInvalidatesLegacyImplementation(t *testing.T) {
	legacy := &remoteArtifactReceiptLegacyTestQuota{maximum: 10}
	quota := ensureRemoteArtifactReceiptQuotaInvalidation(legacy)
	require.NoError(t, quota.Reserve(4))
	injected := fmt.Errorf("injected inventory failure")
	invalidateRemoteArtifactReceiptQuota(quota, injected)

	require.ErrorIs(t, quota.Reserve(1), injected)
	require.ErrorIs(t, quota.Reconcile(0, 4, 4), injected)
	require.Equal(t, uint64(4), legacy.usage)
}

func TestRemoteArtifactReceiptQuotaAdapterPropagatesInvalidation(t *testing.T) {
	underlying := &remoteArtifactReceiptTestQuota{maximum: 10}
	quota := ensureRemoteArtifactReceiptQuotaInvalidation(underlying)
	injected := fmt.Errorf("injected inventory failure")
	invalidateRemoteArtifactReceiptQuota(quota, injected)

	require.ErrorIs(t, underlying.invalidated, injected)
	require.ErrorIs(t, quota.Reserve(0), injected)
}

func TestMutateRemoteArtifactReceiptStateInvalidatesQuotaAfterFinalInventoryFailure(t *testing.T) {
	directory := t.TempDir()
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	injected := fmt.Errorf("injected final inventory failure")
	usageCalls := 0
	stateUsage := func(string) (int64, error) {
		usageCalls++
		if usageCalls == 2 {
			return 0, injected
		}
		return 0, nil
	}

	err := mutateRemoteArtifactReceiptStateWithStateUsage(directory, quota, func() error { return nil }, stateUsage)
	require.ErrorIs(t, err, injected)
	require.ErrorIs(t, quota.invalidated, injected)
	require.ErrorIs(t, quota.Reserve(0), quota.invalidated)
}

func TestReconcileFailedRemoteArtifactReceiptRestoreInvalidatesQuotaAfterFinalInventoryFailure(t *testing.T) {
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	store := &remoteArtifactReceiptStore{quota: quota}
	injected := fmt.Errorf("injected final inventory failure")

	err := store.reconcileFailedRemoteArtifactReceiptRestoreWithStateUsage(t.TempDir(), 0, func(string) (int64, error) {
		return 0, injected
	})
	require.ErrorIs(t, err, injected)
	require.ErrorIs(t, quota.invalidated, injected)
	require.ErrorIs(t, quota.Reserve(0), quota.invalidated)
}

func TestRemoteArtifactReceiptReconcilesFailedRestoreState(t *testing.T) {
	for _, test := range []struct {
		name      string
		remaining bool
	}{
		{name: "empty"},
		{name: "restored", remaining: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, identity := newJournalTestIdentity(t)
			quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20, usage: 17}
			store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", quota)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, store.close()) })
			directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName("recording.bcast"))
			require.NoError(t, ensureJournalDirectory(directory, true))
			if test.remaining {
				require.NoError(t, writeRemoteArtifactReceiptTestFile(filepath.Join(directory, remoteArtifactReceiptRetentionFileName), make([]byte, 17)))
			}

			require.NoError(t, store.reconcileFailedRemoteArtifactReceiptRestore(directory, 17))
			if test.remaining {
				require.DirExists(t, directory)
				require.Equal(t, uint64(17), quota.usage)
			} else {
				require.NoDirExists(t, directory)
				require.Zero(t, quota.usage)
			}
		})
	}
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

func recoverRemoteArtifactReceiptTestTemporary(t *testing.T, store *remoteArtifactReceiptStore, artifact RemoteArtifact, expected remoteArtifactReceipt, payload []byte) remoteArtifactReceipt {
	t.Helper()
	directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	require.NoError(t, ensureJournalDirectory(directory, true))
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	target := filepath.Join(directory, remoteArtifactReceiptFileName)
	require.NoFileExists(t, temporary)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, payload))
	require.FileExists(t, temporary)
	before, err := remoteArtifactReceiptStateUsage(directory)
	require.NoError(t, err)
	if quota, ok := unwrapRemoteArtifactReceiptTestQuota(store.quota); ok {
		quota.usage = uint64(before)
		quota.peak = max(quota.peak, quota.usage)
	}

	require.NoError(t, (&RemoteArtifactReceipts{store: store}).Recover(t.Context()))
	require.NoFileExists(t, temporary)
	require.FileExists(t, target)
	after, err := remoteArtifactReceiptStateUsage(directory)
	require.NoError(t, err)
	if quota, ok := unwrapRemoteArtifactReceiptTestQuota(store.quota); ok {
		require.Equal(t, uint64(after), quota.usage)
	}
	recovered, exists, err := store.load(artifact)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, expected, recovered)
	return recovered
}

func remoteArtifactReceiptTestReadFile(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	require.NoError(t, err)
	return payload
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
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b817-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", &remoteArtifactReceiptTestQuota{maximum: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })

	_, err = store.initialize(artifact, time.Now().UTC(), nil)
	require.ErrorContains(t, err, "quota exceeded")
}

func TestRemoteArtifactReceiptStoreRemovesIncompleteTemporaries(t *testing.T) {
	for _, name := range []string{remoteArtifactReceiptTempFileName, remoteArtifactReceiptRetentionTempName} {
		t.Run(name, func(t *testing.T) {
			_, identity := newJournalTestIdentity(t)
			root := t.TempDir()
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b813-9dad-4d1f-80b4-00c04fd430c8.becast", []byte("recording"))
			store, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, store.close()) })
			directory := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
			require.NoError(t, ensureJournalDirectory(directory, true))
			temporary := filepath.Join(directory, name)
			require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, []byte("{")))

			_, _, err = store.load(artifact)
			require.ErrorContains(t, err, "cannot decode remote artifact delivery receipt")
			require.NoFileExists(t, temporary)
			_, exists, err := store.load(artifact)
			require.NoError(t, err)
			require.False(t, exists)
		})
	}
}

func TestRemoteArtifactReceiptScansRemoveMalformedOnlyTemporaries(t *testing.T) {
	for _, temporaryName := range []string{remoteArtifactReceiptTempFileName, remoteArtifactReceiptRetentionTempName} {
		for _, operation := range []string{"recover", "list"} {
			t.Run(temporaryName+"/"+operation, func(t *testing.T) {
				_, identity := newJournalTestIdentity(t)
				store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, store.close()) })
				state := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName("unpublished.bcast"))
				require.NoError(t, ensureJournalDirectory(state, true))
				temporary := filepath.Join(state, temporaryName)
				require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, []byte("{")))
				receipts := &RemoteArtifactReceipts{store: store}
				run := func() error {
					if operation == "recover" {
						return receipts.Recover(t.Context())
					}
					_, err := receipts.ListRetentionCandidates(t.Context(), time.Now().UTC())
					return err
				}

				require.ErrorContains(t, run(), "cannot identify remote artifact delivery receipt")
				require.NoFileExists(t, temporary)
				require.NoError(t, run())
			})
		}
	}
}

func TestRemoteArtifactReceiptRecoveryRemovesOversizedTemporary(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	state := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName("unpublished.bcast"))
	require.NoError(t, ensureJournalDirectory(state, true))
	temporary := filepath.Join(state, remoteArtifactReceiptTempFileName)
	require.NoError(t, writeRemoteArtifactReceiptTestFile(temporary, make([]byte, maxJournalRecordPayloadSize+1)))
	receipts := &RemoteArtifactReceipts{store: store}

	recoverErr := receipts.Recover(t.Context())
	require.ErrorContains(t, recoverErr, "exceeds")
	require.True(t, bferrors.System.IsErr(recoverErr))
	require.NoFileExists(t, temporary)
	require.NoError(t, receipts.Recover(t.Context()))
}

func TestRemoteArtifactReceiptRecoveryRemovesCleanupTombstones(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	quota := &remoteArtifactReceiptTestQuota{maximum: 1 << 20}
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", quota)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	state := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName("unpublished.bcast"))
	require.NoError(t, ensureJournalDirectory(state, true))
	for index, name := range []string{remoteArtifactReceiptTempFileName, remoteArtifactReceiptRetentionTempName} {
		path := filepath.Join(state, name+remoteArtifactReceiptCleanupSuffix)
		payload := []byte("cleanup")
		if index == 1 {
			payload = make([]byte, maxJournalRecordPayloadSize+1)
		}
		require.NoError(t, writeRemoteArtifactReceiptTestFile(path, payload))
		quota.usage += uint64(len(payload))
	}

	require.NoError(t, (&RemoteArtifactReceipts{store: store}).Recover(t.Context()))
	require.NoFileExists(t, filepath.Join(state, remoteArtifactReceiptTempFileName+remoteArtifactReceiptCleanupSuffix))
	require.NoFileExists(t, filepath.Join(state, remoteArtifactReceiptRetentionTempName+remoteArtifactReceiptCleanupSuffix))
	require.Zero(t, quota.usage)
}

func TestRemoteArtifactReceiptRecoveryRejectsNonRegularCleanupTombstone(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	state := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName("unpublished.bcast"))
	require.NoError(t, ensureJournalDirectory(state, true))
	tombstone := filepath.Join(state, remoteArtifactReceiptTempFileName+remoteArtifactReceiptCleanupSuffix)
	require.NoError(t, os.Mkdir(tombstone, journalDirectoryMode))

	err = (&RemoteArtifactReceipts{store: store}).Recover(t.Context())
	require.ErrorContains(t, err, "is not a regular file")
	require.DirExists(t, tombstone)
}

func TestRemoteArtifactReceiptRecoveryRemovesEmptyUnpublishedState(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	store, err := newRemoteArtifactReceiptStore(t.TempDir(), identity, "security", nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.close()) })
	state := filepath.Join(store.producerDirectory, remoteArtifactReceiptStateName("unpublished.bcast"))
	require.NoError(t, ensureJournalDirectory(state, true))

	require.NoError(t, (&RemoteArtifactReceipts{store: store}).Recover(t.Context()))
	require.NoDirExists(t, state)
}

func TestRemoteArtifactReceiptStateNamesAvoidFilesystemAliases(t *testing.T) {
	lower := remoteArtifactReceiptStateName("recording.bcast")
	upper := remoteArtifactReceiptStateName("RECORDING.bcast")
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
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b815-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
	_, err = first.initialize(artifact, time.Now().UTC(), nil)
	require.ErrorContains(t, err, "closed")
	second, err := newRemoteArtifactReceiptStore(root, identity, "security", nil)
	require.NoError(t, err)
	require.NoError(t, second.close())
}

func TestRemoteArtifactReceiptKeepsSelectionAcrossConfigurationChanges(t *testing.T) {
	_, identity := newJournalTestIdentity(t)
	root := t.TempDir()
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "6ba7b814-9dad-4d1f-80b4-00c04fd430c8.bcast", []byte("recording"))
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
	maximum     uint64
	usage       uint64
	peak        uint64
	reconciles  int
	onReserve   func()
	invalidated error
}

func (this *remoteArtifactReceiptTestQuota) Reserve(bytes uint64) error {
	if this.invalidated != nil {
		return this.invalidated
	}
	if this.usage > this.maximum || bytes > this.maximum-this.usage {
		return fmt.Errorf("quota exceeded")
	}
	this.usage += bytes
	this.peak = max(this.peak, this.usage)
	if this.onReserve != nil {
		this.onReserve()
	}
	return nil
}

func (this *remoteArtifactReceiptTestQuota) Reconcile(reserved uint64, before, after int64) error {
	if this.invalidated != nil {
		return this.invalidated
	}
	this.reconciles++
	if after >= before {
		this.usage -= reserved - uint64(after-before)
	} else {
		this.usage -= reserved + uint64(before-after)
	}
	return nil
}

func (this *remoteArtifactReceiptTestQuota) Invalidate(cause error) {
	if this.invalidated == nil {
		this.invalidated = cause
	}
}

func unwrapRemoteArtifactReceiptTestQuota(quota RemoteArtifactReceiptQuota) (*remoteArtifactReceiptTestQuota, bool) {
	switch quota := quota.(type) {
	case *remoteArtifactReceiptTestQuota:
		return quota, true
	case *invalidatableRemoteArtifactReceiptQuota:
		return unwrapRemoteArtifactReceiptTestQuota(quota.quota)
	default:
		return nil, false
	}
}

type remoteArtifactReceiptLegacyTestQuota struct {
	maximum uint64
	usage   uint64
}

func (this *remoteArtifactReceiptLegacyTestQuota) Reserve(bytes uint64) error {
	if this.usage > this.maximum || bytes > this.maximum-this.usage {
		return fmt.Errorf("quota exceeded")
	}
	this.usage += bytes
	return nil
}

func (this *remoteArtifactReceiptLegacyTestQuota) Reconcile(reserved uint64, before, after int64) error {
	if after >= before {
		this.usage -= reserved - uint64(after-before)
	} else {
		this.usage -= reserved + uint64(before-after)
	}
	return nil
}
