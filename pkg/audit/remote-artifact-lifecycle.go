package audit

import (
	"bytes"
	"context"
	"encoding/json"
	goerrors "errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	remoteArtifactLifecycleFileName      = "receipt.lifecycle"
	remoteArtifactLifecycleTempName      = "receipt.lifecycle.tmp"
	remoteArtifactLifecycleSchema        = "bifroest.session-recording-lifecycle-outbox/v1"
	remoteArtifactLifecycleSignDomain    = "BIFROEST-SESSION-RECORDING-LIFECYCLE-OUTBOX-SIGNATURE/v1\x00"
	remoteArtifactLifecycleStateIntent   = "intent"
	remoteArtifactLifecycleStateStaged   = "staged"
	remoteArtifactLifecycleStatePrepared = "prepared"
	remoteArtifactLifecycleStatePending  = "pending"
)

type remoteArtifactLifecycleContent struct {
	Schema         string                     `json:"schema"`
	State          string                     `json:"state"`
	ProducerId     ProducerId                 `json:"producerId"`
	Auditlog       configuration.AuditlogName `json:"auditlog"`
	FileName       string                     `json:"fileName"`
	StartedAt      string                     `json:"startedAt"`
	ArtifactDigest ArtifactDigest             `json:"artifactDigest,omitempty"`
	Event          Event                      `json:"event"`
	PublicKey      []byte                     `json:"publicKey"`
}

type remoteArtifactLifecycle struct {
	remoteArtifactLifecycleContent
	Signature []byte `json:"signature"`
}

// RemoteArtifactLifecycleEvent is an immutable terminal event awaiting audit
// persistence. Event data is replayed byte-for-byte from signed local state.
type RemoteArtifactLifecycleEvent struct {
	Auditlog       configuration.AuditlogName
	FileName       string
	ArtifactDigest ArtifactDigest
	Event          Event
}

func (this *RemoteArtifactReceipts) BeginLifecycle(ctx context.Context, fileName string, startedAt time.Time, event Event) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.beginLifecycle(ctx, fileName, startedAt, event)
}

func (this *RemoteArtifactReceipts) StageLifecycle(ctx context.Context, fileName string, event Event) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.stageLifecycle(ctx, fileName, event)
}

func (this *RemoteArtifactReceipts) PendingLifecycle(ctx context.Context) ([]RemoteArtifactLifecycleEvent, error) {
	if this == nil || this.store == nil {
		return nil, errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.pendingLifecycle(ctx)
}

// LifecyclePrepared reports whether artifact preparation has durably bound the
// terminal event. Pending events remain prepared until they are completed.
func (this *RemoteArtifactReceipts) LifecyclePrepared(ctx context.Context, fileName string) (bool, error) {
	if this == nil || this.store == nil {
		return false, errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.lifecyclePrepared(ctx, fileName)
}

// PromoteLifecycle makes a prepared terminal event replayable after the local
// repository has atomically published and verified the exact artifact.
func (this *RemoteArtifactReceipts) PromoteLifecycle(ctx context.Context, artifact RemoteArtifact) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.promoteLifecycle(ctx, artifact)
}

func (this *RemoteArtifactReceipts) CompleteLifecycle(ctx context.Context, pending RemoteArtifactLifecycleEvent) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.completeLifecycle(ctx, pending)
}

// DiscardLifecycle removes an intent only when no receipt exists. Callers must
// first establish that no active, staged, or sealed artifact survives.
func (this *RemoteArtifactReceipts) DiscardLifecycle(ctx context.Context, fileName string) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.discardLifecycle(ctx, fileName)
}

// CleanupOrphanedLifecycles removes pre-create intents after recording startup
// recovery has consumed every recoverable active artifact.
func (this *RemoteArtifactReceipts) CleanupOrphanedLifecycles(ctx context.Context) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.cleanupOrphanedLifecycles(ctx)
}

func (this *remoteArtifactReceiptStore) beginLifecycle(ctx context.Context, fileName string, startedAt time.Time, event Event) error {
	if err := validateRemoteArtifactReceiptOwner(this.identity, this.auditlog, fileName); err != nil {
		return err
	}
	canonicalStartedAt, err := canonicalRemoteArtifactReceiptTime(startedAt)
	if err != nil {
		return errors.Config.Newf("illegal session Recording lifecycle start time: %w", err)
	}
	if event.Name != EventNameSessionRecordingStarted {
		return errors.Config.Newf("session Recording lifecycle intent is not a started event")
	}
	if err := validateAuditEventForWrite(event); err != nil {
		return err
	}
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	if _, exists, err := this.loadSnapshotLocked(fileName, nil); err != nil {
		return err
	} else if exists {
		return errors.Config.Newf("cannot begin session Recording lifecycle for sealed artifact %q", fileName)
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(fileName))
	if err := ensureRemoteArtifactReceiptDirectory(directory); err != nil {
		return err
	}
	existing, exists, err := this.loadLifecycleLocked(fileName, nil)
	if err != nil {
		return err
	}
	if exists {
		if existing.State == remoteArtifactLifecycleStateIntent && existing.StartedAt == canonicalStartedAt && reflect.DeepEqual(existing.Event, event) {
			return nil
		}
		return errors.Config.Newf("session Recording lifecycle intent for %q already exists", fileName)
	}
	marker, payload, err := signRemoteArtifactLifecycle(this.identity, remoteArtifactLifecycleContent{
		Schema:     remoteArtifactLifecycleSchema,
		State:      remoteArtifactLifecycleStateIntent,
		ProducerId: this.identity.ProducerId(),
		Auditlog:   this.auditlog,
		FileName:   fileName,
		StartedAt:  canonicalStartedAt,
		Event:      event,
		PublicKey:  this.identity.PublicKey().Marshal(),
	})
	if err != nil {
		return err
	}
	_ = marker
	return writeRemoteArtifactLifecycle(directory, fileName, payload, this.quota)
}

func (this *remoteArtifactReceiptStore) stageLifecycle(ctx context.Context, fileName string, event Event) error {
	if event.RecordingDigest != "" {
		return errors.Config.Newf("staged session Recording lifecycle event already has an artifact digest")
	}
	validation := event
	validation.RecordingDigest = ArtifactDigest{1}.String()
	if err := validateAuditEventForWrite(validation); err != nil {
		return err
	}
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	marker, exists, err := this.loadLifecycleLocked(fileName, nil)
	if err != nil {
		return err
	}
	if !exists {
		return errors.Config.Newf("session Recording lifecycle intent for %q is missing", fileName)
	}
	if marker.State == remoteArtifactLifecycleStateStaged && reflect.DeepEqual(marker.Event, event) {
		return nil
	}
	if marker.State != remoteArtifactLifecycleStateIntent && marker.State != remoteArtifactLifecycleStateStaged {
		return errors.Config.Newf("session Recording lifecycle event for %q is already finalized", fileName)
	}
	if !sameRemoteArtifactLifecycleCorrelation(marker.Event, event) {
		return errors.Config.Newf("staged session Recording lifecycle event changes immutable correlation")
	}
	content := marker.remoteArtifactLifecycleContent
	content.State = remoteArtifactLifecycleStateStaged
	content.Event = event
	_, payload, err := signRemoteArtifactLifecycle(this.identity, content)
	if err != nil {
		return err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(fileName))
	return writeRemoteArtifactLifecycle(directory, fileName, payload, this.quota)
}

func (this *remoteArtifactReceiptStore) finalizeLifecycleLocked(artifact RemoteArtifact, sealedAt time.Time, recordingDigest string, interrupted bool) error {
	marker, exists, err := this.loadLifecycleLocked(artifact.FileName(), nil)
	if err != nil {
		return err
	}
	if !exists {
		return errors.Config.Newf("session Recording lifecycle intent for %q is missing", artifact.FileName())
	}
	if marker.State == remoteArtifactLifecycleStatePrepared || marker.State == remoteArtifactLifecycleStatePending {
		if marker.ArtifactDigest != artifact.Digest() || marker.Event.RecordingDigest != recordingDigest {
			return errors.Config.Newf("session Recording lifecycle event belongs to a different artifact")
		}
		return nil
	}
	event := marker.Event
	if interrupted {
		startedAt, err := parseRemoteArtifactReceiptTime(marker.StartedAt)
		if err != nil {
			return err
		}
		if sealedAt.Before(startedAt) {
			return errors.Config.Newf("session Recording lifecycle seal time precedes its start time")
		}
		durationMillis := sealedAt.Sub(startedAt).Milliseconds()
		event.Name = EventNameSessionRecordingIncomplete
		event.Outcome = EventOutcomeFailure
		event.Reason = EventReasonStartupRecovery
		event.ErrorCategory = ""
		event.Pty = nil
		event.ExitCode = nil
		event.DurationMillis = &durationMillis
	} else if marker.State != remoteArtifactLifecycleStateStaged {
		return errors.Config.Newf("session Recording lifecycle event for %q was not staged before sealing", artifact.FileName())
	}
	event.RecordingDigest = recordingDigest
	if err := validateAuditEventForWrite(event); err != nil {
		return err
	}
	content := marker.remoteArtifactLifecycleContent
	content.State = remoteArtifactLifecycleStatePrepared
	content.ArtifactDigest = artifact.Digest()
	content.Event = event
	_, payload, err := signRemoteArtifactLifecycle(this.identity, content)
	if err != nil {
		return err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	return writeRemoteArtifactLifecycle(directory, artifact.FileName(), payload, this.quota)
}

func (this *remoteArtifactReceiptStore) promoteLifecycle(ctx context.Context, artifact RemoteArtifact) error {
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, receiptExists, err := this.loadLocked(artifact)
	if err != nil {
		return err
	}
	if !receiptExists {
		return errors.Config.Newf("remote artifact delivery receipt for %q is missing", artifact.FileName())
	}
	marker, exists, err := this.loadLifecycleLocked(artifact.FileName(), &receipt)
	if err != nil {
		return err
	}
	if !exists {
		return errors.Config.Newf("session Recording lifecycle state for %q is missing", artifact.FileName())
	}
	if marker.State == remoteArtifactLifecycleStatePending {
		return nil
	}
	if marker.State != remoteArtifactLifecycleStatePrepared {
		return errors.Config.Newf("session Recording lifecycle event for %q is not prepared", artifact.FileName())
	}
	content := marker.remoteArtifactLifecycleContent
	content.State = remoteArtifactLifecycleStatePending
	_, payload, err := signRemoteArtifactLifecycle(this.identity, content)
	if err != nil {
		return err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	return writeRemoteArtifactLifecycle(directory, artifact.FileName(), payload, this.quota)
}

func (this *remoteArtifactReceiptStore) pendingLifecycle(ctx context.Context) ([]RemoteArtifactLifecycleEvent, error) {
	if err := this.lock(ctx); err != nil {
		return nil, err
	}
	defer this.unlock()
	if this.closed {
		return nil, errors.System.Newf("remote artifact receipt store is closed")
	}
	fileNames, err := this.stateFileNamesLocked(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]RemoteArtifactLifecycleEvent, 0)
	for _, fileName := range fileNames {
		marker, exists, err := this.loadLifecycleLocked(fileName, nil)
		if err != nil {
			return nil, err
		}
		if !exists || marker.State != remoteArtifactLifecycleStatePending {
			continue
		}
		receipt, receiptExists, err := this.loadSnapshotLocked(fileName, nil)
		if err != nil {
			return nil, err
		}
		if !receiptExists || receipt.ArtifactDigest != marker.ArtifactDigest {
			return nil, errors.Config.Newf("session Recording lifecycle event for %q does not match its receipt", fileName)
		}
		result = append(result, RemoteArtifactLifecycleEvent{Auditlog: this.auditlog, FileName: fileName, ArtifactDigest: marker.ArtifactDigest, Event: marker.Event})
	}
	return result, nil
}

func (this *remoteArtifactReceiptStore) lifecyclePrepared(ctx context.Context, fileName string) (bool, error) {
	if err := this.lock(ctx); err != nil {
		return false, err
	}
	defer this.unlock()
	if this.closed {
		return false, errors.System.Newf("remote artifact receipt store is closed")
	}
	marker, exists, err := this.loadLifecycleLocked(fileName, nil)
	if err != nil || !exists {
		return false, err
	}
	return marker.State == remoteArtifactLifecycleStatePrepared || marker.State == remoteArtifactLifecycleStatePending, nil
}

func (this *remoteArtifactReceiptStore) completeLifecycle(ctx context.Context, pending RemoteArtifactLifecycleEvent) error {
	if pending.Auditlog != this.auditlog || pending.FileName == "" || pending.ArtifactDigest.IsZero() {
		return errors.Config.Newf("invalid pending session Recording lifecycle event")
	}
	if err := validateAuditEventForWrite(pending.Event); err != nil {
		return err
	}
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	marker, exists, err := this.loadLifecycleLocked(pending.FileName, nil)
	if err != nil || !exists {
		return err
	}
	if marker.State != remoteArtifactLifecycleStatePending || marker.ArtifactDigest != pending.ArtifactDigest || !reflect.DeepEqual(marker.Event, pending.Event) {
		return errors.Config.Newf("pending session Recording lifecycle event changed")
	}
	receipt, receiptExists, err := this.loadSnapshotLocked(pending.FileName, nil)
	if err != nil {
		return err
	}
	if !receiptExists || receipt.ArtifactDigest != pending.ArtifactDigest {
		return errors.Config.Newf("pending session Recording lifecycle event does not match its receipt")
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(pending.FileName))
	return mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
		return removeRemoteArtifactReceiptFile(filepath.Join(directory, remoteArtifactLifecycleFileName), directory)
	})
}

func (this *remoteArtifactReceiptStore) discardLifecycle(ctx context.Context, fileName string) error {
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, receiptExists, err := this.loadSnapshotLocked(fileName, nil)
	if err != nil {
		return err
	}
	_ = receipt
	if receiptExists {
		return errors.Config.Newf("cannot discard session Recording lifecycle for sealed artifact %q", fileName)
	}
	marker, exists, err := this.loadLifecycleLocked(fileName, nil)
	if err != nil || !exists {
		return err
	}
	if marker.State != remoteArtifactLifecycleStateIntent {
		return errors.Config.Newf("cannot discard non-intent session Recording lifecycle for %q", fileName)
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(fileName))
	if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
		return removeRemoteArtifactReceiptFile(filepath.Join(directory, remoteArtifactLifecycleFileName), directory)
	}); err != nil {
		return err
	}
	return removeEmptyRemoteArtifactReceiptState(directory, this.producerDirectory)
}

func (this *remoteArtifactReceiptStore) cleanupOrphanedLifecycles(ctx context.Context) error {
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	fileNames, err := this.stateFileNamesLocked(ctx)
	if err != nil {
		return err
	}
	for _, fileName := range fileNames {
		_, receiptExists, err := this.loadSnapshotLocked(fileName, nil)
		if err != nil {
			return err
		}
		marker, markerExists, err := this.loadLifecycleLocked(fileName, nil)
		if err != nil {
			return err
		}
		if receiptExists || !markerExists {
			continue
		}
		if marker.State != remoteArtifactLifecycleStateIntent {
			return errors.Config.Newf("non-intent session Recording lifecycle for %q has no receipt", fileName)
		}
		directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(fileName))
		if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
			return removeRemoteArtifactReceiptFile(filepath.Join(directory, remoteArtifactLifecycleFileName), directory)
		}); err != nil {
			return err
		}
		if err := removeEmptyRemoteArtifactReceiptState(directory, this.producerDirectory); err != nil {
			return err
		}
	}
	return nil
}

func signRemoteArtifactLifecycle(identity *Identity, content remoteArtifactLifecycleContent) (remoteArtifactLifecycle, []byte, error) {
	if identity == nil || content.ProducerId != identity.ProducerId() || !bytes.Equal(content.PublicKey, identity.journalPublicKey()) {
		return remoteArtifactLifecycle{}, nil, errors.Config.Newf("session Recording lifecycle identity does not match its content")
	}
	if err := validateRemoteArtifactLifecycleContent(content); err != nil {
		return remoteArtifactLifecycle{}, nil, err
	}
	unsigned, err := json.Marshal(content)
	if err != nil {
		return remoteArtifactLifecycle{}, nil, err
	}
	signature, err := identity.sign(append([]byte(remoteArtifactLifecycleSignDomain), unsigned...))
	if err != nil {
		return remoteArtifactLifecycle{}, nil, err
	}
	marker := remoteArtifactLifecycle{remoteArtifactLifecycleContent: content, Signature: signature}
	payload, err := json.Marshal(marker)
	if err != nil {
		return remoteArtifactLifecycle{}, nil, err
	}
	if len(payload) > maxJournalRecordPayloadSize {
		return remoteArtifactLifecycle{}, nil, errors.Config.Newf("session Recording lifecycle state exceeds %d bytes", maxJournalRecordPayloadSize)
	}
	return marker, payload, nil
}

func decodeRemoteArtifactLifecycle(payload []byte, identity *Identity, auditlog configuration.AuditlogName, fileName string) (remoteArtifactLifecycle, error) {
	var marker remoteArtifactLifecycle
	if err := decodeCanonicalJournalPayload(payload, &marker); err != nil {
		return marker, errors.System.Newf("cannot decode session Recording lifecycle state: %w", err)
	}
	if marker.ProducerId != identity.ProducerId() || marker.Auditlog != auditlog || marker.FileName != fileName || !bytes.Equal(marker.PublicKey, identity.journalPublicKey()) {
		return marker, errors.Config.Newf("session Recording lifecycle state belongs to a different producer, auditlog, or artifact")
	}
	if err := validateRemoteArtifactLifecycleContent(marker.remoteArtifactLifecycleContent); err != nil {
		return marker, err
	}
	unsigned, err := json.Marshal(marker.remoteArtifactLifecycleContent)
	if err != nil {
		return marker, err
	}
	if err := identity.verify(append([]byte(remoteArtifactLifecycleSignDomain), unsigned...), marker.Signature); err != nil {
		return marker, errors.System.Newf("cannot verify session Recording lifecycle state: %w", err)
	}
	return marker, nil
}

func validateRemoteArtifactLifecycleContent(content remoteArtifactLifecycleContent) error {
	if content.Schema != remoteArtifactLifecycleSchema || content.ProducerId.IsZero() || len(content.PublicKey) == 0 {
		return errors.Config.Newf("session Recording lifecycle state has invalid immutable content")
	}
	if err := content.Auditlog.Validate(); err != nil {
		return err
	}
	if err := validateRemoteArtifactFileName(content.FileName); err != nil {
		return err
	}
	if _, err := parseRemoteArtifactReceiptTime(content.StartedAt); err != nil {
		return errors.Config.Newf("session Recording lifecycle state has an illegal start time: %w", err)
	}
	recordingId := strings.TrimSuffix(strings.TrimSuffix(content.FileName, ".bcast"), ".becast")
	if recordingId == content.FileName || content.Event.RecordingId != recordingId {
		return errors.Config.Newf("session Recording lifecycle event does not match its artifact name")
	}
	switch content.State {
	case remoteArtifactLifecycleStateIntent:
		if !content.ArtifactDigest.IsZero() || content.Event.Name != EventNameSessionRecordingStarted {
			return errors.Config.Newf("session Recording lifecycle intent has illegal state")
		}
		return validateAuditEventForWrite(content.Event)
	case remoteArtifactLifecycleStateStaged:
		if !content.ArtifactDigest.IsZero() || content.Event.RecordingDigest != "" {
			return errors.Config.Newf("staged session Recording lifecycle event has illegal artifact state")
		}
		validation := content.Event
		validation.RecordingDigest = ArtifactDigest{1}.String()
		return validateAuditEventForWrite(validation)
	case remoteArtifactLifecycleStatePrepared, remoteArtifactLifecycleStatePending:
		if content.ArtifactDigest.IsZero() || content.Event.RecordingDigest == "" {
			return errors.Config.Newf("prepared or pending session Recording lifecycle event has illegal artifact state")
		}
		return validateAuditEventForWrite(content.Event)
	default:
		return errors.Config.Newf("session Recording lifecycle state %q is unknown", content.State)
	}
}

func (this *remoteArtifactReceiptStore) loadLifecycleLocked(fileName string, receipt *remoteArtifactReceipt) (remoteArtifactLifecycle, bool, error) {
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(fileName))
	if err := ensureRemoteArtifactReceiptDirectory(directory); err != nil {
		return remoteArtifactLifecycle{}, false, err
	}
	read := func(path string) (remoteArtifactLifecycle, []byte, bool, error) {
		payload, exists, err := readRemoteArtifactReceiptPayload(path)
		if err != nil || !exists {
			return remoteArtifactLifecycle{}, nil, exists, err
		}
		marker, err := decodeRemoteArtifactLifecycle(payload, this.identity, this.auditlog, fileName)
		return marker, payload, true, err
	}
	targetPath := filepath.Join(directory, remoteArtifactLifecycleFileName)
	temporaryPath := filepath.Join(directory, remoteArtifactLifecycleTempName)
	marker, payload, exists, err := read(targetPath)
	if err != nil {
		return marker, exists, errors.System.Newf("cannot use session Recording lifecycle state %q: %w", targetPath, err)
	}
	temporary, temporaryPayload, temporaryExists, err := read(temporaryPath)
	if err != nil {
		cleanupErr := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
			return cleanupRemoteArtifactReceiptFile(temporaryPath, directory)
		})
		return remoteArtifactLifecycle{}, false, goerrors.Join(err, cleanupErr)
	}
	if temporaryExists {
		switch {
		case exists && bytes.Equal(payload, temporaryPayload):
			if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
				return removeRemoteArtifactReceiptFile(temporaryPath, directory)
			}); err != nil {
				return remoteArtifactLifecycle{}, false, err
			}
		case exists && !isRemoteArtifactLifecycleSuccessor(marker, temporary):
			return remoteArtifactLifecycle{}, false, errors.Config.Newf("temporary session Recording lifecycle state for %q conflicts with its published state", fileName)
		default:
			if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
				if err := replaceJournalFile(temporaryPath, targetPath); err != nil {
					return err
				}
				return syncJournalDirectory(directory)
			}); err != nil {
				return remoteArtifactLifecycle{}, false, err
			}
			marker, exists = temporary, true
		}
	}
	if exists && receipt != nil && (marker.State == remoteArtifactLifecycleStatePrepared || marker.State == remoteArtifactLifecycleStatePending) && marker.ArtifactDigest != receipt.ArtifactDigest {
		return remoteArtifactLifecycle{}, false, errors.Config.Newf("session Recording lifecycle state for %q belongs to a different receipt", fileName)
	}
	return marker, exists, nil
}

func isRemoteArtifactLifecycleSuccessor(current, next remoteArtifactLifecycle) bool {
	if current.Schema != next.Schema || current.ProducerId != next.ProducerId || current.Auditlog != next.Auditlog || current.FileName != next.FileName || current.StartedAt != next.StartedAt || !bytes.Equal(current.PublicKey, next.PublicKey) {
		return false
	}
	if !sameRemoteArtifactLifecycleCorrelation(current.Event, next.Event) {
		return false
	}
	if current.State == remoteArtifactLifecycleStateIntent {
		return next.State == remoteArtifactLifecycleStateStaged || next.State == remoteArtifactLifecycleStatePrepared
	}
	if current.State == remoteArtifactLifecycleStateStaged {
		return next.State == remoteArtifactLifecycleStateStaged || next.State == remoteArtifactLifecycleStatePrepared
	}
	return current.State == remoteArtifactLifecycleStatePrepared && (next.State == remoteArtifactLifecycleStatePrepared || next.State == remoteArtifactLifecycleStatePending)
}

func sameRemoteArtifactLifecycleCorrelation(left, right Event) bool {
	return left.Domain == right.Domain && left.Flow == right.Flow && left.ConnectionId == right.ConnectionId &&
		left.SessionId == right.SessionId && left.OperationId == right.OperationId && left.RecordingId == right.RecordingId &&
		left.SessionTask == right.SessionTask
}

func writeRemoteArtifactLifecycle(directory, fileName string, payload []byte, quota RemoteArtifactReceiptQuota) (result error) {
	before, err := remoteArtifactReceiptStateUsage(directory)
	if err != nil {
		return err
	}
	reserved := uint64(len(payload))
	if quota != nil {
		if err := quota.Reserve(reserved); err != nil {
			return err
		}
		defer func() {
			after, usageErr := remoteArtifactReceiptStateUsage(directory)
			if usageErr != nil {
				invalidateRemoteArtifactReceiptQuota(quota, usageErr)
				result = goerrors.Join(result, usageErr)
				return
			}
			result = goerrors.Join(result, quota.Reconcile(reserved, before, after))
		}()
	}
	temporary := filepath.Join(directory, remoteArtifactLifecycleTempName)
	if err := removeRemoteArtifactReceiptFile(temporary, directory); err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			result = goerrors.Join(result, cleanupRemoteArtifactReceiptFile(temporary, directory))
		}
	}()
	if err := secureJournalFile(temporary, file); err != nil {
		return err
	}
	written, err := file.Write(payload)
	if err == nil && written != len(payload) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	err = goerrors.Join(err, file.Close())
	if err != nil {
		return errors.System.Newf("cannot write session Recording lifecycle state for %q: %w", fileName, err)
	}
	if err := replaceJournalFile(temporary, filepath.Join(directory, remoteArtifactLifecycleFileName)); err != nil {
		return err
	}
	if err := syncJournalDirectory(directory); err != nil {
		return err
	}
	cleanup = false
	return nil
}
