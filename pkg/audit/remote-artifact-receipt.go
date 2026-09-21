package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	goerrors "errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	remoteArtifactReceiptStateDirectoryName = ".delivery"
	remoteArtifactReceiptFileName           = "receipt.json"
	remoteArtifactReceiptRetentionFileName  = "receipt.retention"
	remoteArtifactReceiptRetentionTempName  = "receipt.retention.tmp"
	remoteArtifactReceiptTempFileName       = "receipt.tmp"
	remoteArtifactReceiptCleanupSuffix      = ".cleanup"
	remoteArtifactReceiptSchema             = "bifroest.session-recording-remote-delivery-receipt/v2"
	remoteArtifactReceiptSignDomain         = "BIFROEST-SESSION-RECORDING-REMOTE-DELIVERY-RECEIPT-SIGNATURE/v2\x00"
	remoteArtifactReceiptStateReserveBytes  = 320
)

type remoteArtifactReceiptTarget struct {
	Target                 configuration.AuditlogTargetName     `json:"target"`
	DestinationFingerprint remoteDeliveryDestinationFingerprint `json:"destinationFingerprint"`
	AcknowledgedAt         string                               `json:"acknowledgedAt,omitempty"`
	AuditOperationId       string                               `json:"auditOperationId,omitempty"`
	FailedAt               string                               `json:"failedAt,omitempty"`
	FailureErrorCategory   ErrorCategory                        `json:"failureErrorCategory,omitempty"`
	FailureAuditedAt       string                               `json:"failureAuditedAt,omitempty"`
	SuccessAuditedAt       string                               `json:"successAuditedAt,omitempty"`
}

type remoteArtifactReceiptContent struct {
	Schema         string                        `json:"schema"`
	ProducerId     ProducerId                    `json:"producerId"`
	Auditlog       configuration.AuditlogName    `json:"auditlog"`
	FileName       string                        `json:"fileName"`
	ArtifactDigest ArtifactDigest                `json:"artifactDigest"`
	Size           int64                         `json:"size"`
	SealedAt       string                        `json:"sealedAt"`
	Targets        []remoteArtifactReceiptTarget `json:"targets"`
	PublicKey      []byte                        `json:"publicKey"`
	StatePadding   string                        `json:"statePadding"`
}

type remoteArtifactReceipt struct {
	remoteArtifactReceiptContent
	Signature []byte `json:"signature"`
}

type oversizedRemoteArtifactReceiptError struct {
	cause error
}

func (this *oversizedRemoteArtifactReceiptError) Error() string {
	return this.cause.Error()

}

func (this *oversizedRemoteArtifactReceiptError) Unwrap() error {
	return this.cause
}

type remoteArtifactReceiptTargetStatus uint8

type remoteArtifactReceiptUUIDGenerator func() (uuid.UUID, error)

const (
	remoteArtifactReceiptTargetNotSelected remoteArtifactReceiptTargetStatus = iota
	remoteArtifactReceiptTargetPending
	remoteArtifactReceiptTargetFailureAuditPending
	remoteArtifactReceiptTargetSuccessAuditPending
	remoteArtifactReceiptTargetAcknowledged
)

type remoteArtifactReceiptStore struct {
	mutex             chan struct{}
	producerDirectory string
	identity          *Identity
	auditlog          configuration.AuditlogName
	quota             RemoteArtifactReceiptQuota
	newUUID           remoteArtifactReceiptUUIDGenerator
	stateLock         *journalProcessLock
	closed            bool
	closeErr          error
}

type RemoteArtifactReceiptQuota interface {
	Reserve(uint64) error
	Reconcile(uint64, int64, int64) error
}

type remoteArtifactReceiptQuotaInvalidator interface{ Invalidate(error) }

type invalidatableRemoteArtifactReceiptQuota struct {
	mutex    sync.Mutex
	quota    RemoteArtifactReceiptQuota
	poisoned error
}

func (this *invalidatableRemoteArtifactReceiptQuota) Reserve(bytes uint64) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.poisoned != nil {
		return this.poisoned
	}
	return this.quota.Reserve(bytes)
}

func (this *invalidatableRemoteArtifactReceiptQuota) Reconcile(reserved uint64, before, after int64) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.poisoned != nil {
		return this.poisoned
	}
	return this.quota.Reconcile(reserved, before, after)
}

func (this *invalidatableRemoteArtifactReceiptQuota) Invalidate(cause error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.poisoned != nil {
		return
	}
	if cause == nil {
		cause = errors.System.Newf("unknown remote artifact receipt quota failure")
	}
	this.poisoned = errors.System.Newf("remote artifact receipt quota usage is uncertain: %w", cause)
	if invalidator, ok := this.quota.(remoteArtifactReceiptQuotaInvalidator); ok {
		invalidator.Invalidate(cause)
	}
}

func ensureRemoteArtifactReceiptQuotaInvalidation(quota RemoteArtifactReceiptQuota) RemoteArtifactReceiptQuota {
	if quota == nil {
		return nil
	}
	return &invalidatableRemoteArtifactReceiptQuota{quota: quota}
}

type remoteArtifactReceiptWriteOperations struct {
	write         func(*os.File, []byte) (int, error)
	sync          func(*os.File) error
	close         func(*os.File) error
	replace       func(string, string) error
	syncDirectory func(string) error
	stateUsage    func(string) (int64, error)
}

// RemoteArtifactReceipts owns the durable delivery receipts for one Recording
// repository. Prepare must complete before the sealed artifact is published.
type RemoteArtifactReceipts struct {
	store   *remoteArtifactReceiptStore
	targets *RemoteArtifactTargets
}

// RemoteArtifactRetentionCandidate identifies a fully acknowledged artifact
// whose signed receipt permits retention cleanup.
type RemoteArtifactRetentionCandidate struct {
	FileName           string
	ArtifactDigest     ArtifactDigest
	Size               int64
	RetentionStartedAt time.Time
	DeletionStarted    bool
}

func newRemoteArtifactReceipt(identity *Identity, auditlog configuration.AuditlogName, artifact RemoteArtifact, sealedAt time.Time, targets *RemoteArtifactTargets) (remoteArtifactReceipt, []byte, error) {
	if err := validateRemoteArtifactReceiptIdentity(identity, auditlog, artifact); err != nil {
		return remoteArtifactReceipt{}, nil, err
	}
	canonicalSealedAt, err := canonicalRemoteArtifactReceiptTime(sealedAt)
	if err != nil {
		return remoteArtifactReceipt{}, nil, errors.Config.Newf("illegal remote artifact seal time: %w", err)
	}
	selected, err := snapshotRemoteArtifactReceiptTargets(auditlog, targets)
	if err != nil {
		return remoteArtifactReceipt{}, nil, err
	}
	content := remoteArtifactReceiptContent{
		Schema:         remoteArtifactReceiptSchema,
		ProducerId:     artifact.ProducerId(),
		Auditlog:       auditlog,
		FileName:       artifact.FileName(),
		ArtifactDigest: artifact.Digest(),
		Size:           artifact.Size(),
		SealedAt:       canonicalSealedAt,
		Targets:        selected,
		PublicKey:      identity.PublicKey().Marshal(),
	}
	return signRemoteArtifactReceipt(identity, content)
}

func decodeRemoteArtifactReceipt(payload []byte, identity *Identity, auditlog configuration.AuditlogName, fileName string) (remoteArtifactReceipt, error) {
	if err := validateRemoteArtifactReceiptOwner(identity, auditlog, fileName); err != nil {
		return remoteArtifactReceipt{}, err
	}
	var receipt remoteArtifactReceipt
	if err := decodeCanonicalJournalPayload(payload, &receipt); err != nil {
		return remoteArtifactReceipt{}, errors.System.Newf("cannot decode remote artifact delivery receipt: %w", err)
	}
	if receipt.Schema != remoteArtifactReceiptSchema || receipt.ProducerId != identity.ProducerId() || receipt.Auditlog != auditlog || !bytes.Equal(receipt.PublicKey, identity.journalPublicKey()) {
		return remoteArtifactReceipt{}, errors.Config.Newf("remote artifact delivery receipt belongs to a different producer or auditlog")
	}
	if receipt.FileName != fileName {
		return remoteArtifactReceipt{}, errors.Config.Newf("remote artifact delivery receipt belongs to a different artifact")
	}
	if err := validateRemoteArtifactReceiptContent(receipt.remoteArtifactReceiptContent); err != nil {
		return remoteArtifactReceipt{}, err
	}
	unsigned, err := json.Marshal(receipt.remoteArtifactReceiptContent)
	if err != nil {
		return remoteArtifactReceipt{}, errors.System.Newf("cannot re-encode remote artifact delivery receipt: %w", err)
	}
	if err := identity.verify(append([]byte(remoteArtifactReceiptSignDomain), unsigned...), receipt.Signature); err != nil {
		return remoteArtifactReceipt{}, errors.System.Newf("cannot verify remote artifact delivery receipt: %w", err)
	}
	return receipt, nil
}

func validateRemoteArtifactReceiptOwner(identity *Identity, auditlog configuration.AuditlogName, fileName string) error {
	if identity == nil || identity.ProducerId().IsZero() {
		return errors.Config.Newf("nil audit identity")
	}
	if err := auditlog.Validate(); err != nil {
		return errors.Config.Newf("illegal remote artifact receipt auditlog: %w", err)
	}
	if err := validateRemoteArtifactFileName(fileName); err != nil {
		return err
	}
	return nil
}

func bindRemoteArtifactReceipt(receipt remoteArtifactReceipt, identity *Identity, auditlog configuration.AuditlogName, artifact RemoteArtifact) error {
	if err := validateRemoteArtifactReceiptIdentity(identity, auditlog, artifact); err != nil {
		return err
	}
	if receipt.FileName != artifact.FileName() || receipt.ArtifactDigest != artifact.Digest() || receipt.Size != artifact.Size() {
		return errors.Config.Newf("remote artifact delivery receipt belongs to a different artifact")
	}
	return nil
}

func signRemoteArtifactReceipt(identity *Identity, content remoteArtifactReceiptContent) (remoteArtifactReceipt, []byte, error) {
	if identity == nil || content.ProducerId != identity.ProducerId() || !bytes.Equal(content.PublicKey, identity.journalPublicKey()) {
		return remoteArtifactReceipt{}, nil, errors.Config.Newf("remote artifact delivery receipt identity does not match its content")
	}
	var err error
	content, err = normalizeRemoteArtifactReceiptStatePadding(content)
	if err != nil {
		return remoteArtifactReceipt{}, nil, err
	}
	if err := validateRemoteArtifactReceiptContent(content); err != nil {
		return remoteArtifactReceipt{}, nil, err
	}
	unsigned, err := json.Marshal(content)
	if err != nil {
		return remoteArtifactReceipt{}, nil, errors.System.Newf("cannot encode remote artifact delivery receipt: %w", err)
	}
	signature, err := identity.sign(append([]byte(remoteArtifactReceiptSignDomain), unsigned...))
	if err != nil {
		return remoteArtifactReceipt{}, nil, err
	}
	receipt := remoteArtifactReceipt{remoteArtifactReceiptContent: content, Signature: signature}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return remoteArtifactReceipt{}, nil, errors.System.Newf("cannot encode signed remote artifact delivery receipt: %w", err)
	}
	if len(payload) > maxJournalRecordPayloadSize {
		return remoteArtifactReceipt{}, nil, errors.Config.Newf("remote artifact delivery receipt exceeds %d bytes", maxJournalRecordPayloadSize)
	}
	return receipt, payload, nil
}

func validateRemoteArtifactReceiptIdentity(identity *Identity, auditlog configuration.AuditlogName, artifact RemoteArtifact) error {
	if err := validateRemoteArtifactReceiptOwner(identity, auditlog, artifact.FileName()); err != nil {
		return err
	}
	if err := artifact.validateMetadata(context.Background()); err != nil {
		return err
	}
	if artifact.ProducerId() != identity.ProducerId() {
		return errors.Config.Newf("remote artifact producer does not match receipt identity")
	}
	return nil
}

func validateRemoteArtifactReceiptContent(content remoteArtifactReceiptContent) error {
	if content.Schema != remoteArtifactReceiptSchema || content.ProducerId.IsZero() || content.ArtifactDigest.IsZero() || content.Size <= 0 || len(content.PublicKey) == 0 {
		return errors.Config.Newf("remote artifact delivery receipt has invalid immutable content")
	}
	if err := content.Auditlog.Validate(); err != nil {
		return errors.Config.Newf("remote artifact delivery receipt has an illegal auditlog: %w", err)
	}
	if err := validateRemoteArtifactFileName(content.FileName); err != nil {
		return err
	}
	sealedAt, err := parseRemoteArtifactReceiptTime(content.SealedAt)
	if err != nil {
		return errors.Config.Newf("remote artifact delivery receipt has an illegal seal time: %w", err)
	}
	names := make(map[configuration.AuditlogTargetName]bool, len(content.Targets))
	for _, target := range content.Targets {
		if err := target.Target.Validate(); err != nil {
			return errors.Config.Newf("remote artifact delivery receipt has an illegal target: %w", err)
		}
		if names[target.Target] {
			return errors.Config.Newf("remote artifact delivery receipt contains duplicate target %q", target.Target)
		}
		names[target.Target] = true
		if target.DestinationFingerprint.IsZero() {
			return errors.Config.Newf("remote artifact delivery receipt target %q has an empty destination fingerprint", target.Target)
		}
		if err := validateRemoteArtifactReceiptTargetAudit(target, sealedAt); err != nil {
			return err
		}
	}
	normalized, err := normalizeRemoteArtifactReceiptStatePadding(content)
	if err != nil {
		return err
	}
	if normalized.StatePadding != content.StatePadding {
		return errors.Config.Newf("remote artifact delivery receipt has invalid state padding")
	}
	return nil
}

func normalizeRemoteArtifactReceiptStatePadding(content remoteArtifactReceiptContent) (remoteArtifactReceiptContent, error) {
	content.StatePadding = ""
	baseline := content
	baseline.Targets = append([]remoteArtifactReceiptTarget{}, content.Targets...)
	for index := range baseline.Targets {
		baseline.Targets[index].AcknowledgedAt = ""
		baseline.Targets[index].AuditOperationId = ""
		baseline.Targets[index].FailedAt = ""
		baseline.Targets[index].FailureErrorCategory = ""
		baseline.Targets[index].FailureAuditedAt = ""
		baseline.Targets[index].SuccessAuditedAt = ""
	}
	baselinePayload, err := json.Marshal(baseline)
	if err != nil {
		return remoteArtifactReceiptContent{}, errors.System.Newf("cannot size initial remote artifact delivery receipt: %w", err)
	}
	currentPayload, err := json.Marshal(content)
	if err != nil {
		return remoteArtifactReceiptContent{}, errors.System.Newf("cannot size remote artifact delivery receipt state: %w", err)
	}
	reserve := len(content.Targets) * remoteArtifactReceiptStateReserveBytes
	growth := len(currentPayload) - len(baselinePayload)
	if growth < 0 || growth > reserve {
		return remoteArtifactReceiptContent{}, errors.Config.Newf("remote artifact delivery receipt state exceeds its reserved size")
	}
	content.StatePadding = strings.Repeat("0", reserve-growth)
	return content, nil
}

func validateRemoteArtifactReceiptTargetAudit(target remoteArtifactReceiptTarget, sealedAt time.Time) error {
	operationId := target.AuditOperationId
	if operationId != "" {
		parsed, err := uuid.Parse(operationId)
		if err != nil || parsed == uuid.Nil || parsed.String() != operationId {
			return errors.Config.Newf("remote artifact delivery receipt target %q has an illegal audit operation ID", target.Target)
		}
	}
	parseTime := func(name, value string) (time.Time, error) {
		if value == "" {
			return time.Time{}, nil
		}
		parsed, err := parseRemoteArtifactReceiptTime(value)
		if err != nil {
			return time.Time{}, errors.Config.Newf("remote artifact delivery receipt target %q has an illegal %s time: %w", target.Target, name, err)
		}
		if parsed.Before(sealedAt) {
			return time.Time{}, errors.Config.Newf("remote artifact delivery receipt target %q has a %s time before the artifact was sealed", target.Target, name)
		}
		return parsed, nil
	}
	acknowledgedAt, err := parseTime("acknowledgement", target.AcknowledgedAt)
	if err != nil {
		return err
	}
	failedAt, err := parseTime("failure", target.FailedAt)
	if err != nil {
		return err
	}
	failureAuditedAt, err := parseTime("failure audit", target.FailureAuditedAt)
	if err != nil {
		return err
	}
	successAuditedAt, err := parseTime("success audit", target.SuccessAuditedAt)
	if err != nil {
		return err
	}
	hasAuditState := target.FailedAt != "" || target.FailureErrorCategory != "" || target.FailureAuditedAt != "" || target.SuccessAuditedAt != ""
	if hasAuditState && operationId == "" {
		return errors.Config.Newf("remote artifact delivery receipt target %q has audit state without an operation ID", target.Target)
	}
	if (target.FailedAt == "") != (target.FailureErrorCategory == "") {
		return errors.Config.Newf("remote artifact delivery receipt target %q has incomplete failure state", target.Target)
	}
	if target.FailureErrorCategory != "" && !isErrorCategory(target.FailureErrorCategory) {
		return errors.Config.Newf("remote artifact delivery receipt target %q has an illegal failure error category", target.Target)
	}
	if target.FailureAuditedAt != "" && (target.FailedAt == "" || failureAuditedAt.Before(failedAt)) {
		return errors.Config.Newf("remote artifact delivery receipt target %q has inconsistent failure audit state", target.Target)
	}
	if target.SuccessAuditedAt != "" && (target.AcknowledgedAt == "" || successAuditedAt.Before(acknowledgedAt)) {
		return errors.Config.Newf("remote artifact delivery receipt target %q has inconsistent success audit state", target.Target)
	}
	if target.AcknowledgedAt != "" && operationId == "" {
		return errors.Config.Newf("remote artifact delivery receipt target %q has an acknowledgement without an audit operation ID", target.Target)
	}
	return nil
}

func snapshotRemoteArtifactReceiptTargets(auditlog configuration.AuditlogName, targets *RemoteArtifactTargets) ([]remoteArtifactReceiptTarget, error) {
	if targets == nil {
		return []remoteArtifactReceiptTarget{}, nil
	}
	result := make([]remoteArtifactReceiptTarget, 0, len(targets.entries))
	for _, entry := range targets.entries {
		if entry.scope.Auditlog != auditlog {
			return nil, errors.Config.Newf("remote artifact target %q belongs to auditlog %q instead of %q", entry.scope.Target, entry.scope.Auditlog, auditlog)
		}
		result = append(result, remoteArtifactReceiptTarget{
			Target:                 entry.scope.Target,
			DestinationFingerprint: entry.destinationFingerprint,
		})
	}
	return result, nil
}

func acknowledgeRemoteArtifactReceipt(identity *Identity, receipt remoteArtifactReceipt, entry remoteArtifactTargetEntry, acknowledgedAt time.Time, newUUID remoteArtifactReceiptUUIDGenerator) (remoteArtifactReceipt, []byte, bool, error) {
	if entry.scope.Auditlog != receipt.Auditlog {
		return remoteArtifactReceipt{}, nil, false, errors.Config.Newf("remote artifact target %q belongs to a different auditlog", entry.scope.Target)
	}
	index := -1
	for current := range receipt.Targets {
		if receipt.Targets[current].Target == entry.scope.Target {
			index = current
			break
		}
	}
	if index < 0 {
		return remoteArtifactReceipt{}, nil, false, errors.Config.Newf("remote artifact target %q is not selected by the delivery receipt", entry.scope.Target)
	}
	if receipt.Targets[index].DestinationFingerprint != entry.destinationFingerprint || entry.destinationFingerprint.IsZero() {
		return remoteArtifactReceipt{}, nil, false, errors.Config.Newf("remote artifact target %q uses a different destination than the delivery receipt", entry.scope.Target)
	}
	if receipt.Targets[index].AcknowledgedAt != "" {
		payload, err := json.Marshal(receipt)
		return receipt, payload, false, err
	}
	sealedAt, err := parseRemoteArtifactReceiptTime(receipt.SealedAt)
	if err != nil {
		return remoteArtifactReceipt{}, nil, false, err
	}
	if acknowledgedAt.Before(sealedAt) {
		acknowledgedAt = sealedAt
	}
	canonicalAcknowledgedAt, err := canonicalRemoteArtifactReceiptTime(acknowledgedAt)
	if err != nil {
		return remoteArtifactReceipt{}, nil, false, err
	}
	content := receipt.remoteArtifactReceiptContent
	content.Targets = append([]remoteArtifactReceiptTarget(nil), receipt.Targets...)
	content.Targets[index].AcknowledgedAt = canonicalAcknowledgedAt
	if content.Targets[index].AuditOperationId == "" {
		content.Targets[index].AuditOperationId, err = newRemoteArtifactDeliveryAuditOperationId(newUUID)
		if err != nil {
			return remoteArtifactReceipt{}, nil, false, err
		}
	}
	updated, payload, err := signRemoteArtifactReceipt(identity, content)
	return updated, payload, err == nil, err
}

func newRemoteArtifactDeliveryAuditOperationId(newUUID remoteArtifactReceiptUUIDGenerator) (string, error) {
	value, err := newUUID()
	if err != nil {
		return "", errors.System.Newf("cannot generate remote artifact delivery audit operation ID: %w", err)
	}
	return value.String(), nil
}

func (this remoteArtifactReceipt) retentionStartedAt() (time.Time, bool) {
	latest, err := parseRemoteArtifactReceiptTime(this.SealedAt)
	if err != nil {
		return time.Time{}, false
	}
	for _, target := range this.Targets {
		if target.AcknowledgedAt == "" || target.SuccessAuditedAt == "" {
			return time.Time{}, false
		}
		acknowledgedAt, err := parseRemoteArtifactReceiptTime(target.AcknowledgedAt)
		if err != nil {
			return time.Time{}, false
		}
		if acknowledgedAt.After(latest) {
			latest = acknowledgedAt
		}
	}
	return latest, true
}

func canonicalRemoteArtifactReceiptTime(value time.Time) (string, error) {
	if value.IsZero() {
		return "", errors.Config.Newf("time is empty")
	}
	return value.UTC().Format(time.RFC3339Nano), nil
}

func parseRemoteArtifactReceiptTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	if parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.Config.Newf("time is not canonical UTC RFC3339")
	}
	return parsed, nil
}

func newRemoteArtifactReceiptStore(recordingDirectory string, identity *Identity, auditlog configuration.AuditlogName, quota RemoteArtifactReceiptQuota) (*remoteArtifactReceiptStore, error) {
	if identity == nil || identity.ProducerId().IsZero() {
		return nil, errors.Config.Newf("nil audit identity")
	}
	if err := auditlog.Validate(); err != nil {
		return nil, errors.Config.Newf("illegal remote artifact receipt auditlog: %w", err)
	}
	producerDirectory, stateLock, err := prepareRemoteArtifactReceiptState(recordingDirectory, identity.ProducerId())
	if err != nil {
		return nil, err
	}
	mutex := make(chan struct{}, 1)
	mutex <- struct{}{}
	return &remoteArtifactReceiptStore{mutex: mutex, producerDirectory: producerDirectory, identity: identity, auditlog: auditlog, quota: ensureRemoteArtifactReceiptQuotaInvalidation(quota), newUUID: uuid.NewRandom, stateLock: stateLock}, nil
}

func NewRemoteArtifactReceipts(recordingDirectory string, identity *Identity, auditlog configuration.AuditlogName, targets *RemoteArtifactTargets, quota RemoteArtifactReceiptQuota) (*RemoteArtifactReceipts, error) {
	if quota == nil {
		return nil, errors.Config.Newf("nil remote artifact receipt quota")
	}
	store, err := newRemoteArtifactReceiptStore(recordingDirectory, identity, auditlog, quota)
	if err != nil {
		return nil, err
	}
	return &RemoteArtifactReceipts{store: store, targets: targets}, nil
}

func (this *RemoteArtifactReceipts) Prepare(ctx context.Context, artifact RemoteArtifact, sealedAt time.Time) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := this.store.initializeContext(ctx, artifact, sealedAt, this.targets)
	return err
}

func (this *RemoteArtifactReceipts) Require(ctx context.Context, artifact RemoteArtifact) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, exists, err := this.store.loadContext(ctx, artifact)
	if err != nil {
		return err
	}
	if !exists {
		return errors.Config.Newf("remote artifact delivery receipt for %q is missing", artifact.FileName())
	}
	return nil
}

// Recover validates and completes interrupted receipt replacements before the
// recording repository performs operations that may need spool capacity.
func (this *RemoteArtifactReceipts) Recover(ctx context.Context) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.recover(ctx)
}

// ListRetentionCandidates returns fully acknowledged artifacts whose retention
// start is at or before the supplied cutoff.
func (this *RemoteArtifactReceipts) ListRetentionCandidates(ctx context.Context, cutoff time.Time) ([]RemoteArtifactRetentionCandidate, error) {
	if this == nil || this.store == nil {
		return nil, errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.listRetentionCandidates(ctx, cutoff)
}

// MarkRetentionDeleting durably records that the matching artifact was
// verified and retention deletion has started.
func (this *RemoteArtifactReceipts) MarkRetentionDeleting(ctx context.Context, candidate RemoteArtifactRetentionCandidate, cutoff time.Time) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.markRetentionDeleting(ctx, candidate, cutoff)
}

// RemoveRetentionCandidate removes the durable receipt after its artifact has
// already been removed. The signed receipt is revalidated under the store lock.
func (this *RemoteArtifactReceipts) RemoveRetentionCandidate(ctx context.Context, candidate RemoteArtifactRetentionCandidate, cutoff time.Time) error {
	if this == nil || this.store == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	return this.store.removeRetentionCandidate(ctx, candidate, cutoff)
}

func (this *RemoteArtifactReceipts) Acknowledge(ctx context.Context, artifact RemoteArtifact, target configuration.AuditlogTargetName, acknowledgedAt time.Time) error {
	if this == nil || this.store == nil || this.targets == nil {
		return errors.System.Newf("nil remote artifact receipts")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, entry := range this.targets.entries {
		if entry.scope.Target == target {
			_, err := this.store.acknowledge(ctx, artifact, entry, acknowledgedAt)
			return err
		}
	}
	return errors.Config.Newf("remote artifact target %q is not configured for auditlog %q", target, this.store.auditlog)
}

func (this *RemoteArtifactReceipts) Close() error {
	if this == nil || this.store == nil {
		return nil
	}
	return this.store.close()
}

func (this *remoteArtifactReceiptStore) initialize(artifact RemoteArtifact, sealedAt time.Time, targets *RemoteArtifactTargets) (remoteArtifactReceipt, error) {
	return this.initializeContext(context.Background(), artifact, sealedAt, targets)
}

func (this *remoteArtifactReceiptStore) initializeContext(ctx context.Context, artifact RemoteArtifact, sealedAt time.Time, targets *RemoteArtifactTargets) (remoteArtifactReceipt, error) {
	if this == nil {
		return remoteArtifactReceipt{}, errors.System.Newf("nil remote artifact receipt store")
	}
	if err := this.lock(ctx); err != nil {
		return remoteArtifactReceipt{}, err
	}
	defer this.unlock()
	if this.closed {
		return remoteArtifactReceipt{}, errors.System.Newf("remote artifact receipt store is closed")
	}
	existing, exists, err := this.loadLocked(artifact)
	if err != nil {
		return remoteArtifactReceipt{}, err
	}
	if exists {
		return existing, nil
	}
	desired, payload, err := newRemoteArtifactReceipt(this.identity, this.auditlog, artifact, sealedAt, targets)
	if err != nil {
		return remoteArtifactReceipt{}, err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	if err := writeRemoteArtifactReceipt(directory, artifact.FileName(), payload, this.quota); err != nil {
		return remoteArtifactReceipt{}, err
	}
	return desired, nil
}

func (this *remoteArtifactReceiptStore) close() error {
	if this == nil {
		return nil
	}
	if err := this.lock(context.Background()); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return this.closeErr
	}
	this.closed = true
	this.closeErr = this.stateLock.Close()
	return this.closeErr
}

func (this *remoteArtifactReceiptStore) load(artifact RemoteArtifact) (remoteArtifactReceipt, bool, error) {
	return this.loadContext(context.Background(), artifact)
}

func (this *remoteArtifactReceiptStore) loadContext(ctx context.Context, artifact RemoteArtifact) (remoteArtifactReceipt, bool, error) {
	if this == nil {
		return remoteArtifactReceipt{}, false, errors.System.Newf("nil remote artifact receipt store")
	}
	if err := this.lock(ctx); err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	defer this.unlock()
	if this.closed {
		return remoteArtifactReceipt{}, false, errors.System.Newf("remote artifact receipt store is closed")
	}
	return this.loadLocked(artifact)
}

func (this *remoteArtifactReceiptStore) recover(ctx context.Context) error {
	if this == nil {
		return errors.System.Newf("nil remote artifact receipt store")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	entries, err := os.ReadDir(this.producerDirectory)
	if err != nil {
		return errors.System.Newf("cannot inspect remote artifact delivery receipt state: %w", err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		directory := filepath.Join(this.producerDirectory, entry.Name())
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !isRemoteArtifactReceiptStateName(entry.Name()) {
			return errors.Config.Newf("remote artifact delivery receipt state contains unsupported entry %q", entry.Name())
		}
		if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
			return cleanupRemoteArtifactReceiptTombstones(directory)
		}); err != nil {
			return err
		}
		if err := cleanupMalformedRemoteArtifactReceiptTemporaries(directory, this.quota); err != nil {
			return err
		}
		fileName, exists, err := remoteArtifactReceiptStateFileName(directory)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if remoteArtifactReceiptStateName(fileName) != entry.Name() {
			return errors.Config.Newf("remote artifact delivery receipt state %q does not match its artifact", directory)
		}
		if _, exists, err := this.loadSnapshotLocked(fileName, nil); err != nil {
			return err
		} else if !exists {
			return errors.Config.Newf("remote artifact delivery receipt for %q is missing", fileName)
		}
	}
	return nil
}

func (this *remoteArtifactReceiptStore) listRetentionCandidates(ctx context.Context, cutoff time.Time) ([]RemoteArtifactRetentionCandidate, error) {
	if this == nil {
		return nil, errors.System.Newf("nil remote artifact receipt store")
	}
	if ctx == nil {
		ctx = context.Background()
	}
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
	result := make([]RemoteArtifactRetentionCandidate, 0, len(fileNames))
	for _, fileName := range fileNames {
		receipt, exists, err := this.loadSnapshotLocked(fileName, nil)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, errors.Config.Newf("remote artifact delivery receipt for %q is missing", fileName)
		}
		directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(fileName))
		deletionStarted, err := remoteArtifactReceiptRetentionDeleting(directory)
		if err != nil {
			return nil, err
		}
		startedAt, ready := receipt.retentionStartedAt()
		if !ready || !deletionStarted && (cutoff.IsZero() || startedAt.After(cutoff)) {
			continue
		}
		result = append(result, RemoteArtifactRetentionCandidate{
			FileName:           receipt.FileName,
			ArtifactDigest:     receipt.ArtifactDigest,
			Size:               receipt.Size,
			RetentionStartedAt: startedAt,
			DeletionStarted:    deletionStarted,
		})
	}
	return result, nil
}

func (this *remoteArtifactReceiptStore) markRetentionDeleting(ctx context.Context, candidate RemoteArtifactRetentionCandidate, cutoff time.Time) error {
	if this == nil {
		return errors.System.Newf("nil remote artifact receipt store")
	}
	if err := validateRemoteArtifactRetentionCandidate(candidate, cutoff); err != nil {
		return err
	}
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, exists, err := this.loadSnapshotLocked(candidate.FileName, nil)
	if err != nil {
		return err
	}
	if !exists {
		return errors.Config.Newf("remote artifact delivery receipt for %q is missing", candidate.FileName)
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(candidate.FileName))
	deletionStarted, err := remoteArtifactReceiptRetentionDeleting(directory)
	if err != nil {
		return err
	}
	candidate.DeletionStarted = deletionStarted
	if !deletionStarted && cutoff.IsZero() {
		return errors.Config.Newf("remote artifact retention cutoff is empty")
	}
	if err := validateRemoteArtifactRetentionReceipt(receipt, candidate, cutoff); err != nil {
		return err
	}
	if deletionStarted {
		if err := syncJournalDirectory(directory); err != nil {
			return errors.System.Newf("cannot flush remote artifact %q retention deletion marker: %w", candidate.FileName, err)
		}
		return nil
	}
	source := filepath.Join(directory, remoteArtifactReceiptFileName)
	target := filepath.Join(directory, remoteArtifactReceiptRetentionFileName)
	if err := replaceJournalFile(source, target); err != nil {
		return errors.System.Newf("cannot mark remote artifact %q for retention deletion: %w", candidate.FileName, err)
	}
	if err := syncJournalDirectory(directory); err != nil {
		return errors.System.Newf("cannot flush remote artifact %q retention deletion marker: %w", candidate.FileName, err)
	}
	return nil
}

func (this *remoteArtifactReceiptStore) removeRetentionCandidate(ctx context.Context, candidate RemoteArtifactRetentionCandidate, cutoff time.Time) error {
	if this == nil {
		return errors.System.Newf("nil remote artifact receipt store")
	}
	if err := validateRemoteArtifactRetentionCandidate(candidate, cutoff); err != nil {
		return err
	}
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, exists, err := this.loadSnapshotLocked(candidate.FileName, nil)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if err := validateRemoteArtifactRetentionReceipt(receipt, candidate, cutoff); err != nil {
		return err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(candidate.FileName))
	deletionStarted, err := remoteArtifactReceiptRetentionDeleting(directory)
	if err != nil {
		return err
	}
	if !candidate.DeletionStarted || !deletionStarted {
		return errors.Config.Newf("remote artifact %q has not started retention deletion", candidate.FileName)
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return errors.System.Newf("cannot encode remote artifact delivery receipt for retention cleanup: %w", err)
	}
	before, err := remoteArtifactReceiptStateUsage(directory)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, remoteArtifactReceiptRetentionFileName)
	if err := removeRemoteArtifactReceiptFile(path, directory); err != nil {
		restoreErr := restoreRemoteArtifactReceiptFile(path, directory, payload)
		if restoreErr == nil {
			return err
		}
		return goerrors.Join(err, restoreErr, this.reconcileFailedRemoteArtifactReceiptRestore(directory, before))
	}
	var quotaErr error
	if this.quota != nil {
		quotaErr = this.quota.Reconcile(0, before, 0)
	}
	if err := os.Remove(directory); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return goerrors.Join(quotaErr, errors.System.Newf("cannot remove remote artifact delivery receipt state %q: %w", directory, err))
	}
	if err := syncJournalDirectory(this.producerDirectory); err != nil {
		return goerrors.Join(quotaErr, errors.System.Newf("cannot flush remote artifact delivery receipt cleanup: %w", err))
	}
	return quotaErr
}

func (this *remoteArtifactReceiptStore) reconcileFailedRemoteArtifactReceiptRestore(directory string, before int64) error {
	return this.reconcileFailedRemoteArtifactReceiptRestoreWithStateUsage(directory, before, remoteArtifactReceiptStateUsage)
}

func (this *remoteArtifactReceiptStore) reconcileFailedRemoteArtifactReceiptRestoreWithStateUsage(directory string, before int64, stateUsage func(string) (int64, error)) error {
	after, usageErr := stateUsage(directory)
	if usageErr != nil {
		invalidateRemoteArtifactReceiptQuota(this.quota, usageErr)
		return usageErr
	}
	var quotaErr error
	if this.quota != nil {
		quotaErr = this.quota.Reconcile(0, before, after)
	}
	if after != 0 {
		return quotaErr
	}
	removeErr := os.Remove(directory)
	if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
		removeErr = errors.System.Newf("cannot remove empty remote artifact delivery receipt state %q: %w", directory, removeErr)
	}
	syncErr := syncJournalDirectory(this.producerDirectory)
	if syncErr != nil {
		syncErr = errors.System.Newf("cannot flush empty remote artifact delivery receipt cleanup: %w", syncErr)
	}
	return goerrors.Join(quotaErr, removeErr, syncErr)
}

func validateRemoteArtifactRetentionCandidate(candidate RemoteArtifactRetentionCandidate, cutoff time.Time) error {
	if err := validateRemoteArtifactFileName(candidate.FileName); err != nil || candidate.ArtifactDigest.IsZero() || candidate.Size <= 0 || candidate.RetentionStartedAt.IsZero() {
		return errors.Config.Newf("invalid remote artifact retention candidate")
	}
	return nil
}

func validateRemoteArtifactRetentionReceipt(receipt remoteArtifactReceipt, candidate RemoteArtifactRetentionCandidate, cutoff time.Time) error {
	startedAt, ready := receipt.retentionStartedAt()
	if !ready || !candidate.DeletionStarted && (cutoff.IsZero() || startedAt.After(cutoff)) || receipt.ArtifactDigest != candidate.ArtifactDigest || receipt.Size != candidate.Size || !startedAt.Equal(candidate.RetentionStartedAt) {
		return errors.Config.Newf("remote artifact %q is no longer eligible for retention cleanup", candidate.FileName)
	}
	return nil
}

func (this *remoteArtifactReceiptStore) stateFileNamesLocked(ctx context.Context) ([]string, error) {
	entries, err := os.ReadDir(this.producerDirectory)
	if err != nil {
		return nil, errors.System.Newf("cannot inspect remote artifact delivery receipt state: %w", err)
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		directory := filepath.Join(this.producerDirectory, entry.Name())
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !isRemoteArtifactReceiptStateName(entry.Name()) {
			return nil, errors.Config.Newf("remote artifact delivery receipt state contains unsupported entry %q", entry.Name())
		}
		if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
			return cleanupRemoteArtifactReceiptTombstones(directory)
		}); err != nil {
			return nil, err
		}
		if err := cleanupMalformedRemoteArtifactReceiptTemporaries(directory, this.quota); err != nil {
			return nil, err
		}
		fileName, exists, err := remoteArtifactReceiptStateFileName(directory)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		if remoteArtifactReceiptStateName(fileName) != entry.Name() {
			return nil, errors.Config.Newf("remote artifact delivery receipt state %q does not match its artifact", directory)
		}
		result = append(result, fileName)
	}
	sort.Strings(result)
	return result, nil
}

func (this *remoteArtifactReceiptStore) targetStatus(ctx context.Context, fileName string, entry remoteArtifactTargetEntry) (remoteArtifactReceiptTargetStatus, error) {
	if this == nil {
		return remoteArtifactReceiptTargetNotSelected, errors.System.Newf("nil remote artifact receipt store")
	}
	if err := this.lock(ctx); err != nil {
		return remoteArtifactReceiptTargetNotSelected, err
	}
	defer this.unlock()
	if this.closed {
		return remoteArtifactReceiptTargetNotSelected, errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, exists, err := this.loadSnapshotLocked(fileName, nil)
	if err != nil {
		return remoteArtifactReceiptTargetNotSelected, err
	}
	if !exists {
		return remoteArtifactReceiptTargetNotSelected, errors.Config.Newf("remote artifact delivery receipt for %q is missing", fileName)
	}
	return remoteArtifactReceiptStatus(receipt, entry)
}

func (this *remoteArtifactReceiptStore) targetStatusForArtifact(ctx context.Context, artifact RemoteArtifact, entry remoteArtifactTargetEntry) (remoteArtifactReceiptTargetStatus, error) {
	if this == nil {
		return remoteArtifactReceiptTargetNotSelected, errors.System.Newf("nil remote artifact receipt store")
	}
	if err := this.lock(ctx); err != nil {
		return remoteArtifactReceiptTargetNotSelected, err
	}
	defer this.unlock()
	if this.closed {
		return remoteArtifactReceiptTargetNotSelected, errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, exists, err := this.loadLocked(artifact)
	if err != nil {
		return remoteArtifactReceiptTargetNotSelected, err
	}
	if !exists {
		return remoteArtifactReceiptTargetNotSelected, errors.Config.Newf("remote artifact delivery receipt for %q is missing", artifact.FileName())
	}
	return remoteArtifactReceiptStatus(receipt, entry)
}

func remoteArtifactReceiptStatus(receipt remoteArtifactReceipt, entry remoteArtifactTargetEntry) (remoteArtifactReceiptTargetStatus, error) {
	for _, target := range receipt.Targets {
		if target.Target != entry.scope.Target {
			continue
		}
		if entry.scope.Auditlog != receipt.Auditlog {
			return remoteArtifactReceiptTargetNotSelected, errors.Config.Newf("remote artifact target %q belongs to a different auditlog", entry.scope.Target)
		}
		if target.AcknowledgedAt != "" && target.SuccessAuditedAt != "" {
			return remoteArtifactReceiptTargetAcknowledged, nil
		}
		if entry.destinationFingerprint.IsZero() || target.DestinationFingerprint != entry.destinationFingerprint {
			return remoteArtifactReceiptTargetNotSelected, errors.Config.Newf("remote artifact target %q uses a different destination than the delivery receipt", entry.scope.Target)
		}
		if target.FailedAt != "" && target.FailureAuditedAt == "" {
			return remoteArtifactReceiptTargetFailureAuditPending, nil
		}
		if target.AcknowledgedAt != "" {
			return remoteArtifactReceiptTargetSuccessAuditPending, nil
		}
		return remoteArtifactReceiptTargetPending, nil
	}
	return remoteArtifactReceiptTargetNotSelected, nil
}

func (this *remoteArtifactReceiptStore) beginDeliveryFailure(ctx context.Context, fileName string, entry remoteArtifactTargetEntry, category ErrorCategory, failedAt time.Time) (RemoteArtifactDeliveryAuditEvent, bool, error) {
	if this == nil {
		return RemoteArtifactDeliveryAuditEvent{}, false, errors.System.Newf("nil remote artifact receipt store")
	}
	if !isErrorCategory(category) {
		return RemoteArtifactDeliveryAuditEvent{}, false, errors.Config.Newf("illegal remote artifact delivery error category %q", category)
	}
	if err := this.lock(ctx); err != nil {
		return RemoteArtifactDeliveryAuditEvent{}, false, err
	}
	defer this.unlock()
	if this.closed {
		return RemoteArtifactDeliveryAuditEvent{}, false, errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, exists, err := this.loadSnapshotLocked(fileName, nil)
	if err != nil {
		return RemoteArtifactDeliveryAuditEvent{}, false, err
	}
	if !exists {
		return RemoteArtifactDeliveryAuditEvent{}, false, errors.Config.Newf("remote artifact delivery receipt for %q is missing", fileName)
	}
	index, err := remoteArtifactReceiptTargetIndex(receipt, entry)
	if err != nil {
		return RemoteArtifactDeliveryAuditEvent{}, false, err
	}
	target := receipt.Targets[index]
	if target.AcknowledgedAt != "" || target.FailureAuditedAt != "" {
		return RemoteArtifactDeliveryAuditEvent{}, false, nil
	}
	if target.FailedAt == "" {
		sealedAt, err := parseRemoteArtifactReceiptTime(receipt.SealedAt)
		if err != nil {
			return RemoteArtifactDeliveryAuditEvent{}, false, err
		}
		if failedAt.Before(sealedAt) {
			failedAt = sealedAt
		}
		canonicalFailedAt, err := canonicalRemoteArtifactReceiptTime(failedAt)
		if err != nil {
			return RemoteArtifactDeliveryAuditEvent{}, false, err
		}
		content := receipt.remoteArtifactReceiptContent
		content.Targets = append([]remoteArtifactReceiptTarget(nil), receipt.Targets...)
		if content.Targets[index].AuditOperationId == "" {
			content.Targets[index].AuditOperationId, err = newRemoteArtifactDeliveryAuditOperationId(this.newUUID)
			if err != nil {
				return RemoteArtifactDeliveryAuditEvent{}, false, err
			}
		}
		content.Targets[index].FailedAt = canonicalFailedAt
		content.Targets[index].FailureErrorCategory = category
		receipt, err = this.replaceDeliveryReceiptLocked(fileName, content)
		if err != nil {
			return RemoteArtifactDeliveryAuditEvent{}, false, err
		}
		target = receipt.Targets[index]
	}
	return newRemoteArtifactDeliveryAuditEvent(receipt, target, RemoteArtifactDeliveryAuditFailed), true, nil
}

func (this *remoteArtifactReceiptStore) pendingDeliveryAudit(ctx context.Context, fileName string, entry remoteArtifactTargetEntry) (RemoteArtifactDeliveryAuditEvent, bool, error) {
	if this == nil {
		return RemoteArtifactDeliveryAuditEvent{}, false, errors.System.Newf("nil remote artifact receipt store")
	}
	if err := this.lock(ctx); err != nil {
		return RemoteArtifactDeliveryAuditEvent{}, false, err
	}
	defer this.unlock()
	if this.closed {
		return RemoteArtifactDeliveryAuditEvent{}, false, errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, exists, err := this.loadSnapshotLocked(fileName, nil)
	if err != nil {
		return RemoteArtifactDeliveryAuditEvent{}, false, err
	}
	if !exists {
		return RemoteArtifactDeliveryAuditEvent{}, false, errors.Config.Newf("remote artifact delivery receipt for %q is missing", fileName)
	}
	index, err := remoteArtifactReceiptTargetIndex(receipt, entry)
	if err != nil {
		return RemoteArtifactDeliveryAuditEvent{}, false, err
	}
	target := receipt.Targets[index]
	switch {
	case target.FailedAt != "" && target.FailureAuditedAt == "":
		return newRemoteArtifactDeliveryAuditEvent(receipt, target, RemoteArtifactDeliveryAuditFailed), true, nil
	case target.AcknowledgedAt != "" && target.AuditOperationId != "" && target.SuccessAuditedAt == "":
		return newRemoteArtifactDeliveryAuditEvent(receipt, target, RemoteArtifactDeliveryAuditSucceeded), true, nil
	default:
		return RemoteArtifactDeliveryAuditEvent{}, false, nil
	}
}

func (this *remoteArtifactReceiptStore) completeDeliveryAudit(ctx context.Context, event RemoteArtifactDeliveryAuditEvent, auditedAt time.Time) error {
	if this == nil {
		return errors.System.Newf("nil remote artifact receipt store")
	}
	if err := this.lock(ctx); err != nil {
		return err
	}
	defer this.unlock()
	if this.closed {
		return errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, exists, err := this.loadSnapshotLocked(event.FileName, nil)
	if err != nil {
		return err
	}
	if !exists {
		return errors.Config.Newf("remote artifact delivery receipt for %q is missing", event.FileName)
	}
	entry := remoteArtifactTargetEntry{scope: event.Scope, destinationFingerprint: event.destinationFingerprint}
	index, err := remoteArtifactReceiptTargetIndex(receipt, entry)
	if err != nil {
		return err
	}
	target := receipt.Targets[index]
	if target.AuditOperationId != event.OperationId {
		return errors.Config.Newf("remote artifact delivery audit operation for target %q changed", event.Scope.Target)
	}
	var occurredAt time.Time
	switch event.State {
	case RemoteArtifactDeliveryAuditFailed:
		if target.FailedAt == "" || target.FailureErrorCategory != event.ErrorCategory {
			return errors.Config.Newf("remote artifact delivery failure audit for target %q does not match its receipt", event.Scope.Target)
		}
		if target.FailureAuditedAt != "" {
			return nil
		}
		occurredAt, err = parseRemoteArtifactReceiptTime(target.FailedAt)
	case RemoteArtifactDeliveryAuditSucceeded:
		if target.AcknowledgedAt == "" {
			return errors.Config.Newf("remote artifact delivery success audit for target %q precedes its acknowledgement", event.Scope.Target)
		}
		if target.SuccessAuditedAt != "" {
			return nil
		}
		occurredAt, err = parseRemoteArtifactReceiptTime(target.AcknowledgedAt)
	default:
		return errors.Config.Newf("illegal remote artifact delivery audit state %q", event.State)
	}
	if err != nil {
		return err
	}
	if auditedAt.Before(occurredAt) {
		auditedAt = occurredAt
	}
	canonicalAuditedAt, err := canonicalRemoteArtifactReceiptTime(auditedAt)
	if err != nil {
		return err
	}
	content := receipt.remoteArtifactReceiptContent
	content.Targets = append([]remoteArtifactReceiptTarget(nil), receipt.Targets...)
	if event.State == RemoteArtifactDeliveryAuditFailed {
		content.Targets[index].FailureAuditedAt = canonicalAuditedAt
	} else {
		content.Targets[index].SuccessAuditedAt = canonicalAuditedAt
	}
	_, err = this.replaceDeliveryReceiptLocked(event.FileName, content)
	return err
}

func remoteArtifactReceiptTargetIndex(receipt remoteArtifactReceipt, entry remoteArtifactTargetEntry) (int, error) {
	if entry.scope.Auditlog != receipt.Auditlog {
		return -1, errors.Config.Newf("remote artifact target %q belongs to a different auditlog", entry.scope.Target)
	}
	for index, target := range receipt.Targets {
		if target.Target != entry.scope.Target {
			continue
		}
		if entry.destinationFingerprint.IsZero() || target.DestinationFingerprint != entry.destinationFingerprint {
			return -1, errors.Config.Newf("remote artifact target %q uses a different destination than the delivery receipt", entry.scope.Target)
		}
		return index, nil
	}
	return -1, errors.Config.Newf("remote artifact target %q is not selected by the delivery receipt", entry.scope.Target)
}

func (this *remoteArtifactReceiptStore) replaceDeliveryReceiptLocked(fileName string, content remoteArtifactReceiptContent) (remoteArtifactReceipt, error) {
	updated, payload, err := signRemoteArtifactReceipt(this.identity, content)
	if err != nil {
		return remoteArtifactReceipt{}, err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(fileName))
	if err := writeRemoteArtifactReceipt(directory, fileName, payload, this.quota); err != nil {
		return remoteArtifactReceipt{}, err
	}
	return updated, nil
}

func (this *remoteArtifactReceiptStore) deliveryTargets(ctx context.Context, fileName string) ([]remoteArtifactReceiptTarget, error) {
	if this == nil {
		return nil, errors.System.Newf("nil remote artifact receipt store")
	}
	if err := this.lock(ctx); err != nil {
		return nil, err
	}
	defer this.unlock()
	if this.closed {
		return nil, errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, exists, err := this.loadSnapshotLocked(fileName, nil)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.Config.Newf("remote artifact delivery receipt for %q is missing", fileName)
	}
	return append([]remoteArtifactReceiptTarget(nil), receipt.Targets...), nil
}

func (this *remoteArtifactReceiptStore) acknowledge(ctx context.Context, artifact RemoteArtifact, entry remoteArtifactTargetEntry, acknowledgedAt time.Time) (remoteArtifactReceipt, error) {
	if this == nil {
		return remoteArtifactReceipt{}, errors.System.Newf("nil remote artifact receipt store")
	}
	if err := this.lock(ctx); err != nil {
		return remoteArtifactReceipt{}, err
	}
	defer this.unlock()
	if this.closed {
		return remoteArtifactReceipt{}, errors.System.Newf("remote artifact receipt store is closed")
	}
	receipt, exists, err := this.loadLocked(artifact)
	if err != nil {
		return remoteArtifactReceipt{}, err
	}
	if !exists {
		return remoteArtifactReceipt{}, errors.System.Newf("remote artifact delivery receipt for %q is missing", artifact.FileName())
	}
	updated, payload, changed, err := acknowledgeRemoteArtifactReceipt(this.identity, receipt, entry, acknowledgedAt, this.newUUID)
	if err != nil || !changed {
		return updated, err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	if err := writeRemoteArtifactReceipt(directory, artifact.FileName(), payload, this.quota); err != nil {
		return remoteArtifactReceipt{}, err
	}
	return updated, nil
}

func (this *remoteArtifactReceiptStore) lock(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-this.mutex:
	}
	if err := ctx.Err(); err != nil {
		this.unlock()
		return err
	}
	return nil
}

func (this *remoteArtifactReceiptStore) unlock() {
	this.mutex <- struct{}{}
}

func (this *remoteArtifactReceiptStore) loadLocked(artifact RemoteArtifact) (remoteArtifactReceipt, bool, error) {
	if err := validateRemoteArtifactReceiptIdentity(this.identity, this.auditlog, artifact); err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	return this.loadSnapshotLocked(artifact.FileName(), func(receipt remoteArtifactReceipt) error {
		return bindRemoteArtifactReceipt(receipt, this.identity, this.auditlog, artifact)
	})
}

func (this *remoteArtifactReceiptStore) loadSnapshotLocked(fileName string, bind func(remoteArtifactReceipt) error) (remoteArtifactReceipt, bool, error) {
	if err := validateRemoteArtifactReceiptOwner(this.identity, this.auditlog, fileName); err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(fileName))
	if err := ensureRemoteArtifactReceiptDirectory(directory); err != nil {
		return remoteArtifactReceipt{}, false, errors.System.Newf("cannot prepare delivery receipt state for remote artifact %q: %w", fileName, err)
	}
	if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
		return cleanupRemoteArtifactReceiptTombstones(directory)
	}); err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	if err := validateRemoteArtifactReceiptState(directory); err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	targetPath := filepath.Join(directory, remoteArtifactReceiptFileName)
	retentionPath := filepath.Join(directory, remoteArtifactReceiptRetentionFileName)
	temporaryPath := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	receipt, payload, exists, err := readRemoteArtifactReceipt(targetPath, this.identity, this.auditlog, fileName)
	if err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	retentionReceipt, retentionPayload, retentionExists, err := readRemoteArtifactReceipt(retentionPath, this.identity, this.auditlog, fileName)
	if err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	if exists && retentionExists {
		return remoteArtifactReceipt{}, false, errors.Config.Newf("remote artifact delivery receipt for %q has conflicting retention state", fileName)
	}
	retentionTemporaryPath := filepath.Join(directory, remoteArtifactReceiptRetentionTempName)
	retentionTemporary, retentionTemporaryPayload, retentionTemporaryExists, err := this.readTemporaryLocked(directory, retentionTemporaryPath, fileName)
	if err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	if retentionTemporaryExists && bind != nil {
		if err := bind(retentionTemporary); err != nil {
			return remoteArtifactReceipt{}, false, err
		}
	}
	if retentionTemporaryExists {
		if exists || retentionExists {
			publishedPayload := payload
			if retentionExists {
				publishedPayload = retentionPayload
			}
			if !bytes.Equal(publishedPayload, retentionTemporaryPayload) {
				return remoteArtifactReceipt{}, false, errors.System.Newf("temporary remote artifact retention receipt for %q conflicts with its published receipt", fileName)
			}
			if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
				return removeRemoteArtifactReceiptFile(retentionTemporaryPath, directory)
			}); err != nil {
				return remoteArtifactReceipt{}, false, err
			}
		} else {
			if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
				if err := replaceJournalFile(retentionTemporaryPath, retentionPath); err != nil {
					return errors.System.Newf("cannot recover remote artifact retention receipt for %q: %w", fileName, err)
				}
				return syncJournalDirectory(directory)
			}); err != nil {
				return remoteArtifactReceipt{}, false, err
			}
			retentionReceipt, retentionPayload, retentionExists = retentionTemporary, retentionTemporaryPayload, true
		}
	}
	if retentionExists {
		targetPath = retentionPath
		receipt, payload, exists = retentionReceipt, retentionPayload, true
	}
	if exists && bind != nil {
		if err := bind(receipt); err != nil {
			return remoteArtifactReceipt{}, false, err
		}
	}
	temporary, temporaryPayload, temporaryExists, temporaryErr := this.readTemporaryLocked(directory, temporaryPath, fileName)
	if temporaryErr != nil {
		return remoteArtifactReceipt{}, false, temporaryErr
	}
	if temporaryExists && bind != nil {
		if err := bind(temporary); err != nil {
			return remoteArtifactReceipt{}, false, err
		}
	}
	if !temporaryExists {
		return receipt, exists, nil
	}
	if exists {
		if bytes.Equal(payload, temporaryPayload) {
			if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
				return removeRemoteArtifactReceiptFile(temporaryPath, directory)
			}); err != nil {
				return remoteArtifactReceipt{}, false, err
			}
			return receipt, true, nil
		}
		if !isRemoteArtifactReceiptSuccessor(receipt, temporary) {
			return remoteArtifactReceipt{}, false, errors.System.Newf("temporary remote artifact delivery receipt for %q conflicts with its published receipt", fileName)
		}
	}
	if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
		if err := replaceJournalFile(temporaryPath, targetPath); err != nil {
			return errors.System.Newf("cannot recover remote artifact delivery receipt for %q: %w", fileName, err)
		}
		if err := syncJournalDirectory(directory); err != nil {
			return errors.System.Newf("cannot flush recovered remote artifact delivery receipt for %q: %w", fileName, err)
		}
		return nil
	}); err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	return temporary, true, nil
}

func (this *remoteArtifactReceiptStore) readTemporaryLocked(directory, path, fileName string) (remoteArtifactReceipt, []byte, bool, error) {
	payload, exists, err := readRemoteArtifactReceiptPayload(path)
	if err != nil {
		var oversized *oversizedRemoteArtifactReceiptError
		if !goerrors.As(err, &oversized) {
			return remoteArtifactReceipt{}, nil, exists, err
		}
		cleanupErr := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
			return cleanupRemoteArtifactReceiptFile(path, directory)
		})
		return remoteArtifactReceipt{}, nil, false, goerrors.Join(err, cleanupErr)
	}
	if !exists {
		return remoteArtifactReceipt{}, nil, exists, err
	}
	receipt, decodeErr := decodeRemoteArtifactReceipt(payload, this.identity, this.auditlog, fileName)
	if decodeErr == nil {
		return receipt, payload, true, nil
	}
	receiptErr := errors.System.Newf("cannot use remote artifact delivery receipt %q: %w", path, decodeErr)
	cleanupErr := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
		return cleanupRemoteArtifactReceiptFile(path, directory)
	})
	return remoteArtifactReceipt{}, nil, false, goerrors.Join(receiptErr, cleanupErr)
}

func prepareRemoteArtifactReceiptState(recordingDirectory string, producerId ProducerId) (string, *journalProcessLock, error) {
	return prepareRemoteArtifactReceiptStateWithLock(recordingDirectory, producerId, acquireJournalProcessLock)
}

func prepareRemoteArtifactReceiptStateWithLock(recordingDirectory string, producerId ProducerId, acquireLock func(string, os.FileMode) (*journalProcessLock, error)) (string, *journalProcessLock, error) {
	if producerId.IsZero() {
		return "", nil, errors.Config.Newf("remote artifact delivery receipt producer ID is empty")
	}
	absolute, err := filepath.Abs(recordingDirectory)
	if err != nil {
		return "", nil, errors.Config.Newf("cannot resolve recording directory for delivery receipts: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", nil, errors.Config.Newf("cannot canonicalize recording directory for delivery receipts: %w", err)
	}
	root := filepath.Join(canonical, remoteArtifactReceiptStateDirectoryName)
	if err := ensureRemoteArtifactReceiptDirectory(root); err != nil {
		return "", nil, errors.System.Newf("cannot prepare remote artifact delivery receipt directory %q: %w", root, err)
	}
	lockPath := filepath.Join(root, journalLockFileName)
	stateLock, err := acquireLock(lockPath, journalFileMode)
	if err != nil {
		return "", nil, errors.System.Newf("cannot lock remote artifact delivery receipt state %q: %w", root, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = stateLock.Close()
		}
	}()
	if err := validateLockedJournalPath(stateLock, lockPath); err != nil {
		return "", nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", nil, errors.System.Newf("cannot inspect remote artifact delivery receipt directory %q: %w", root, err)
	}
	expected := producerId.String()
	for _, entry := range entries {
		if entry.Name() == journalLockFileName && entry.Type().IsRegular() {
			continue
		}
		if entry.Name() != expected || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return "", nil, errors.Config.Newf("remote artifact delivery receipt state %q contains unsupported entry %q", root, entry.Name())
		}
	}
	producerDirectory := filepath.Join(root, expected)
	if err := ensureJournalDirectory(producerDirectory, true); err != nil {
		return "", nil, errors.System.Newf("cannot prepare remote artifact delivery receipt producer state %q: %w", producerDirectory, err)
	}
	entries, err = os.ReadDir(producerDirectory)
	if err != nil {
		return "", nil, errors.System.Newf("cannot inspect remote artifact delivery receipt producer state %q: %w", producerDirectory, err)
	}
	for _, entry := range entries {
		if !isRemoteArtifactReceiptStateName(entry.Name()) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return "", nil, errors.Config.Newf("remote artifact delivery receipt producer state %q contains unsupported entry %q", producerDirectory, entry.Name())
		}
	}
	committed = true
	return producerDirectory, stateLock, nil
}

func ensureRemoteArtifactReceiptDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Config.Newf("remote artifact delivery receipt path %q is not a regular directory", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := ensureJournalDirectory(path, true); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Config.Newf("remote artifact delivery receipt path %q is not a regular directory", path)
	}
	return nil
}

func remoteArtifactReceiptStateName(fileName string) string {
	hash := sha256.Sum256([]byte(fileName))
	return hex.EncodeToString(hash[:])
}

func isRemoteArtifactReceiptStateName(name string) bool {
	if len(name) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(name)
	return err == nil && hex.EncodeToString(decoded) == name
}

func validateRemoteArtifactReceiptState(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.System.Newf("cannot inspect remote artifact delivery receipt state %q: %w", directory, err)
	}
	regular, retention := false, false
	for _, entry := range entries {
		if (entry.Name() != remoteArtifactReceiptFileName && entry.Name() != remoteArtifactReceiptRetentionFileName && entry.Name() != remoteArtifactReceiptRetentionTempName && entry.Name() != remoteArtifactReceiptTempFileName && entry.Name() != remoteArtifactReceiptRetentionTempName+remoteArtifactReceiptCleanupSuffix && entry.Name() != remoteArtifactReceiptTempFileName+remoteArtifactReceiptCleanupSuffix) || !entry.Type().IsRegular() {
			return errors.Config.Newf("remote artifact delivery receipt state %q contains unsupported entry %q", directory, entry.Name())
		}
		regular = regular || entry.Name() == remoteArtifactReceiptFileName
		retention = retention || entry.Name() == remoteArtifactReceiptRetentionFileName
	}
	if regular && retention {
		return errors.Config.Newf("remote artifact delivery receipt state %q has conflicting retention state", directory)
	}
	return nil
}

func readRemoteArtifactReceipt(path string, identity *Identity, auditlog configuration.AuditlogName, fileName string) (remoteArtifactReceipt, []byte, bool, error) {
	payload, exists, err := readRemoteArtifactReceiptPayload(path)
	if err != nil || !exists {
		return remoteArtifactReceipt{}, nil, exists, err
	}
	receipt, err := decodeRemoteArtifactReceipt(payload, identity, auditlog, fileName)
	if err != nil {
		return remoteArtifactReceipt{}, nil, false, errors.System.Newf("cannot use remote artifact delivery receipt %q: %w", path, err)
	}
	return receipt, payload, true, nil
}

func remoteArtifactReceiptStateFileName(directory string) (string, bool, error) {
	for _, name := range []string{remoteArtifactReceiptFileName, remoteArtifactReceiptRetentionFileName, remoteArtifactReceiptRetentionTempName, remoteArtifactReceiptTempFileName} {
		path := filepath.Join(directory, name)
		payload, exists, err := readRemoteArtifactReceiptPayload(path)
		if err != nil {
			return "", false, err
		}
		if !exists {
			continue
		}
		var content struct {
			FileName string `json:"fileName"`
		}
		if err := json.Unmarshal(payload, &content); err != nil {
			return "", false, errors.System.Newf("cannot identify remote artifact delivery receipt %q: %w", path, err)
		}
		if err := validateRemoteArtifactFileName(content.FileName); err != nil {
			return "", false, errors.Config.Newf("remote artifact delivery receipt %q has an illegal artifact name: %w", path, err)
		}
		return content.FileName, true, nil
	}
	return "", false, nil
}

func cleanupMalformedRemoteArtifactReceiptTemporaries(directory string, quota RemoteArtifactReceiptQuota) error {
	var result error
	for _, name := range []string{remoteArtifactReceiptRetentionTempName, remoteArtifactReceiptTempFileName} {
		path := filepath.Join(directory, name)
		payload, exists, err := readRemoteArtifactReceiptPayload(path)
		if err != nil {
			var oversized *oversizedRemoteArtifactReceiptError
			if !goerrors.As(err, &oversized) {
				return goerrors.Join(result, err)
			}
			cleanupErr := mutateRemoteArtifactReceiptState(directory, quota, func() error {
				return cleanupRemoteArtifactReceiptFile(path, directory)
			})
			result = goerrors.Join(result, err, cleanupErr)
			continue
		}
		if !exists {
			continue
		}
		var content struct {
			FileName string `json:"fileName"`
		}
		decodeErr := json.Unmarshal(payload, &content)
		if decodeErr == nil {
			decodeErr = validateRemoteArtifactFileName(content.FileName)
		}
		if decodeErr == nil {
			continue
		}
		identifyErr := errors.System.Newf("cannot identify remote artifact delivery receipt %q: %w", path, decodeErr)
		cleanupErr := mutateRemoteArtifactReceiptState(directory, quota, func() error {
			return cleanupRemoteArtifactReceiptFile(path, directory)
		})
		result = goerrors.Join(result, identifyErr, cleanupErr)
	}
	return result
}

func remoteArtifactReceiptRetentionDeleting(directory string) (bool, error) {
	path := filepath.Join(directory, remoteArtifactReceiptRetentionFileName)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.System.Newf("cannot inspect remote artifact retention deletion marker %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, errors.Config.Newf("remote artifact retention deletion marker %q is not a regular file", path)
	}
	return true, nil
}

func readRemoteArtifactReceiptPayload(path string) ([]byte, bool, error) {
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.System.Newf("cannot inspect remote artifact delivery receipt %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, false, errors.Config.Newf("remote artifact delivery receipt %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, errors.System.Newf("cannot open remote artifact delivery receipt %q: %w", path, err)
	}
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return nil, false, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		if err != nil {
			return nil, false, errors.System.Newf("cannot inspect open remote artifact delivery receipt %q: %w", path, err)
		}
		return nil, false, errors.System.Newf("remote artifact delivery receipt %q changed while opening", path)
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maxJournalRecordPayloadSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, false, errors.System.Newf("cannot read remote artifact delivery receipt %q: %w", path, readErr)
	}
	if closeErr != nil {
		return nil, false, errors.System.Newf("cannot close remote artifact delivery receipt %q: %w", path, closeErr)
	}
	if len(payload) > maxJournalRecordPayloadSize {
		return nil, false, &oversizedRemoteArtifactReceiptError{cause: errors.System.Newf("remote artifact delivery receipt %q exceeds %d bytes", path, maxJournalRecordPayloadSize)}
	}
	return payload, true, nil
}

func writeRemoteArtifactReceipt(directory, fileName string, payload []byte, quota RemoteArtifactReceiptQuota) error {
	return writeRemoteArtifactReceiptWithOperations(directory, fileName, payload, quota, defaultRemoteArtifactReceiptWriteOperations())
}

func defaultRemoteArtifactReceiptWriteOperations() remoteArtifactReceiptWriteOperations {
	return remoteArtifactReceiptWriteOperations{
		write:         func(file *os.File, value []byte) (int, error) { return file.Write(value) },
		sync:          func(file *os.File) error { return file.Sync() },
		close:         func(file *os.File) error { return file.Close() },
		replace:       replaceJournalFile,
		syncDirectory: syncJournalDirectory,
		stateUsage:    remoteArtifactReceiptStateUsage,
	}
}

func writeRemoteArtifactReceiptWithOperations(directory, fileName string, payload []byte, quota RemoteArtifactReceiptQuota, operations remoteArtifactReceiptWriteOperations) (result error) {
	before, err := operations.stateUsage(directory)
	if err != nil {
		return err
	}
	reserved := uint64(len(payload))
	if quota != nil {
		if err := quota.Reserve(reserved); err != nil {
			return err
		}
		defer func() {
			after, usageErr := operations.stateUsage(directory)
			if usageErr != nil {
				invalidateRemoteArtifactReceiptQuota(quota, usageErr)
				result = goerrors.Join(result, usageErr)
				return
			}
			result = goerrors.Join(result, quota.Reconcile(reserved, before, after))
		}()
	}
	temporary := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	if err := removeRemoteArtifactReceiptFile(temporary, directory); err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	if err != nil {
		return goerrors.Join(
			errors.System.Newf("cannot create temporary remote artifact delivery receipt for %q: %w", fileName, err),
			cleanupRemoteArtifactReceiptFile(temporary, directory),
		)
	}
	cleanupTemporary := true
	defer func() {
		if cleanupTemporary {
			_ = file.Close()
			result = goerrors.Join(result, cleanupRemoteArtifactReceiptFile(temporary, directory))
		}
	}()
	if err := secureJournalFile(temporary, file); err != nil {
		_ = file.Close()
		return err
	}
	written, err := operations.write(file, payload)
	if err == nil && written != len(payload) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = operations.sync(file)
	}
	closeErr := operations.close(file)
	if err != nil || closeErr != nil {
		return errors.System.Newf("cannot write remote artifact delivery receipt for %q: %w", fileName, goerrors.Join(err, closeErr))
	}
	target := filepath.Join(directory, remoteArtifactReceiptFileName)
	if err := operations.replace(temporary, target); err != nil {
		return errors.System.Newf("cannot publish remote artifact delivery receipt for %q: %w", fileName, err)
	}
	if err := operations.syncDirectory(directory); err != nil {
		return errors.System.Newf("cannot flush remote artifact delivery receipt for %q: %w", fileName, err)
	}
	cleanupTemporary = false
	return nil
}

func mutateRemoteArtifactReceiptState(directory string, quota RemoteArtifactReceiptQuota, mutate func() error) (result error) {
	return mutateRemoteArtifactReceiptStateWithStateUsage(directory, quota, mutate, remoteArtifactReceiptStateUsage)
}

func mutateRemoteArtifactReceiptStateWithStateUsage(directory string, quota RemoteArtifactReceiptQuota, mutate func() error, stateUsage func(string) (int64, error)) (result error) {
	if quota == nil {
		return mutate()
	}
	before, err := stateUsage(directory)
	if err != nil {
		return err
	}
	result = mutate()
	after, usageErr := stateUsage(directory)
	if usageErr != nil {
		invalidateRemoteArtifactReceiptQuota(quota, usageErr)
		return goerrors.Join(result, usageErr)
	}
	return goerrors.Join(result, quota.Reconcile(0, before, after))
}

func invalidateRemoteArtifactReceiptQuota(quota RemoteArtifactReceiptQuota, cause error) {
	if invalidator, ok := quota.(remoteArtifactReceiptQuotaInvalidator); ok {
		invalidator.Invalidate(cause)
	}
}

func remoteArtifactReceiptStateUsage(directory string) (int64, error) {
	var result int64
	for _, name := range []string{remoteArtifactReceiptFileName, remoteArtifactReceiptRetentionFileName, remoteArtifactReceiptRetentionTempName, remoteArtifactReceiptTempFileName, remoteArtifactReceiptRetentionTempName + remoteArtifactReceiptCleanupSuffix, remoteArtifactReceiptTempFileName + remoteArtifactReceiptCleanupSuffix} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, errors.System.Newf("cannot inspect remote artifact delivery receipt state usage: %w", err)
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > int64(^uint64(0)>>1)-result {
			return 0, errors.System.Newf("remote artifact delivery receipt state has an invalid size")
		}
		result += info.Size()
	}
	return result, nil
}

func removeRemoteArtifactReceiptFile(path, directory string) error {
	removeErr := os.Remove(path)
	if errors.Is(removeErr, fs.ErrNotExist) {
		return nil
	}
	if removeErr != nil {
		return errors.System.Newf("cannot remove remote artifact delivery receipt file %q: %w", path, removeErr)
	}
	syncErr := syncJournalDirectory(directory)
	if syncErr != nil {
		return errors.System.Newf("cannot flush remote artifact delivery receipt file removal: %w", syncErr)
	}
	return nil
}

func cleanupRemoteArtifactReceiptFile(path, directory string) error {
	removeErr := removeTemporaryJournalFile(path)
	if errors.Is(removeErr, fs.ErrNotExist) {
		removeErr = nil
	} else if removeErr != nil {
		removeErr = errors.System.Newf("cannot remove temporary remote artifact delivery receipt file %q: %w", path, removeErr)
	}
	syncErr := syncJournalDirectory(directory)
	if syncErr != nil {
		syncErr = errors.System.Newf("cannot flush temporary remote artifact delivery receipt cleanup: %w", syncErr)
	}
	return goerrors.Join(removeErr, syncErr)
}

func cleanupRemoteArtifactReceiptTombstones(directory string) error {
	removed := false
	var result error
	for _, name := range []string{remoteArtifactReceiptRetentionTempName, remoteArtifactReceiptTempFileName} {
		path := filepath.Join(directory, name+remoteArtifactReceiptCleanupSuffix)
		exists, err := validateRemoteArtifactReceiptCleanupMarker(path)
		if err != nil {
			result = goerrors.Join(result, errors.System.Newf("cannot validate temporary remote artifact delivery receipt cleanup marker: %w", err))
			continue
		}
		if !exists {
			continue
		}
		if err := os.Remove(path); err != nil {
			result = goerrors.Join(result, errors.System.Newf("cannot remove temporary remote artifact delivery receipt cleanup marker: %w", err))
			continue
		}
		removed = true
	}
	if removed {
		if err := syncJournalDirectory(directory); err != nil {
			result = goerrors.Join(result, errors.System.Newf("cannot flush temporary remote artifact delivery receipt cleanup markers: %w", err))
		}
	}
	return result
}

func validateRemoteArtifactReceiptCleanupMarker(path string) (bool, error) {
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !pathInfo.Mode().IsRegular() {
		return false, errors.Config.Newf("temporary remote artifact delivery receipt cleanup marker %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return false, err
	}
	openedInfo, err := file.Stat()
	closeErr := file.Close()
	if err != nil {
		return false, goerrors.Join(err, closeErr)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return false, goerrors.Join(errors.System.Newf("temporary remote artifact delivery receipt cleanup marker changed while opening"), closeErr)
	}
	return true, closeErr
}

func restoreRemoteArtifactReceiptFile(path, directory string, payload []byte) error {
	return restoreRemoteArtifactReceiptFileWithOperations(path, directory, payload, defaultRemoteArtifactReceiptWriteOperations())
}

func restoreRemoteArtifactReceiptFileWithOperations(path, directory string, payload []byte, operations remoteArtifactReceiptWriteOperations) (result error) {
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return errors.System.Newf("cannot inspect remote artifact delivery receipt restoration path %q: %w", path, err)
	}
	temporary := filepath.Join(directory, remoteArtifactReceiptRetentionTempName)
	if err := removeRemoteArtifactReceiptFile(temporary, directory); err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, journalFileMode)
	if err != nil {
		return goerrors.Join(
			errors.System.Newf("cannot create temporary remote artifact delivery receipt restoration %q: %w", temporary, err),
			cleanupRemoteArtifactReceiptFile(temporary, directory),
		)
	}
	cleanupTemporary := true
	defer func() {
		if cleanupTemporary {
			_ = file.Close()
			result = goerrors.Join(result, cleanupRemoteArtifactReceiptFile(temporary, directory))
		}
	}()
	if err := secureJournalFile(temporary, file); err != nil {
		_ = file.Close()
		return err
	}
	written, writeErr := operations.write(file, payload)
	if writeErr == nil && written != len(payload) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = operations.sync(file)
	}
	closeErr := operations.close(file)
	if writeErr != nil || closeErr != nil {
		return errors.System.Newf("cannot write restored remote artifact delivery receipt %q: %w", path, goerrors.Join(writeErr, closeErr))
	}
	if err := operations.replace(temporary, path); err != nil {
		return errors.System.Newf("cannot publish restored remote artifact delivery receipt %q: %w", path, err)
	}
	if err := operations.syncDirectory(directory); err != nil {
		return errors.System.Newf("cannot flush restored remote artifact delivery receipt %q: %w", path, err)
	}
	cleanupTemporary = false
	return nil
}

func sameRemoteArtifactReceiptSelection(left, right remoteArtifactReceipt) bool {
	if left.Schema != right.Schema || left.ProducerId != right.ProducerId || left.Auditlog != right.Auditlog || left.FileName != right.FileName || left.ArtifactDigest != right.ArtifactDigest || left.Size != right.Size || left.SealedAt != right.SealedAt || !bytes.Equal(left.PublicKey, right.PublicKey) || len(left.Targets) != len(right.Targets) {
		return false
	}
	for index := range left.Targets {
		if left.Targets[index].Target != right.Targets[index].Target || left.Targets[index].DestinationFingerprint != right.Targets[index].DestinationFingerprint {
			return false
		}
	}
	return true
}

func isRemoteArtifactReceiptSuccessor(current, next remoteArtifactReceipt) bool {
	if !sameRemoteArtifactReceiptSelection(current, next) {
		return false
	}
	advanced := 0
	for index := range current.Targets {
		if current.Targets[index] == next.Targets[index] {
			continue
		}
		if !isRemoteArtifactReceiptTargetSuccessor(current.Targets[index], next.Targets[index]) {
			return false
		}
		advanced++
	}
	return advanced == 1
}

func isRemoteArtifactReceiptTargetSuccessor(current, next remoteArtifactReceiptTarget) bool {
	if current.Target != next.Target || current.DestinationFingerprint != next.DestinationFingerprint {
		return false
	}
	for _, values := range [][2]string{
		{current.AcknowledgedAt, next.AcknowledgedAt},
		{current.AuditOperationId, next.AuditOperationId},
		{current.FailedAt, next.FailedAt},
		{string(current.FailureErrorCategory), string(next.FailureErrorCategory)},
		{current.FailureAuditedAt, next.FailureAuditedAt},
		{current.SuccessAuditedAt, next.SuccessAuditedAt},
	} {
		if values[0] != values[1] && (values[0] != "" || values[1] == "") {
			return false
		}
	}
	return true
}
