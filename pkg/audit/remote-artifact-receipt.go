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
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	remoteArtifactReceiptStateDirectoryName = ".delivery"
	remoteArtifactReceiptFileName           = "receipt.json"
	remoteArtifactReceiptTempFileName       = "receipt.tmp"
	remoteArtifactReceiptSchema             = "bifroest.session-recording-remote-delivery-receipt/v1"
	remoteArtifactReceiptSignDomain         = "BIFROEST-SESSION-RECORDING-REMOTE-DELIVERY-RECEIPT-SIGNATURE/v1\x00"
)

type remoteArtifactReceiptTarget struct {
	Target                 configuration.AuditlogTargetName     `json:"target"`
	DestinationFingerprint remoteDeliveryDestinationFingerprint `json:"destinationFingerprint"`
	AcknowledgedAt         string                               `json:"acknowledgedAt,omitempty"`
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
}

type remoteArtifactReceipt struct {
	remoteArtifactReceiptContent
	Signature []byte `json:"signature"`
}

type remoteArtifactReceiptStore struct {
	mutex             sync.Mutex
	producerDirectory string
	identity          *Identity
	auditlog          configuration.AuditlogName
	quota             RemoteArtifactReceiptQuota
	stateLock         *journalProcessLock
	closed            bool
	closeErr          error
}

type RemoteArtifactReceiptQuota interface {
	Reserve(uint64) error
	Reconcile(uint64, int64, int64) error
}

// RemoteArtifactReceipts owns the durable delivery receipts for one Recording
// repository. Prepare must complete before the sealed artifact is published.
type RemoteArtifactReceipts struct {
	store   *remoteArtifactReceiptStore
	targets *RemoteArtifactTargets
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

func decodeRemoteArtifactReceipt(payload []byte, identity *Identity, auditlog configuration.AuditlogName, artifact RemoteArtifact) (remoteArtifactReceipt, error) {
	var receipt remoteArtifactReceipt
	if err := decodeCanonicalJournalPayload(payload, &receipt); err != nil {
		return remoteArtifactReceipt{}, errors.System.Newf("cannot decode remote artifact delivery receipt: %w", err)
	}
	if err := validateRemoteArtifactReceiptIdentity(identity, auditlog, artifact); err != nil {
		return remoteArtifactReceipt{}, err
	}
	if receipt.Schema != remoteArtifactReceiptSchema || receipt.ProducerId != identity.ProducerId() || receipt.Auditlog != auditlog || !bytes.Equal(receipt.PublicKey, identity.journalPublicKey()) {
		return remoteArtifactReceipt{}, errors.Config.Newf("remote artifact delivery receipt belongs to a different producer or auditlog")
	}
	if receipt.FileName != artifact.FileName() || receipt.ArtifactDigest != artifact.Digest() || receipt.Size != artifact.Size() {
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

func signRemoteArtifactReceipt(identity *Identity, content remoteArtifactReceiptContent) (remoteArtifactReceipt, []byte, error) {
	if identity == nil || content.ProducerId != identity.ProducerId() || !bytes.Equal(content.PublicKey, identity.journalPublicKey()) {
		return remoteArtifactReceipt{}, nil, errors.Config.Newf("remote artifact delivery receipt identity does not match its content")
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
	if identity == nil || identity.ProducerId().IsZero() {
		return errors.Config.Newf("nil audit identity")
	}
	if err := auditlog.Validate(); err != nil {
		return errors.Config.Newf("illegal remote artifact receipt auditlog: %w", err)
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
		if target.AcknowledgedAt == "" {
			continue
		}
		acknowledgedAt, err := parseRemoteArtifactReceiptTime(target.AcknowledgedAt)
		if err != nil {
			return errors.Config.Newf("remote artifact delivery receipt target %q has an illegal acknowledgement time: %w", target.Target, err)
		}
		if acknowledgedAt.Before(sealedAt) {
			return errors.Config.Newf("remote artifact delivery receipt target %q was acknowledged before the artifact was sealed", target.Target)
		}
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

func acknowledgeRemoteArtifactReceipt(identity *Identity, receipt remoteArtifactReceipt, entry remoteArtifactTargetEntry, acknowledgedAt time.Time) (remoteArtifactReceipt, []byte, bool, error) {
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
	updated, payload, err := signRemoteArtifactReceipt(identity, content)
	return updated, payload, err == nil, err
}

func (this remoteArtifactReceipt) retentionStartedAt() (time.Time, bool) {
	latest, err := parseRemoteArtifactReceiptTime(this.SealedAt)
	if err != nil {
		return time.Time{}, false
	}
	for _, target := range this.Targets {
		if target.AcknowledgedAt == "" {
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
	return &remoteArtifactReceiptStore{producerDirectory: producerDirectory, identity: identity, auditlog: auditlog, quota: quota, stateLock: stateLock}, nil
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
	_, err := this.store.initialize(artifact, sealedAt, this.targets)
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
	_, exists, err := this.store.load(artifact)
	if err != nil {
		return err
	}
	if !exists {
		return errors.Config.Newf("remote artifact delivery receipt for %q is missing", artifact.FileName())
	}
	return nil
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
			_, err := this.store.acknowledge(artifact, entry, acknowledgedAt)
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
	if this == nil {
		return remoteArtifactReceipt{}, errors.System.Newf("nil remote artifact receipt store")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
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
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return this.closeErr
	}
	this.closed = true
	this.closeErr = this.stateLock.Close()
	return this.closeErr
}

func (this *remoteArtifactReceiptStore) load(artifact RemoteArtifact) (remoteArtifactReceipt, bool, error) {
	if this == nil {
		return remoteArtifactReceipt{}, false, errors.System.Newf("nil remote artifact receipt store")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return remoteArtifactReceipt{}, false, errors.System.Newf("remote artifact receipt store is closed")
	}
	return this.loadLocked(artifact)
}

func (this *remoteArtifactReceiptStore) acknowledge(artifact RemoteArtifact, entry remoteArtifactTargetEntry, acknowledgedAt time.Time) (remoteArtifactReceipt, error) {
	if this == nil {
		return remoteArtifactReceipt{}, errors.System.Newf("nil remote artifact receipt store")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
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
	updated, payload, changed, err := acknowledgeRemoteArtifactReceipt(this.identity, receipt, entry, acknowledgedAt)
	if err != nil || !changed {
		return updated, err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	if err := writeRemoteArtifactReceipt(directory, artifact.FileName(), payload, this.quota); err != nil {
		return remoteArtifactReceipt{}, err
	}
	return updated, nil
}

func (this *remoteArtifactReceiptStore) loadLocked(artifact RemoteArtifact) (remoteArtifactReceipt, bool, error) {
	if err := validateRemoteArtifactReceiptIdentity(this.identity, this.auditlog, artifact); err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	directory := filepath.Join(this.producerDirectory, remoteArtifactReceiptStateName(artifact.FileName()))
	if err := ensureRemoteArtifactReceiptDirectory(directory); err != nil {
		return remoteArtifactReceipt{}, false, errors.System.Newf("cannot prepare delivery receipt state for remote artifact %q: %w", artifact.FileName(), err)
	}
	if err := validateRemoteArtifactReceiptState(directory); err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	targetPath := filepath.Join(directory, remoteArtifactReceiptFileName)
	temporaryPath := filepath.Join(directory, remoteArtifactReceiptTempFileName)
	receipt, payload, exists, err := readRemoteArtifactReceipt(targetPath, this.identity, this.auditlog, artifact)
	if err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	temporary, temporaryPayload, temporaryExists, temporaryErr := readRemoteArtifactReceipt(temporaryPath, this.identity, this.auditlog, artifact)
	if temporaryErr != nil {
		return remoteArtifactReceipt{}, false, temporaryErr
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
			return remoteArtifactReceipt{}, false, errors.System.Newf("temporary remote artifact delivery receipt for %q conflicts with its published receipt", artifact.FileName())
		}
	}
	if err := mutateRemoteArtifactReceiptState(directory, this.quota, func() error {
		if err := replaceJournalFile(temporaryPath, targetPath); err != nil {
			return errors.System.Newf("cannot recover remote artifact delivery receipt for %q: %w", artifact.FileName(), err)
		}
		if err := syncJournalDirectory(directory); err != nil {
			return errors.System.Newf("cannot flush recovered remote artifact delivery receipt for %q: %w", artifact.FileName(), err)
		}
		return nil
	}); err != nil {
		return remoteArtifactReceipt{}, false, err
	}
	return temporary, true, nil
}

func prepareRemoteArtifactReceiptState(recordingDirectory string, producerId ProducerId) (string, *journalProcessLock, error) {
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
	stateLock, err := acquireJournalProcessLock(filepath.Join(root, journalLockFileName), journalFileMode)
	if err != nil {
		return "", nil, errors.System.Newf("cannot lock remote artifact delivery receipt state %q: %w", root, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = stateLock.Close()
		}
	}()
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
	for _, entry := range entries {
		if (entry.Name() != remoteArtifactReceiptFileName && entry.Name() != remoteArtifactReceiptTempFileName) || !entry.Type().IsRegular() {
			return errors.Config.Newf("remote artifact delivery receipt state %q contains unsupported entry %q", directory, entry.Name())
		}
	}
	return nil
}

func readRemoteArtifactReceipt(path string, identity *Identity, auditlog configuration.AuditlogName, artifact RemoteArtifact) (remoteArtifactReceipt, []byte, bool, error) {
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return remoteArtifactReceipt{}, nil, false, nil
	}
	if err != nil {
		return remoteArtifactReceipt{}, nil, false, errors.System.Newf("cannot inspect remote artifact delivery receipt %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return remoteArtifactReceipt{}, nil, false, errors.Config.Newf("remote artifact delivery receipt %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return remoteArtifactReceipt{}, nil, false, errors.System.Newf("cannot open remote artifact delivery receipt %q: %w", path, err)
	}
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return remoteArtifactReceipt{}, nil, false, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		if err != nil {
			return remoteArtifactReceipt{}, nil, false, errors.System.Newf("cannot inspect open remote artifact delivery receipt %q: %w", path, err)
		}
		return remoteArtifactReceipt{}, nil, false, errors.System.Newf("remote artifact delivery receipt %q changed while opening", path)
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, maxJournalRecordPayloadSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return remoteArtifactReceipt{}, nil, false, errors.System.Newf("cannot read remote artifact delivery receipt %q: %w", path, readErr)
	}
	if closeErr != nil {
		return remoteArtifactReceipt{}, nil, false, errors.System.Newf("cannot close remote artifact delivery receipt %q: %w", path, closeErr)
	}
	if len(payload) > maxJournalRecordPayloadSize {
		return remoteArtifactReceipt{}, nil, false, errors.System.Newf("remote artifact delivery receipt %q exceeds %d bytes", path, maxJournalRecordPayloadSize)
	}
	receipt, err := decodeRemoteArtifactReceipt(payload, identity, auditlog, artifact)
	if err != nil {
		return remoteArtifactReceipt{}, nil, false, errors.System.Newf("cannot use remote artifact delivery receipt %q: %w", path, err)
	}
	return receipt, payload, true, nil
}

func writeRemoteArtifactReceipt(directory, fileName string, payload []byte, quota RemoteArtifactReceiptQuota) (result error) {
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
		return errors.System.Newf("cannot create temporary remote artifact delivery receipt for %q: %w", fileName, err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := secureJournalFile(temporary, file); err != nil {
		_ = file.Close()
		return err
	}
	written, err := file.Write(payload)
	if err == nil && written != len(payload) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return errors.System.Newf("cannot write remote artifact delivery receipt for %q: %w", fileName, err)
	}
	if closeErr != nil {
		return errors.System.Newf("cannot close remote artifact delivery receipt for %q: %w", fileName, closeErr)
	}
	target := filepath.Join(directory, remoteArtifactReceiptFileName)
	if err := replaceJournalFile(temporary, target); err != nil {
		return errors.System.Newf("cannot publish remote artifact delivery receipt for %q: %w", fileName, err)
	}
	removeTemporary = false
	if err := syncJournalDirectory(directory); err != nil {
		return errors.System.Newf("cannot flush remote artifact delivery receipt for %q: %w", fileName, err)
	}
	return nil
}

func mutateRemoteArtifactReceiptState(directory string, quota RemoteArtifactReceiptQuota, mutate func() error) (result error) {
	if quota == nil {
		return mutate()
	}
	before, err := remoteArtifactReceiptStateUsage(directory)
	if err != nil {
		return err
	}
	result = mutate()
	after, usageErr := remoteArtifactReceiptStateUsage(directory)
	if usageErr != nil {
		return goerrors.Join(result, usageErr)
	}
	return goerrors.Join(result, quota.Reconcile(0, before, after))
}

func remoteArtifactReceiptStateUsage(directory string) (int64, error) {
	var result int64
	for _, name := range []string{remoteArtifactReceiptFileName, remoteArtifactReceiptTempFileName} {
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
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.System.Newf("cannot remove temporary remote artifact delivery receipt %q: %w", path, err)
	}
	if err := syncJournalDirectory(directory); err != nil {
		return errors.System.Newf("cannot flush temporary remote artifact delivery receipt removal: %w", err)
	}
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
		before := current.Targets[index].AcknowledgedAt
		after := next.Targets[index].AcknowledgedAt
		switch {
		case before == after:
		case before == "" && after != "":
			advanced++
		default:
			return false
		}
	}
	return advanced == 1
}
