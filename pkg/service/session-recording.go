package service

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type sessionRecordingRepositoryFormat uint8

const (
	sessionRecordingRepositoryFormatBCast sessionRecordingRepositoryFormat = iota + 1
	sessionRecordingRepositoryFormatBECast

	defaultSessionRecordingColumns = 80
	defaultSessionRecordingRows    = 24
	sessionRecordingBCastSuffix    = ".bcast"
	sessionRecordingBECastSuffix   = ".becast"
)

type sessionRecordingRepository struct {
	format        sessionRecordingRepositoryFormat
	audited       bool
	native        *recording.LocalNativeRecordingRepository
	receipts      *audit.RemoteArtifactReceipts
	auditlog      configuration.AuditlogName
	producerId    audit.ProducerId
	chunkSize     int
	flushInterval time.Duration
	flushSize     uint64
	notice        template.String
}

type sessionRecordingRetentionCandidate struct {
	recordingId recording.Id
	receipt     audit.RemoteArtifactRetentionCandidate
}

type sessionRecordingReceiptProvider struct {
	mutex     sync.Mutex
	audited   bool
	directory string
	identity  *audit.Identity
	auditlog  configuration.AuditlogName
	targets   *audit.RemoteArtifactTargets
	quota     audit.RemoteArtifactReceiptQuota
	receipts  *audit.RemoteArtifactReceipts
	err       error
}

type sessionRecordingStartupRecovery struct {
	recordingId   recording.Id
	status        recording.CastStatus
	digest        recording.CastDigest
	truncated     bool
	alreadySealed bool
}

type activeSessionRecording struct {
	recordingSink
	checkpoint func() error
	seal       func(time.Duration, recording.CastResult, *uint32) (sessionRecordingSealSummary, error)
	close      func() error
}

type sessionRecordingSealSummary struct {
	recordingId recording.Id
	status      recording.CastStatus
	digest      recording.CastDigest
}

type sessionRecordingFailurePhase uint8

const (
	sessionRecordingFailurePhaseNone sessionRecordingFailurePhase = iota
	sessionRecordingFailurePhaseCapture
	sessionRecordingFailurePhaseSeal
)

type sessionRecordingCoordinator struct {
	mu            sync.Mutex
	active        *activeSessionRecording
	flushInterval time.Duration
	flushSize     uint64
	pendingBytes  uint64
	dirty         bool
	started       bool
	stopping      bool
	stopped       bool
	failure       error
	stopSummary   sessionRecordingSealSummary
	stopPhase     sessionRecordingFailurePhase
	stopErr       error
	onFailure     func(error)
	stop          chan struct{}
	timerDone     chan struct{}
	finalDone     chan struct{}
	stopOnce      sync.Once
}

type sessionRecordingLifecycle struct {
	service     *service
	auditlog    configuration.AuditlogName
	repository  *sessionRecordingRepository
	ctx         essh.Context
	capture     *recordedSession
	coordinator *sessionRecordingCoordinator
	started     time.Time
	startedAt   time.Time
	metadata    recording.CastMetadata
	notice      template.String
}

type bestEffortSessionRecordingSink struct {
	service  *service
	auditlog configuration.AuditlogName
	delegate recordingSink
}

func (this *bestEffortSessionRecordingSink) WriteOutput(elapsed time.Duration, stream recording.OutputStream, data []byte) error {
	if this.service.auditlogDisabled(this.auditlog) {
		return nil
	}
	return this.service.handleRecordingFailure(this.auditlog, "session Recording", this.delegate.WriteOutput(elapsed, stream, data))
}

func (this *bestEffortSessionRecordingSink) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	if this.service.auditlogDisabled(this.auditlog) {
		return nil
	}
	return this.service.handleRecordingFailure(this.auditlog, "session Recording", this.delegate.WriteResize(elapsed, columns, rows))
}

type sessionRecordingNoticeContext struct {
	recording sessionRecordingNotice
}

type sessionRecordingNotice struct {
	id        recording.Id
	startedAt time.Time
}

func (this sessionRecordingNoticeContext) GetField(name string) (any, bool, error) {
	switch name {
	case "recording":
		return this.recording, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this sessionRecordingNotice) GetField(name string) (any, bool, error) {
	switch name {
	case "id":
		return this.id, true, nil
	case "startedAt":
		return this.startedAt, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

type sessionRecordingFailure struct {
	cause error
}

func (this *sessionRecordingFailure) Error() string {
	return this.cause.Error()
}

func (this *sessionRecordingFailure) Unwrap() error {
	return this.cause
}

func markSessionRecordingFailure(err error) error {
	if err == nil || isSessionRecordingFailure(err) {
		return err
	}
	return &sessionRecordingFailure{cause: err}
}

func isSessionRecordingFailure(err error) bool {
	var target *sessionRecordingFailure
	return goerrors.As(err, &target)
}

func newSessionRecordingRepository(ctx context.Context, configuration configuration.AuditlogRecording, identity *audit.Identity, encryptionPublicKey crypto.PublicKeys, auditlogName configuration.AuditlogName, targets *audit.RemoteArtifactTargets, audited bool) (*sessionRecordingRepository, error) {
	if identity == nil {
		return nil, errors.Config.Newf("nil session Recording identity")
	}
	if configuration.ChunkSizeBytes > uint64(math.MaxInt) {
		return nil, errors.Config.Newf("session Recording chunk size exceeds platform limits")
	}
	base := sessionRecordingRepository{
		audited:       audited,
		producerId:    identity.ProducerId(),
		auditlog:      auditlogName,
		chunkSize:     int(configuration.ChunkSizeBytes),
		flushInterval: configuration.FlushInterval.Native(),
		flushSize:     configuration.FlushSizeBytes,
		notice:        configuration.Notice,
	}
	receiptProvider := &sessionRecordingReceiptProvider{
		audited:   audited,
		directory: configuration.Directory,
		identity:  identity,
		auditlog:  auditlogName,
		targets:   targets,
	}
	repositoryOptions := recording.LocalRepositoryOptions{
		MaximumSpoolBytes: configuration.MaximumSpoolBytes,
		RecordingOnly:     !audited,
	}
	prepareSealed := &sessionRecordingReceiptPreparer{provider: receiptProvider}
	base.format = sessionRecordingRepositoryFormatBCast
	var recipient *crypto.AgeSshRecipient
	if !encryptionPublicKey.IsZero() {
		keys, err := encryptionPublicKey.Get()
		if err != nil {
			return nil, fmt.Errorf("cannot parse Recording encryption public key: %w", err)
		}
		if len(keys) != 1 {
			return nil, errors.Config.Newf("Recording encryption requires exactly one SSH public key")
		}
		recipient, err = crypto.NewAgeSshRecipient(keys[0])
		if err != nil {
			return nil, fmt.Errorf("cannot create Recording encryption recipient: %w", err)
		}
		base.format = sessionRecordingRepositoryFormatBECast
	}
	repository, err := recording.NewLocalNativeRecordingRepositoryWithArtifactPreparer(ctx, configuration.Directory, identity, recipient, recording.NativeRecordingVerifyOptions{}, repositoryOptions, prepareSealed)
	if err != nil {
		return nil, goerrors.Join(err, receiptProvider.close())
	}
	receipts, err := receiptProvider.get()
	if err != nil {
		return nil, goerrors.Join(err, repository.Close(), receiptProvider.close())
	}
	base.native = repository
	base.receipts = receipts
	if err := base.validateSealedReceipts(ctx); err != nil {
		return nil, goerrors.Join(err, base.Close())
	}
	return &base, nil
}

type sessionRecordingReceiptPreparer struct {
	provider *sessionRecordingReceiptProvider
}

func (this *sessionRecordingReceiptPreparer) BindSealedArtifactQuota(quota audit.RemoteArtifactReceiptQuota) {
	this.provider.setQuota(quota)
}

func (this *sessionRecordingReceiptPreparer) RecoverSealedArtifactState(ctx context.Context) error {
	receipts, err := this.provider.get()
	if err != nil {
		return err
	}
	return receipts.Recover(ctx)
}

func (this *sessionRecordingReceiptPreparer) Prepare(ctx context.Context, artifact audit.RemoteArtifact, sealedAt time.Time) error {
	receipts, err := this.provider.get()
	if err != nil {
		return err
	}
	return receipts.Prepare(ctx, artifact, sealedAt)
}

func (this *sessionRecordingReceiptPreparer) PrepareLifecycle(ctx context.Context, artifact audit.RemoteArtifact, sealedAt time.Time, digest recording.CastDigest, interrupted bool) error {
	receipts, err := this.provider.get()
	if err != nil {
		return err
	}
	return receipts.PrepareLifecycle(ctx, artifact, sealedAt, digest.String(), interrupted)
}

func (this *sessionRecordingReceiptPreparer) PromoteLifecycle(ctx context.Context, artifact audit.RemoteArtifact) error {
	receipts, err := this.provider.get()
	if err != nil {
		return err
	}
	return receipts.PromoteLifecycle(ctx, artifact)
}

func (this *sessionRecordingReceiptPreparer) CleanupOrphanedSealedArtifactState(ctx context.Context) error {
	receipts, err := this.provider.get()
	if err != nil {
		return err
	}
	return receipts.CleanupOrphanedLifecycles(ctx)
}

func (this *sessionRecordingReceiptPreparer) Require(ctx context.Context, artifact audit.RemoteArtifact) error {
	receipts, err := this.provider.get()
	if err != nil {
		return err
	}
	return receipts.Require(ctx, artifact)
}

func (this *sessionRecordingReceiptProvider) setQuota(quota audit.RemoteArtifactReceiptQuota) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.quota = quota
}

func (this *sessionRecordingReceiptProvider) get() (*audit.RemoteArtifactReceipts, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.receipts == nil && this.err == nil {
		if this.audited {
			this.receipts, this.err = audit.NewRemoteArtifactReceipts(this.directory, this.identity, this.auditlog, this.targets, this.quota)
		} else {
			this.receipts, this.err = audit.NewRemoteArtifactReceiptsWithoutAudit(this.directory, this.identity, this.auditlog, this.targets, this.quota)
		}
	}
	return this.receipts, this.err
}

func (this *sessionRecordingReceiptProvider) close() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.receipts == nil {
		return nil
	}
	return this.receipts.Close()
}

func (this *sessionRecordingRepository) validateSealedReceipts(ctx context.Context) error {
	validate := func(artifact interface {
		RemoteArtifact() (audit.RemoteArtifact, error)
		Close() error
	}) error {
		remote, err := artifact.RemoteArtifact()
		if err == nil {
			err = this.receipts.Require(ctx, remote)
		}
		return goerrors.Join(err, artifact.Close())
	}
	ids, err := this.native.ListSealed(ctx)
	if err != nil {
		return err
	}
	sealed := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		name, err := this.artifactName(id)
		if err != nil {
			return err
		}
		sealed[name] = struct{}{}
		artifact, err := this.native.OpenSealed(ctx, id)
		if err != nil {
			return err
		}
		if err := validate(artifact); err != nil {
			return err
		}
	}
	receipts, err := this.receipts.ListSigned(ctx)
	if err != nil {
		return err
	}
	for _, receipt := range receipts {
		if _, exists := sealed[receipt.FileName]; !exists && !receipt.RetentionDeletionStarted {
			return errors.Config.Newf("sealed session Recording artifact %q is missing despite its delivery receipt", receipt.FileName)
		}
	}
	return nil
}

func (this *sessionRecordingRepository) ListSealedArtifactNames(ctx context.Context) ([]string, error) {
	if this == nil {
		return nil, errors.System.Newf("nil session Recording repository")
	}
	ids, err := this.native.ListSealed(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(ids))
	for index, id := range ids {
		result[index], err = this.artifactName(id)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (this *sessionRecordingRepository) OpenSealedArtifact(ctx context.Context, name string) (audit.RemoteArtifactHandle, error) {
	if this == nil {
		return nil, errors.System.Newf("nil session Recording repository")
	}
	id, err := this.recordingIdFromArtifactName(name)
	if err != nil {
		return nil, err
	}
	return this.native.OpenSealed(ctx, id)
}

func (this *sessionRecordingRepository) retentionCandidates(ctx context.Context, cutoff time.Time) ([]sessionRecordingRetentionCandidate, error) {
	if this == nil || this.receipts == nil {
		return nil, errors.System.Newf("nil session Recording repository")
	}
	candidates, err := this.receipts.ListRetentionCandidates(ctx, cutoff)
	if err != nil {
		return nil, err
	}
	result := make([]sessionRecordingRetentionCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		id, err := this.recordingIdFromArtifactName(candidate.FileName)
		if err != nil {
			return nil, err
		}
		result = append(result, sessionRecordingRetentionCandidate{recordingId: id, receipt: candidate})
	}
	return result, nil
}

func (this *sessionRecordingRepository) deleteRetentionCandidate(ctx context.Context, candidate sessionRecordingRetentionCandidate, cutoff time.Time) (bool, sessionRecordingRetentionCandidate, error) {
	if this == nil || this.receipts == nil {
		return false, candidate, errors.System.Newf("nil session Recording repository")
	}
	if !candidate.receipt.DeletionStarted {
		artifact, err := this.OpenSealedArtifact(ctx, candidate.receipt.FileName)
		if err != nil {
			return false, candidate, errors.System.Newf("cannot verify session Recording before retention deletion: %w", err)
		}
		remoteArtifact, err := artifact.RemoteArtifact()
		if err != nil {
			return false, candidate, goerrors.Join(err, artifact.Close())
		}
		if remoteArtifact.Digest() != candidate.receipt.ArtifactDigest || remoteArtifact.Size() != candidate.receipt.Size {
			return false, candidate, goerrors.Join(errors.Config.Newf("sealed session Recording does not match its retention receipt"), artifact.Close())
		}
		if err := artifact.Close(); err != nil {
			return false, candidate, err
		}
	}
	if err := this.receipts.MarkRetentionDeleting(ctx, candidate.receipt, cutoff); err != nil {
		return false, candidate, err
	}
	candidate.receipt.DeletionStarted = true
	deleted, err := this.native.DeleteSealed(ctx, candidate.recordingId, candidate.receipt.ArtifactDigest, candidate.receipt.Size)
	if err != nil {
		return deleted, candidate, err
	}
	completed, err := this.receipts.MarkRetentionCompleted(ctx, candidate.receipt, cutoff)
	if completed.CompletionPending {
		candidate.receipt = completed
	}
	if err != nil {
		return deleted, candidate, err
	}
	return true, candidate, nil
}

func (this *sessionRecordingRepository) completeRetentionCandidate(ctx context.Context, candidate sessionRecordingRetentionCandidate, cutoff time.Time) error {
	if this == nil || this.receipts == nil {
		return errors.System.Newf("nil session Recording repository")
	}
	return this.receipts.RemoveRetentionCandidate(ctx, candidate.receipt, cutoff)
}

func (this *sessionRecordingRepository) recordingIdFromArtifactName(name string) (recording.Id, error) {
	var suffix string
	switch this.format {
	case sessionRecordingRepositoryFormatBCast:
		suffix = sessionRecordingBCastSuffix
	case sessionRecordingRepositoryFormatBECast:
		suffix = sessionRecordingBECastSuffix
	default:
		return recording.Id{}, errors.System.Newf("unknown session Recording repository format")
	}
	if !strings.HasSuffix(name, suffix) {
		return recording.Id{}, errors.Config.Newf("sealed session Recording artifact %q does not match repository format", name)
	}
	var id recording.Id
	if err := id.UnmarshalText([]byte(strings.TrimSuffix(name, suffix))); err != nil || id.String()+suffix != name {
		return recording.Id{}, errors.Config.Newf("illegal sealed session Recording artifact name %q", name)
	}
	return id, nil
}

func (this *sessionRecordingRepository) artifactName(id recording.Id) (string, error) {
	switch this.format {
	case sessionRecordingRepositoryFormatBCast:
		return id.String() + sessionRecordingBCastSuffix, nil
	case sessionRecordingRepositoryFormatBECast:
		return id.String() + sessionRecordingBECastSuffix, nil
	default:
		return "", errors.System.Newf("unknown session Recording repository format")
	}
}

func (this *sessionRecordingRepository) recordingStateExists(id recording.Id) (bool, error) {
	return this.native.RecordingStateExists(id)
}

func (this *sessionRecordingRepository) stageLifecycle(ctx context.Context, id recording.Id, event audit.Event) error {
	name, err := this.artifactName(id)
	if err != nil {
		return err
	}
	return this.receipts.StageLifecycle(ctx, name, event)
}

func (this *sessionRecordingRepository) findPendingLifecycle(ctx context.Context, id recording.Id) (audit.RemoteArtifactLifecycleEvent, bool, error) {
	name, err := this.artifactName(id)
	if err != nil {
		return audit.RemoteArtifactLifecycleEvent{}, false, err
	}
	pending, err := this.receipts.PendingLifecycle(ctx)
	if err != nil {
		return audit.RemoteArtifactLifecycleEvent{}, false, err
	}
	for _, candidate := range pending {
		if candidate.FileName == name {
			return candidate, true, nil
		}
	}
	return audit.RemoteArtifactLifecycleEvent{}, false, nil
}

func (this *sessionRecordingRepository) lifecyclePrepared(ctx context.Context, id recording.Id) (bool, error) {
	name, err := this.artifactName(id)
	if err != nil {
		return false, err
	}
	return this.receipts.LifecyclePrepared(ctx, name)
}

func (this *sessionRecordingRepository) pendingLifecycle(ctx context.Context, id recording.Id) (audit.RemoteArtifactLifecycleEvent, error) {
	pending, exists, err := this.findPendingLifecycle(ctx, id)
	if err != nil {
		return audit.RemoteArtifactLifecycleEvent{}, err
	}
	if !exists {
		name, nameErr := this.artifactName(id)
		if nameErr != nil {
			return audit.RemoteArtifactLifecycleEvent{}, nameErr
		}
		return audit.RemoteArtifactLifecycleEvent{}, errors.System.Newf("pending terminal session Recording lifecycle event for %q is missing", name)
	}
	return pending, nil
}

func (this *service) recordPendingSessionRecordingLifecycle(auditContext, lifecycleContext context.Context, repository *sessionRecordingRepository, id recording.Id) error {
	if repository == nil {
		return errors.System.Newf("nil session Recording repository")
	}
	pending, err := repository.pendingLifecycle(lifecycleContext, id)
	if err != nil {
		return err
	}
	if err := this.recordFlowAudit(auditContext, configuration.FlowName(pending.Event.Flow), pending.Event); err != nil {
		return err
	}
	if auditlog, ok := this.flowAuditlogs[configuration.FlowName(pending.Event.Flow)]; ok && this.auditlogDisabled(auditlog) {
		return nil
	}
	return repository.receipts.CompleteLifecycle(lifecycleContext, pending)
}

func (this *service) recordSessionRecordingStopFailure(auditContext, lifecycleContext context.Context, repository *sessionRecordingRepository, id recording.Id, flow configuration.FlowName, event audit.Event, staged bool, phase sessionRecordingFailurePhase) error {
	if staged && phase == sessionRecordingFailurePhaseSeal {
		if prepared, err := repository.lifecyclePrepared(lifecycleContext, id); err != nil {
			return err
		} else if prepared {
			return nil
		}
	}
	stageErr := repository.stageLifecycle(lifecycleContext, id, event)
	auditErr := this.recordFlowAudit(auditContext, flow, event)
	return goerrors.Join(stageErr, auditErr)
}

func (this *service) replaySessionRecordingLifecycles(ctx context.Context) error {
	var result error
	for _, auditlog := range this.recordingRepositoryOrder {
		if this.auditlogDisabled(auditlog) {
			continue
		}
		repository := this.recordingRepositories[auditlog]
		if repository == nil {
			result = goerrors.Join(result, this.handleRecordingFailure(auditlog, "session Recording recovery", errors.System.Newf("no session Recording repository configured for auditlog %q", auditlog)))
			continue
		}
		if !repository.audited {
			continue
		}
		pending, err := repository.receipts.PendingLifecycle(ctx)
		if err != nil {
			failure := errors.System.Newf("cannot inspect terminal session Recording lifecycle events for auditlog %q: %w", auditlog, err)
			result = goerrors.Join(result, this.handleRecordingFailure(auditlog, "session Recording recovery", failure))
			continue
		}
		recorder := this.auditRecorders[auditlog]
		if recorder == nil {
			result = goerrors.Join(result, this.handleRecordingFailure(auditlog, "session Recording recovery", errors.System.Newf("no audit recorder configured for auditlog %q", auditlog)))
			continue
		}
		for _, event := range pending {
			if err := recorder.Record(ctx, event.Event); err != nil {
				failure := errors.System.Newf("cannot replay terminal session Recording lifecycle event %q for auditlog %q: %w", event.Event.Name, auditlog, err)
				result = goerrors.Join(result, this.handleRecordingFailure(auditlog, "session Recording recovery", failure))
				continue
			}
			if this.auditlogDisabled(auditlog) {
				break
			}
			if err := repository.receipts.CompleteLifecycle(ctx, event); err != nil {
				failure := errors.System.Newf("cannot complete terminal session Recording lifecycle event %q for auditlog %q: %w", event.Event.Name, auditlog, err)
				result = goerrors.Join(result, this.handleRecordingFailure(auditlog, "session Recording recovery", failure))
			}
		}
	}
	return result
}

func sessionRecordingTargetConfigurations(auditlog *configuration.Auditlog) configuration.AuditlogTargets {
	if auditlog == nil || auditlog.Recording.Targets.IsDisabled() {
		return nil
	}
	if configured := auditlog.Recording.Targets.Configured(); configured != nil {
		return configured
	}
	return auditlog.Targets
}

func (this *sessionRecordingRepository) createActive(ctx context.Context, header recording.CastHeader, metadata recording.CastMetadata, chunkSize int) (*activeSessionRecording, error) {
	if this == nil {
		return nil, errors.System.Newf("nil session Recording repository")
	}
	active, err := this.native.CreateActive(ctx, header, metadata, chunkSize)
	if err != nil {
		return nil, err
	}
	return &activeSessionRecording{
		recordingSink: active,
		checkpoint:    active.Checkpoint,
		seal: func(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) (sessionRecordingSealSummary, error) {
			summary, err := active.Seal(elapsed, result, exitStatus)
			return sessionRecordingSealSummary{recordingId: summary.RecordingId, status: summary.Status, digest: summary.Digest}, err
		},
		close: active.Close,
	}, nil
}

func (this *activeSessionRecording) Checkpoint() error {
	if this == nil || this.checkpoint == nil {
		return errors.System.Newf("nil active session Recording")
	}
	return this.checkpoint()
}

func (this *activeSessionRecording) Seal(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) (sessionRecordingSealSummary, error) {
	if this == nil || this.seal == nil {
		return sessionRecordingSealSummary{}, errors.System.Newf("nil active session Recording")
	}
	return this.seal(elapsed, result, exitStatus)
}

func (this *activeSessionRecording) Close() error {
	if this == nil || this.close == nil {
		return nil
	}
	return this.close()
}

func newSessionRecordingCoordinator(active *activeSessionRecording, flushInterval time.Duration, flushSize uint64) (*sessionRecordingCoordinator, error) {
	if active == nil {
		return nil, errors.System.Newf("nil active session Recording")
	}
	if flushInterval <= 0 {
		return nil, errors.Config.Newf("session Recording flush interval must be positive")
	}
	if flushSize == 0 {
		return nil, errors.Config.Newf("session Recording flush size must be positive")
	}
	return &sessionRecordingCoordinator{
		active:        active,
		flushInterval: flushInterval,
		flushSize:     flushSize,
		stop:          make(chan struct{}),
		timerDone:     make(chan struct{}),
		finalDone:     make(chan struct{}),
	}, nil
}

func (this *sessionRecordingCoordinator) Start(onFailure func(error)) error {
	if onFailure == nil {
		return errors.System.Newf("nil session Recording failure callback")
	}
	this.mu.Lock()
	defer this.mu.Unlock()
	if this.started || this.stopping || this.stopped {
		return errors.System.Newf("session Recording coordinator is already started or stopped")
	}
	this.started = true
	this.onFailure = onFailure
	go this.runCheckpointTimer()
	return nil
}

func (this *sessionRecordingCoordinator) WriteOutput(elapsed time.Duration, stream recording.OutputStream, data []byte) error {
	this.mu.Lock()
	defer this.mu.Unlock()
	if err := this.validateWriteLocked(); err != nil {
		return err
	}
	if err := this.active.WriteOutput(elapsed, stream, data); err != nil {
		return this.failLocked(err)
	}
	if len(data) == 0 {
		return nil
	}
	this.dirty = true
	if uint64(len(data)) >= this.flushSize-this.pendingBytes {
		if err := this.active.Checkpoint(); err != nil {
			return this.failLocked(errors.System.Newf("cannot checkpoint session Recording by size: %w", err))
		}
		this.pendingBytes = 0
		this.dirty = false
	} else {
		this.pendingBytes += uint64(len(data))
	}
	return nil
}

func (this *sessionRecordingCoordinator) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	this.mu.Lock()
	defer this.mu.Unlock()
	if err := this.validateWriteLocked(); err != nil {
		return err
	}
	if err := this.active.WriteResize(elapsed, columns, rows); err != nil {
		return this.failLocked(err)
	}
	this.dirty = true
	return nil
}

func (this *sessionRecordingCoordinator) Stop(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) (sessionRecordingSealSummary, sessionRecordingFailurePhase, error) {
	return this.stopPrepared(elapsed, result, exitStatus, nil)
}

func (this *sessionRecordingCoordinator) stopPrepared(elapsed time.Duration, result recording.CastResult, exitStatus *uint32, prepare func(error, sessionRecordingFailurePhase) error) (sessionRecordingSealSummary, sessionRecordingFailurePhase, error) {
	this.mu.Lock()
	if this.stopped {
		summary, phase, stopErr := this.stopSummary, this.stopPhase, this.stopErr
		this.mu.Unlock()
		return summary, phase, stopErr
	}
	if this.stopping {
		done := this.finalDone
		this.mu.Unlock()
		<-done
		this.mu.Lock()
		summary, phase, stopErr := this.stopSummary, this.stopPhase, this.stopErr
		this.mu.Unlock()
		return summary, phase, stopErr
	}
	this.stopping = true
	this.stopOnce.Do(func() { close(this.stop) })
	started := this.started
	this.mu.Unlock()
	if started {
		<-this.timerDone
	}

	this.mu.Lock()
	finalErr := this.failure
	phase := sessionRecordingFailurePhaseNone
	if finalErr != nil {
		phase = sessionRecordingFailurePhaseCapture
	}
	if prepare != nil {
		if err := prepare(finalErr, phase); err != nil {
			finalErr = goerrors.Join(finalErr, errors.System.Newf("cannot stage terminal session Recording audit event: %w", err))
			if phase == sessionRecordingFailurePhaseNone {
				phase = sessionRecordingFailurePhaseSeal
			}
		}
	}
	var summary sessionRecordingSealSummary
	if finalErr == nil {
		var err error
		if summary, err = this.active.Seal(elapsed, result, exitStatus); err != nil {
			finalErr = errors.System.Newf("cannot seal session Recording: %w", err)
			phase = sessionRecordingFailurePhaseSeal
		}
	}
	if err := this.active.Close(); err != nil {
		if phase == sessionRecordingFailurePhaseNone {
			phase = sessionRecordingFailurePhaseSeal
		}
		finalErr = goerrors.Join(finalErr, errors.System.Newf("cannot close active session Recording: %w", err))
	}
	this.stopSummary = summary
	this.stopPhase = phase
	this.stopErr = finalErr
	this.stopped = true
	close(this.finalDone)
	this.mu.Unlock()
	return summary, phase, finalErr
}

func (this *sessionRecordingCoordinator) runCheckpointTimer() {
	ticker := time.NewTicker(this.flushInterval)
	defer ticker.Stop()
	var notify error
	defer func() {
		close(this.timerDone)
		if notify != nil {
			this.onFailure(notify)
		}
	}()
	for {
		select {
		case <-ticker.C:
			this.mu.Lock()
			if this.failure != nil || this.stopping || this.stopped {
				this.mu.Unlock()
				return
			}
			if this.dirty {
				if err := this.active.Checkpoint(); err != nil {
					notify = this.failLocked(errors.System.Newf("cannot checkpoint session Recording by interval: %w", err))
					this.mu.Unlock()
					return
				}
				this.pendingBytes = 0
				this.dirty = false
			}
			this.mu.Unlock()
		case <-this.stop:
			return
		}
	}
}

func (this *sessionRecordingCoordinator) validateWriteLocked() error {
	if this.failure != nil {
		return this.failure
	}
	if !this.started || this.stopping || this.stopped {
		return errors.System.Newf("session Recording coordinator is not running")
	}
	return nil
}

func (this *sessionRecordingCoordinator) failLocked(err error) error {
	if this.failure == nil {
		this.failure = err
		this.stopOnce.Do(func() { close(this.stop) })
	}
	return this.failure
}

func (this *service) beginSessionRecording(sshSession essh.Session, pty recordedSessionPty, connection *connection, storedSession session.Session, operationId uuid.UUID, flow configuration.FlowName, task audit.SessionTask) (recorded *recordedSession, lifecycle *sessionRecordingLifecycle, resultErr error) {
	if task != audit.SessionTaskShell && task != audit.SessionTaskExec {
		return nil, nil, nil
	}
	auditlog, ok := this.flowAuditlogs[flow]
	if !ok {
		return nil, nil, nil
	}
	if this.auditlogDisabled(auditlog) {
		return nil, nil, nil
	}
	defer func() {
		if resultErr == nil {
			return
		}
		if isInvalidSessionRecordingRequest(resultErr) {
			return
		}
		if this.handleRecordingFailure(auditlog, "session Recording", resultErr) == nil {
			recorded = nil
			lifecycle = nil
			resultErr = nil
		}
	}()
	repository := this.recordingRepositories[auditlog]
	if repository == nil {
		return nil, nil, nil
	}
	if connection == nil {
		return nil, nil, errors.System.Newf("cannot start session Recording without a connection")
	}
	if storedSession == nil {
		return nil, nil, errors.System.Newf("cannot start session Recording without a session")
	}
	recordingId, err := recording.NewId()
	if err != nil {
		return nil, nil, errors.System.Newf("cannot generate session Recording ID: %w", err)
	}
	started := time.Now()
	startedAt := started.UTC()
	metadata := recording.CastMetadata{
		RecordingId:  recordingId,
		ConnectionId: connection.Id(),
		SessionId:    storedSession.Id(),
		OperationId:  operationId,
		Flow:         flow,
		Task:         task,
		Pty:          pty.hasPty,
		ProducerId:   repository.producerId,
		StartedAt:    startedAt,
	}
	terminal, err := sessionRecordingTerminal(pty)
	if err != nil {
		auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCreate, err, 0, nil, nil)
		return nil, nil, goerrors.Join(err, auditErr)
	}
	header := recording.CastHeader{
		Version:   recording.CastVersion,
		Terminal:  terminal,
		Timestamp: startedAt.Unix(),
	}
	artifactName, err := repository.artifactName(recordingId)
	if err != nil {
		createErr := errors.System.Newf("cannot identify active session Recording artifact: %w", err)
		auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCreate, createErr, 0, nil, nil)
		return nil, nil, goerrors.Join(createErr, auditErr)
	}
	if repository.audited {
		intentEvent := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil)
		if err := repository.receipts.BeginLifecycle(sshSession.Context(), artifactName, startedAt, intentEvent); err != nil {
			createErr := errors.System.Newf("cannot persist session Recording lifecycle intent: %w", err)
			auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCreate, createErr, 0, nil, nil)
			return nil, nil, goerrors.Join(createErr, auditErr)
		}
	}
	active, err := repository.createActive(sshSession.Context(), header, metadata, repository.chunkSize)
	if err != nil {
		createErr := errors.System.Newf("cannot create active session Recording: %w", err)
		var stateErr error
		if repository.audited {
			var stateExists bool
			stateExists, stateErr = repository.recordingStateExists(recordingId)
			if stateErr == nil && !stateExists {
				stateErr = repository.receipts.DiscardLifecycle(context.WithoutCancel(sshSession.Context()), artifactName)
			}
		}
		auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCreate, createErr, 0, nil, nil)
		return nil, nil, goerrors.Join(createErr, stateErr, auditErr)
	}
	coordinator, err := newSessionRecordingCoordinator(active, repository.flushInterval, repository.flushSize)
	if err != nil {
		startErr := goerrors.Join(err, active.Close())
		auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCreate, startErr, 0, nil, nil)
		return nil, nil, goerrors.Join(startErr, auditErr)
	}
	var failureOnce sync.Once
	onFailure := func(err error) {
		if isInvalidSessionRecordingRequest(err) {
			failureOnce.Do(func() { _ = sshSession.Close() })
			return
		}
		if this.handleRecordingFailure(auditlog, "session Recording", err) == nil {
			return
		}
		failureOnce.Do(func() { _ = sshSession.Close() })
	}
	if err := coordinator.Start(onFailure); err != nil {
		startErr := goerrors.Join(err, active.Close())
		auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCreate, startErr, 0, nil, nil)
		return nil, nil, goerrors.Join(startErr, auditErr)
	}
	var sink recordingSink = coordinator
	if state := this.auditlogStates[auditlog]; state != nil && state.policy == configuration.AuditlogFailurePolicyBestEffort {
		sink = &bestEffortSessionRecordingSink{service: this, auditlog: auditlog, delegate: coordinator}
	}
	capture, err := newRecordedSessionWithPty(sshSession, pty, sink, func() time.Duration {
		return time.Since(started)
	}, onFailure)
	if err != nil {
		elapsed := time.Since(started)
		result := recording.CastResult{
			Status:  recording.CastStatusFailed,
			EndedAt: startedAt.Add(elapsed),
			Reason:  "capture-setup-failed",
		}
		event := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCapture, err, elapsed, nil, nil)
		lifecycleContext := context.WithoutCancel(sshSession.Context())
		staged := false
		var prepare func(error, sessionRecordingFailurePhase) error
		if repository.audited {
			prepare = func(error, sessionRecordingFailurePhase) error {
				stageErr := repository.stageLifecycle(lifecycleContext, recordingId, event)
				staged = stageErr == nil
				return stageErr
			}
		}
		_, stopPhase, stopErr := coordinator.stopPrepared(elapsed, result, nil, prepare)
		auditContext := &sshSessionContext{Context: sshSession.Context(), plainContext: lifecycleContext}
		var auditErr error
		if repository.audited && stopErr == nil {
			auditErr = this.recordPendingSessionRecordingLifecycle(auditContext, lifecycleContext, repository, recordingId)
		} else if repository.audited {
			auditErr = this.recordSessionRecordingStopFailure(auditContext, lifecycleContext, repository, recordingId, metadata.Flow, event, staged, stopPhase)
		}
		return nil, nil, goerrors.Join(err, stopErr, auditErr)
	}
	lifecycle = &sessionRecordingLifecycle{
		service:     this,
		auditlog:    auditlog,
		ctx:         sshSession.Context(),
		capture:     capture,
		coordinator: coordinator,
		started:     started,
		startedAt:   startedAt,
		metadata:    metadata,
		repository:  repository,
		notice:      repository.notice,
	}
	if err := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil); err != nil {
		captureErr := capture.stopAndWait()
		elapsed := time.Since(started)
		result := recording.CastResult{
			Status:  recording.CastStatusFailed,
			EndedAt: startedAt.Add(elapsed),
			Reason:  "audit-start-failed",
		}
		failedEvent := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonAuditWrite, err, elapsed, nil, nil)
		lifecycleContext := context.WithoutCancel(sshSession.Context())
		staged := false
		_, stopPhase, stopErr := coordinator.stopPrepared(elapsed, result, nil, func(error, sessionRecordingFailurePhase) error {
			stageErr := repository.stageLifecycle(lifecycleContext, recordingId, failedEvent)
			staged = stageErr == nil
			return stageErr
		})
		sshContext := sshSession.Context()
		failedAuditContext := &sshSessionContext{Context: sshContext, plainContext: lifecycleContext}
		var failedAuditErr error
		if stopErr == nil {
			failedAuditErr = this.recordPendingSessionRecordingLifecycle(failedAuditContext, lifecycleContext, repository, recordingId)
		} else {
			failedAuditErr = this.recordSessionRecordingStopFailure(failedAuditContext, lifecycleContext, repository, recordingId, metadata.Flow, failedEvent, staged, stopPhase)
		}
		return nil, nil, goerrors.Join(err, captureErr, stopErr, failedAuditErr)
	}
	return capture, lifecycle, nil
}

func sessionRecordingTerminal(pty recordedSessionPty) (recording.CastTerminal, error) {
	columns := uint32(defaultSessionRecordingColumns)
	rows := uint32(defaultSessionRecordingRows)
	terminalType := ""
	if pty.hasPty {
		if requested, dimensionErr := initialWindowDimension(pty.pty.Window.Width, "width"); dimensionErr != nil {
			return recording.CastTerminal{}, invalidSessionRecordingRequest(dimensionErr)
		} else if requested != 0 {
			columns = requested
		}
		if requested, dimensionErr := initialWindowDimension(pty.pty.Window.Height, "height"); dimensionErr != nil {
			return recording.CastTerminal{}, invalidSessionRecordingRequest(dimensionErr)
		} else if requested != 0 {
			rows = requested
		}
		terminalType = pty.pty.Term
	}
	terminal := recording.CastTerminal{Columns: columns, Rows: rows, Type: terminalType}
	if err := terminal.Validate(); err != nil {
		return recording.CastTerminal{}, invalidSessionRecordingRequest(err)
	}
	return terminal, nil
}

func (this *sessionRecordingLifecycle) showNotice(sshSession essh.Session, interactive bool) error {
	if this == nil || !interactive || !this.metadata.Pty || this.metadata.Task != audit.SessionTaskShell || this.notice.IsZero() {
		return nil
	}
	notice, err := this.notice.Render(sessionRecordingNoticeContext{recording: sessionRecordingNotice{
		id:        this.metadata.RecordingId,
		startedAt: this.metadata.StartedAt,
	}})
	if err != nil {
		return errors.System.Newf("cannot render session Recording notice: %w", err)
	}
	if len(notice) == 0 {
		return nil
	}
	if _, err := io.WriteString(sshSession, notice); err != nil {
		return errors.System.Newf("cannot send session Recording notice: %w", err)
	}
	return nil
}

func (this *sessionRecordingLifecycle) finish(exitCode int, taskErr error) error {
	if this == nil {
		return nil
	}
	captureErr := this.capture.stopAndWait()
	elapsed := time.Since(this.started)
	result := recording.CastResult{EndedAt: this.startedAt.Add(elapsed)}
	var exitStatus *uint32
	if exitCode >= 0 && uint64(exitCode) <= uint64(recording.MaximumCastExitStatus) {
		status := uint32(exitCode)
		exitStatus = &status
	}
	switch {
	case this.service.auditlogDisabled(this.auditlog):
		result.Status = recording.CastStatusFailed
		result.Reason = "capture-failed"
	case captureErr != nil:
		result.Status = recording.CastStatusFailed
		result.Reason = "capture-failed"
	case isInvalidSessionExitStatus(taskErr):
		result.Status = recording.CastStatusIncomplete
		result.Reason = "invalid-exit-status"
	case taskErr != nil:
		result.Status = recording.CastStatusIncomplete
		result.Reason = "session-error"
	case exitCode < 0 || uint64(exitCode) > uint64(recording.MaximumCastExitStatus):
		result.Status = recording.CastStatusIncomplete
		result.Reason = "invalid-exit-status"
	default:
		result.Status = recording.CastStatusCompleted
	}
	staged := false
	lifecycleContext := context.WithoutCancel(this.ctx)
	var prepare func(error, sessionRecordingFailurePhase) error
	if this.repository.audited {
		prepare = func(coordinatorErr error, phase sessionRecordingFailurePhase) error {
			event := sessionRecordingTerminalAuditEvent(this.metadata, result, taskErr, captureErr, coordinatorErr, phase, elapsed, exitStatus)
			stageErr := this.repository.stageLifecycle(lifecycleContext, this.metadata.RecordingId, event)
			staged = stageErr == nil
			return stageErr
		}
	}
	_, stopPhase, stopErr := this.coordinator.stopPrepared(elapsed, result, exitStatus, prepare)
	if !this.repository.audited {
		return goerrors.Join(captureErr, this.service.handleRecordingFailure(this.auditlog, "session Recording", stopErr))
	}
	finalAuditContext := &sshSessionContext{Context: this.ctx, plainContext: lifecycleContext}
	if stopErr == nil {
		auditErr := this.service.recordPendingSessionRecordingLifecycle(finalAuditContext, lifecycleContext, this.repository, this.metadata.RecordingId)
		recordingErr := this.service.handleRecordingFailure(this.auditlog, "session Recording", auditErr)
		return goerrors.Join(captureErr, recordingErr)
	}
	event := sessionRecordingTerminalAuditEvent(this.metadata, result, taskErr, captureErr, stopErr, stopPhase, elapsed, exitStatus)
	auditErr := this.service.recordSessionRecordingStopFailure(finalAuditContext, lifecycleContext, this.repository, this.metadata.RecordingId, this.metadata.Flow, event, staged, stopPhase)
	recordingErr := this.service.handleRecordingFailure(this.auditlog, "session Recording", goerrors.Join(stopErr, auditErr))
	return goerrors.Join(captureErr, recordingErr)
}

func sessionRecordingTerminalAuditEvent(metadata recording.CastMetadata, result recording.CastResult, taskErr, captureErr, stopErr error, stopPhase sessionRecordingFailurePhase, elapsed time.Duration, exitStatus *uint32) audit.Event {
	eventName := audit.EventNameSessionRecordingFailed
	outcome := audit.EventOutcomeFailure
	reason := audit.EventReasonRecordingSeal
	eventErr := stopErr
	if captureErr != nil || stopPhase == sessionRecordingFailurePhaseCapture {
		reason = audit.EventReasonRecordingCapture
		eventErr = captureErr
		if eventErr == nil {
			eventErr = stopErr
		}
	} else if stopErr == nil {
		switch result.Status {
		case recording.CastStatusCompleted:
			eventName = audit.EventNameSessionRecordingCompleted
			outcome = audit.EventOutcomeSuccess
			reason = ""
			eventErr = nil
		case recording.CastStatusIncomplete:
			eventName = audit.EventNameSessionRecordingIncomplete
			eventErr = taskErr
			switch {
			case goerrors.Is(taskErr, context.Canceled):
				outcome = audit.EventOutcomeCanceled
				reason = audit.EventReasonContextCanceled
				eventErr = nil
			case goerrors.Is(taskErr, context.DeadlineExceeded):
				outcome = audit.EventOutcomeCanceled
				reason = audit.EventReasonDeadlineExceeded
				eventErr = nil
			case result.Reason == "invalid-exit-status":
				reason = audit.EventReasonInvalidExitCode
				eventErr = nil
			default:
				reason = audit.EventReasonSessionError
			}
		case recording.CastStatusFailed:
			reason = audit.EventReasonRecordingCapture
			eventErr = captureErr
		}
	}
	return sessionRecordingAuditEvent(metadata, eventName, outcome, reason, eventErr, elapsed, nil, exitStatus)
}

func (this *service) recordSessionRecordingEvent(ctx context.Context, metadata recording.CastMetadata, name audit.EventName, outcome audit.EventOutcome, reason audit.EventReason, eventErr error, elapsed time.Duration, digest *recording.CastDigest, exitStatus *uint32) error {
	if auditlog, ok := this.flowAuditlogs[metadata.Flow]; ok && !this.enabledAuditlogs[auditlog] && this.recordingRepositories[auditlog] != nil && this.recordingRepositories[auditlog].native != nil {
		return nil
	}
	event := sessionRecordingAuditEvent(metadata, name, outcome, reason, eventErr, elapsed, digest, exitStatus)
	return this.recordFlowAudit(ctx, metadata.Flow, event)
}

func sessionRecordingAuditEvent(metadata recording.CastMetadata, name audit.EventName, outcome audit.EventOutcome, reason audit.EventReason, eventErr error, elapsed time.Duration, digest *recording.CastDigest, exitStatus *uint32) audit.Event {
	event := audit.Event{
		Name:          name,
		Domain:        audit.EventDomainSession,
		Outcome:       outcome,
		Flow:          metadata.Flow.String(),
		ConnectionId:  metadata.ConnectionId.String(),
		SessionId:     metadata.SessionId.String(),
		OperationId:   metadata.OperationId.String(),
		RecordingId:   metadata.RecordingId.String(),
		SessionTask:   metadata.Task,
		Reason:        reason,
		ErrorCategory: auditErrorCategory(eventErr),
	}
	if eventErr == nil {
		event.ErrorCategory = ""
	}
	if name == audit.EventNameSessionRecordingStarted {
		pty := metadata.Pty
		event.Pty = &pty
	}
	if elapsed > 0 || name == audit.EventNameSessionRecordingCompleted || name == audit.EventNameSessionRecordingIncomplete {
		durationMillis := elapsed.Milliseconds()
		event.DurationMillis = &durationMillis
	}
	if digest != nil {
		event.RecordingDigest = digest.String()
	}
	if exitStatus != nil {
		exitCode := int(*exitStatus)
		event.ExitCode = &exitCode
	}
	return event
}

func (this *sessionRecordingRepository) startupRecoveries() []sessionRecordingStartupRecovery {
	if this == nil {
		return nil
	}
	recoveries := this.native.StartupRecoveries()
	result := make([]sessionRecordingStartupRecovery, len(recoveries))
	for index, recovery := range recoveries {
		result[index] = sessionRecordingStartupRecovery{
			recordingId:   recovery.Summary.RecordingId,
			status:        recovery.Summary.Status,
			digest:        recovery.Summary.Digest,
			truncated:     recovery.Truncated,
			alreadySealed: recovery.AlreadySealed,
		}
	}
	return result
}

func (this *sessionRecordingRepository) Close() error {
	return this.close(false)
}

func (this *sessionRecordingRepository) CloseAfterAcceptedFailure() error {
	return this.close(true)
}

func (this *sessionRecordingRepository) close(ignoreAcceptedFailure bool) error {
	if this == nil {
		return nil
	}
	if ignoreAcceptedFailure {
		return goerrors.Join(this.native.CloseAfterAcceptedFailure(), this.receipts.Close())
	}
	return goerrors.Join(this.native.Close(), this.receipts.Close())
}
