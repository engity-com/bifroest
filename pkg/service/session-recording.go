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
	sessionRecordingRepositoryFormatCastZstd sessionRecordingRepositoryFormat = iota + 1
	sessionRecordingRepositoryFormatBECast

	defaultSessionRecordingColumns = 80
	defaultSessionRecordingRows    = 24
	sessionRecordingCastZstdSuffix = ".cast.zst"
	sessionRecordingBECastSuffix   = ".becast"
)

type sessionRecordingRepository struct {
	format        sessionRecordingRepositoryFormat
	castZstd      *recording.LocalCastZstdRepository
	becast        *recording.LocalBECastRepository
	receipts      *audit.RemoteArtifactReceipts
	producerId    audit.ProducerId
	chunkSize     int
	flushInterval time.Duration
	flushSize     uint64
	notice        template.String
}

type sessionRecordingReceiptProvider struct {
	mutex     sync.Mutex
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
	ctx         essh.Context
	capture     *recordedSession
	coordinator *sessionRecordingCoordinator
	started     time.Time
	startedAt   time.Time
	metadata    recording.CastMetadata
	notice      template.String
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

func newSessionRecordingRepository(ctx context.Context, configuration configuration.AuditlogRecording, identity *audit.Identity, encryptionPublicKey crypto.PublicKeys, auditlogName configuration.AuditlogName, targets *audit.RemoteArtifactTargets) (*sessionRecordingRepository, error) {
	if identity == nil {
		return nil, errors.Config.Newf("nil session Recording identity")
	}
	if configuration.ChunkSizeBytes > uint64(math.MaxInt) {
		return nil, errors.Config.Newf("session Recording chunk size exceeds platform limits")
	}
	base := sessionRecordingRepository{
		producerId:    identity.ProducerId(),
		chunkSize:     int(configuration.ChunkSizeBytes),
		flushInterval: configuration.FlushInterval.Native(),
		flushSize:     configuration.FlushSizeBytes,
		notice:        configuration.Notice,
	}
	receiptProvider := &sessionRecordingReceiptProvider{
		directory: configuration.Directory,
		identity:  identity,
		auditlog:  auditlogName,
		targets:   targets,
	}
	repositoryOptions := recording.LocalRepositoryOptions{
		MaximumSpoolBytes: configuration.MaximumSpoolBytes,
	}
	prepareSealed := &sessionRecordingReceiptPreparer{provider: receiptProvider}
	if encryptionPublicKey.IsZero() {
		repository, err := recording.NewLocalCastZstdRepositoryWithArtifactPreparer(ctx, configuration.Directory, identity, recording.CastZstdVerifyOptions{}, repositoryOptions, prepareSealed)
		if err != nil {
			return nil, goerrors.Join(err, receiptProvider.close())
		}
		receipts, err := receiptProvider.get()
		if err != nil {
			return nil, goerrors.Join(err, repository.Close(), receiptProvider.close())
		}
		base.format = sessionRecordingRepositoryFormatCastZstd
		base.castZstd = repository
		base.receipts = receipts
		if err := base.validateSealedReceipts(ctx); err != nil {
			return nil, goerrors.Join(err, base.Close())
		}
		return &base, nil
	}

	keys, err := encryptionPublicKey.Get()
	if err != nil {
		return nil, fmt.Errorf("cannot parse Recording encryption public key: %w", err)
	}
	if len(keys) != 1 {
		return nil, errors.Config.Newf("Recording encryption requires exactly one SSH public key")
	}
	recipient, err := crypto.NewAgeSshRecipient(keys[0])
	if err != nil {
		return nil, fmt.Errorf("cannot create Recording encryption recipient: %w", err)
	}
	repository, err := recording.NewLocalBECastRepositoryWithArtifactPreparer(ctx, configuration.Directory, identity, recipient, recording.BECastVerifyOptions{}, repositoryOptions, prepareSealed)
	if err != nil {
		return nil, goerrors.Join(err, receiptProvider.close())
	}
	receipts, err := receiptProvider.get()
	if err != nil {
		return nil, goerrors.Join(err, repository.Close(), receiptProvider.close())
	}
	base.format = sessionRecordingRepositoryFormatBECast
	base.becast = repository
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
		this.receipts, this.err = audit.NewRemoteArtifactReceipts(this.directory, this.identity, this.auditlog, this.targets, this.quota)
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
	switch this.format {
	case sessionRecordingRepositoryFormatCastZstd:
		ids, err := this.castZstd.ListSealed(ctx)
		if err != nil {
			return err
		}
		for _, id := range ids {
			artifact, err := this.castZstd.OpenSealed(ctx, id)
			if err != nil {
				return err
			}
			if err := validate(artifact); err != nil {
				return err
			}
		}
	case sessionRecordingRepositoryFormatBECast:
		ids, err := this.becast.ListSealed(ctx)
		if err != nil {
			return err
		}
		for _, id := range ids {
			artifact, err := this.becast.OpenSealed(ctx, id)
			if err != nil {
				return err
			}
			if err := validate(artifact); err != nil {
				return err
			}
		}
	}
	return nil
}

func (this *sessionRecordingRepository) ListSealedArtifactNames(ctx context.Context) ([]string, error) {
	if this == nil {
		return nil, errors.System.Newf("nil session Recording repository")
	}
	var ids []recording.Id
	var suffix string
	var err error
	switch this.format {
	case sessionRecordingRepositoryFormatCastZstd:
		ids, err = this.castZstd.ListSealed(ctx)
		suffix = sessionRecordingCastZstdSuffix
	case sessionRecordingRepositoryFormatBECast:
		ids, err = this.becast.ListSealed(ctx)
		suffix = sessionRecordingBECastSuffix
	default:
		return nil, errors.System.Newf("unknown session Recording repository format")
	}
	if err != nil {
		return nil, err
	}
	result := make([]string, len(ids))
	for index, id := range ids {
		result[index] = id.String() + suffix
	}
	return result, nil
}

func (this *sessionRecordingRepository) OpenSealedArtifact(ctx context.Context, name string) (audit.RemoteArtifactHandle, error) {
	if this == nil {
		return nil, errors.System.Newf("nil session Recording repository")
	}
	var suffix string
	switch this.format {
	case sessionRecordingRepositoryFormatCastZstd:
		suffix = sessionRecordingCastZstdSuffix
	case sessionRecordingRepositoryFormatBECast:
		suffix = sessionRecordingBECastSuffix
	default:
		return nil, errors.System.Newf("unknown session Recording repository format")
	}
	if !strings.HasSuffix(name, suffix) {
		return nil, errors.Config.Newf("sealed session Recording artifact %q does not match repository format", name)
	}
	var id recording.Id
	if err := id.UnmarshalText([]byte(strings.TrimSuffix(name, suffix))); err != nil || id.String()+suffix != name {
		return nil, errors.Config.Newf("illegal sealed session Recording artifact name %q", name)
	}
	if this.format == sessionRecordingRepositoryFormatCastZstd {
		return this.castZstd.OpenSealed(ctx, id)
	}
	return this.becast.OpenSealed(ctx, id)
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
	switch this.format {
	case sessionRecordingRepositoryFormatCastZstd:
		active, err := this.castZstd.CreateActive(ctx, header, metadata, chunkSize)
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
	case sessionRecordingRepositoryFormatBECast:
		active, err := this.becast.CreateActive(ctx, header, metadata, chunkSize)
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
	default:
		return nil, errors.System.Newf("illegal session Recording repository format %d", this.format)
	}
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

func (this *service) beginSessionRecording(sshSession essh.Session, pty recordedSessionPty, connection *connection, storedSession session.Session, operationId uuid.UUID, flow configuration.FlowName, task audit.SessionTask) (*recordedSession, *sessionRecordingLifecycle, error) {
	if task != audit.SessionTaskShell && task != audit.SessionTaskExec {
		return nil, nil, nil
	}
	auditlog, ok := this.flowAuditlogs[flow]
	if !ok {
		return nil, nil, nil
	}
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
	active, err := repository.createActive(sshSession.Context(), header, metadata, repository.chunkSize)
	if err != nil {
		createErr := errors.System.Newf("cannot create active session Recording: %w", err)
		auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCreate, createErr, 0, nil, nil)
		return nil, nil, goerrors.Join(createErr, auditErr)
	}
	coordinator, err := newSessionRecordingCoordinator(active, repository.flushInterval, repository.flushSize)
	if err != nil {
		startErr := goerrors.Join(err, active.Close())
		auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCreate, startErr, 0, nil, nil)
		return nil, nil, goerrors.Join(startErr, auditErr)
	}
	var failureOnce sync.Once
	onFailure := func(error) {
		failureOnce.Do(func() { _ = sshSession.Close() })
	}
	if err := coordinator.Start(onFailure); err != nil {
		startErr := goerrors.Join(err, active.Close())
		auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCreate, startErr, 0, nil, nil)
		return nil, nil, goerrors.Join(startErr, auditErr)
	}
	capture, err := newRecordedSessionWithPty(sshSession, pty, coordinator, func() time.Duration {
		return time.Since(started)
	}, onFailure)
	if err != nil {
		elapsed := time.Since(started)
		result := recording.CastResult{
			Status:  recording.CastStatusFailed,
			EndedAt: startedAt.Add(elapsed),
			Reason:  "capture-setup-failed",
		}
		summary, _, stopErr := coordinator.Stop(elapsed, result, nil)
		var digest *recording.CastDigest
		if stopErr == nil {
			digest = &summary.digest
		}
		auditErr := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonRecordingCapture, err, elapsed, digest, nil)
		return nil, nil, goerrors.Join(err, stopErr, auditErr)
	}
	lifecycle := &sessionRecordingLifecycle{
		service:     this,
		ctx:         sshSession.Context(),
		capture:     capture,
		coordinator: coordinator,
		started:     started,
		startedAt:   startedAt,
		metadata:    metadata,
		notice:      repository.notice,
	}
	if err := this.recordSessionRecordingEvent(sshSession.Context(), metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil); err != nil {
		captureErr := capture.stopAndWait()
		elapsed := time.Since(started)
		summary, _, stopErr := coordinator.Stop(elapsed, recording.CastResult{
			Status:  recording.CastStatusFailed,
			EndedAt: startedAt.Add(elapsed),
			Reason:  "audit-start-failed",
		}, nil)
		var digest *recording.CastDigest
		if stopErr == nil {
			digest = &summary.digest
		}
		sshContext := sshSession.Context()
		failedAuditContext := &sshSessionContext{Context: sshContext, plainContext: context.WithoutCancel(sshContext)}
		failedAuditErr := this.recordSessionRecordingEvent(failedAuditContext, metadata, audit.EventNameSessionRecordingFailed, audit.EventOutcomeFailure, audit.EventReasonAuditWrite, err, elapsed, digest, nil)
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
			return recording.CastTerminal{}, dimensionErr
		} else if requested != 0 {
			columns = requested
		}
		if requested, dimensionErr := initialWindowDimension(pty.pty.Window.Height, "height"); dimensionErr != nil {
			return recording.CastTerminal{}, dimensionErr
		} else if requested != 0 {
			rows = requested
		}
		terminalType = pty.pty.Term
	}
	return recording.CastTerminal{Columns: columns, Rows: rows, Type: terminalType}, nil
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
	if exitCode >= 0 && uint64(exitCode) <= math.MaxUint32 {
		status := uint32(exitCode)
		exitStatus = &status
	}
	switch {
	case captureErr != nil:
		result.Status = recording.CastStatusFailed
		result.Reason = "capture-failed"
	case isInvalidSessionExitStatus(taskErr):
		result.Status = recording.CastStatusIncomplete
		result.Reason = "invalid-exit-status"
	case taskErr != nil:
		result.Status = recording.CastStatusIncomplete
		result.Reason = "session-error"
	case exitCode < 0 || uint64(exitCode) > math.MaxUint32:
		result.Status = recording.CastStatusIncomplete
		result.Reason = "invalid-exit-status"
	default:
		result.Status = recording.CastStatusCompleted
	}
	summary, stopPhase, stopErr := this.coordinator.Stop(elapsed, result, exitStatus)
	eventName := audit.EventNameSessionRecordingFailed
	outcome := audit.EventOutcomeFailure
	reason := audit.EventReasonRecordingSeal
	eventErr := stopErr
	var digest *recording.CastDigest
	if stopErr == nil {
		digest = &summary.digest
	}
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
	finalAuditContext := &sshSessionContext{Context: this.ctx, plainContext: context.WithoutCancel(this.ctx)}
	auditErr := this.service.recordSessionRecordingEvent(finalAuditContext, this.metadata, eventName, outcome, reason, eventErr, elapsed, digest, exitStatus)
	return goerrors.Join(captureErr, stopErr, auditErr)
}

func (this *service) recordSessionRecordingEvent(ctx context.Context, metadata recording.CastMetadata, name audit.EventName, outcome audit.EventOutcome, reason audit.EventReason, eventErr error, elapsed time.Duration, digest *recording.CastDigest, exitStatus *uint32) error {
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
	switch this.format {
	case sessionRecordingRepositoryFormatCastZstd:
		recoveries := this.castZstd.StartupRecoveries()
		result := make([]sessionRecordingStartupRecovery, len(recoveries))
		for index, recovery := range recoveries {
			result[index] = sessionRecordingStartupRecovery{
				recordingId:   recovery.Summary.RecordingId,
				status:        recovery.Summary.Status,
				truncated:     recovery.Truncated,
				alreadySealed: recovery.AlreadySealed,
			}
		}
		return result
	case sessionRecordingRepositoryFormatBECast:
		recoveries := this.becast.StartupRecoveries()
		result := make([]sessionRecordingStartupRecovery, len(recoveries))
		for index, recovery := range recoveries {
			result[index] = sessionRecordingStartupRecovery{
				recordingId:   recovery.Summary.RecordingId,
				status:        recovery.Summary.Status,
				truncated:     recovery.Truncated,
				alreadySealed: recovery.AlreadySealed,
			}
		}
		return result
	default:
		return nil
	}
}

func (this *sessionRecordingRepository) Close() error {
	if this == nil {
		return nil
	}
	switch this.format {
	case sessionRecordingRepositoryFormatCastZstd:
		return goerrors.Join(this.castZstd.Close(), this.receipts.Close())
	case sessionRecordingRepositoryFormatBECast:
		return goerrors.Join(this.becast.Close(), this.receipts.Close())
	default:
		return nil
	}
}
