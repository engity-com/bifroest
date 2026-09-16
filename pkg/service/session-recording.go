package service

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"math"
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
)

type sessionRecordingRepository struct {
	format        sessionRecordingRepositoryFormat
	castZstd      *recording.LocalCastZstdRepository
	becast        *recording.LocalBECastRepository
	producerId    audit.ProducerId
	chunkSize     int
	flushInterval time.Duration
	flushSize     uint64
	notice        template.String
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
	seal       func(time.Duration, recording.CastResult, *uint32) error
	close      func() error
}

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
	stopErr       error
	onFailure     func(error)
	stop          chan struct{}
	timerDone     chan struct{}
	finalDone     chan struct{}
	stopOnce      sync.Once
}

type sessionRecordingLifecycle struct {
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

func newSessionRecordingRepository(ctx context.Context, configuration configuration.AuditlogRecording, identity *audit.Identity, encryptionPublicKey crypto.PublicKeys) (*sessionRecordingRepository, error) {
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
	repositoryOptions := recording.LocalRepositoryOptions{MaximumSpoolBytes: configuration.MaximumSpoolBytes}
	if encryptionPublicKey.IsZero() {
		repository, err := recording.NewLocalCastZstdRepository(ctx, configuration.Directory, identity, recording.CastZstdVerifyOptions{}, repositoryOptions)
		if err != nil {
			return nil, err
		}
		base.format = sessionRecordingRepositoryFormatCastZstd
		base.castZstd = repository
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
	repository, err := recording.NewLocalBECastRepository(ctx, configuration.Directory, identity, recipient, recording.BECastVerifyOptions{}, repositoryOptions)
	if err != nil {
		return nil, err
	}
	base.format = sessionRecordingRepositoryFormatBECast
	base.becast = repository
	return &base, nil
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
			seal: func(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) error {
				_, err := active.Seal(elapsed, result, exitStatus)
				return err
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
			seal: func(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) error {
				_, err := active.Seal(elapsed, result, exitStatus)
				return err
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

func (this *activeSessionRecording) Seal(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) error {
	if this == nil || this.seal == nil {
		return errors.System.Newf("nil active session Recording")
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

func (this *sessionRecordingCoordinator) Stop(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) error {
	this.mu.Lock()
	if this.stopped {
		result := this.stopErr
		this.mu.Unlock()
		return result
	}
	if this.stopping {
		done := this.finalDone
		this.mu.Unlock()
		<-done
		this.mu.Lock()
		result := this.stopErr
		this.mu.Unlock()
		return result
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
	if finalErr == nil {
		if err := this.active.Seal(elapsed, result, exitStatus); err != nil {
			finalErr = errors.System.Newf("cannot seal session Recording: %w", err)
		}
	}
	if err := this.active.Close(); err != nil {
		finalErr = goerrors.Join(finalErr, errors.System.Newf("cannot close active session Recording: %w", err))
	}
	this.stopErr = finalErr
	this.stopped = true
	close(this.finalDone)
	this.mu.Unlock()
	return finalErr
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
	terminal, err := sessionRecordingTerminal(pty)
	if err != nil {
		return nil, nil, err
	}
	recordingId, err := recording.NewId()
	if err != nil {
		return nil, nil, errors.System.Newf("cannot generate session Recording ID: %w", err)
	}
	started := time.Now()
	startedAt := started.UTC()
	header := recording.CastHeader{
		Version:   recording.CastVersion,
		Terminal:  terminal,
		Timestamp: startedAt.Unix(),
	}
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
	active, err := repository.createActive(sshSession.Context(), header, metadata, repository.chunkSize)
	if err != nil {
		return nil, nil, errors.System.Newf("cannot create active session Recording: %w", err)
	}
	coordinator, err := newSessionRecordingCoordinator(active, repository.flushInterval, repository.flushSize)
	if err != nil {
		return nil, nil, goerrors.Join(err, active.Close())
	}
	var failureOnce sync.Once
	onFailure := func(error) {
		failureOnce.Do(func() { _ = sshSession.Close() })
	}
	if err := coordinator.Start(onFailure); err != nil {
		return nil, nil, goerrors.Join(err, active.Close())
	}
	capture, err := newRecordedSessionWithPty(sshSession, pty, coordinator, func() time.Duration {
		return time.Since(started)
	}, onFailure)
	if err != nil {
		elapsed := time.Since(started)
		stopErr := coordinator.Stop(elapsed, recording.CastResult{
			Status:  recording.CastStatusFailed,
			EndedAt: startedAt.Add(elapsed),
			Reason:  "capture-setup-failed",
		}, nil)
		return nil, nil, goerrors.Join(err, stopErr)
	}
	return capture, &sessionRecordingLifecycle{
		capture:     capture,
		coordinator: coordinator,
		started:     started,
		startedAt:   startedAt,
		metadata:    metadata,
		notice:      repository.notice,
	}, nil
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
	switch {
	case captureErr != nil:
		result.Status = recording.CastStatusFailed
		result.Reason = "capture-failed"
	case taskErr != nil:
		result.Status = recording.CastStatusIncomplete
		result.Reason = "session-error"
	case exitCode < 0 || uint64(exitCode) > math.MaxUint32:
		result.Status = recording.CastStatusIncomplete
		result.Reason = "invalid-exit-status"
	default:
		result.Status = recording.CastStatusCompleted
		status := uint32(exitCode)
		exitStatus = &status
	}
	return goerrors.Join(captureErr, this.coordinator.Stop(elapsed, result, exitStatus))
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
		return this.castZstd.Close()
	case sessionRecordingRepositoryFormatBECast:
		return this.becast.Close()
	default:
		return nil
	}
}
