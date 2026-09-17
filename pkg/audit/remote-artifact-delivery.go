package audit

import (
	"context"
	goerrors "errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/fsnotify/fsnotify"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

// RemoteArtifactHandle owns one verified, sealed artifact. Close must be
// idempotent and safe while an operation using the artifact is being canceled.
type RemoteArtifactHandle interface {
	RemoteArtifact() (RemoteArtifact, error)
	io.Closer
}

// RemoteArtifactSource provides immutable sealed artifacts by file name. A
// successful OpenSealedArtifact must return a handle whose RemoteArtifact has
// already been verified against the local sealed representation.
type RemoteArtifactSource interface {
	ListSealedArtifactNames(context.Context) ([]string, error)
	OpenSealedArtifact(context.Context, string) (RemoteArtifactHandle, error)
}

type remoteArtifactDeliveryOptions struct {
	idleDelay      time.Duration
	initialBackoff time.Duration
	maximumBackoff time.Duration
	jitter         func(time.Duration) time.Duration
	newWatcher     func() (*fsnotify.Watcher, error)
	addWatch       func(*fsnotify.Watcher, string) error
	acknowledge    func(context.Context, *remoteArtifactReceiptStore, RemoteArtifact, remoteArtifactTargetEntry, time.Time) error
	auditor        RemoteArtifactDeliveryAuditor
}

func defaultRemoteArtifactDeliveryOptions() remoteArtifactDeliveryOptions {
	return remoteArtifactDeliveryOptions{
		idleDelay:      defaultRemoteDeliveryIdleDelay,
		initialBackoff: defaultRemoteDeliveryInitialBackoff,
		maximumBackoff: defaultRemoteDeliveryMaximumBackoff,
		jitter:         jitterRemoteDeliveryBackoff,
		newWatcher:     fsnotify.NewWatcher,
		addWatch:       func(watcher *fsnotify.Watcher, directory string) error { return watcher.Add(directory) },
		acknowledge: func(ctx context.Context, store *remoteArtifactReceiptStore, artifact RemoteArtifact, entry remoteArtifactTargetEntry, acknowledgedAt time.Time) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, err := store.acknowledge(ctx, artifact, entry, acknowledgedAt)
			return err
		},
	}
}

type RemoteArtifactDeliveryAuditState string

const (
	RemoteArtifactDeliveryAuditFailed    RemoteArtifactDeliveryAuditState = "failed"
	RemoteArtifactDeliveryAuditSucceeded RemoteArtifactDeliveryAuditState = "succeeded"
)

type RemoteArtifactDeliveryAuditEvent struct {
	State                  RemoteArtifactDeliveryAuditState
	Scope                  RemoteTargetScope
	FileName               string
	OperationId            string
	ErrorCategory          ErrorCategory
	destinationFingerprint remoteDeliveryDestinationFingerprint
}

type RemoteArtifactDeliveryAuditor interface {
	RecordRemoteArtifactDelivery(context.Context, RemoteArtifactDeliveryAuditEvent) error
}

// RemoteArtifactDelivery owns one independent, sequential artifact delivery
// worker per target. Receipts are authoritative and local artifacts are never
// removed by this coordinator.
type RemoteArtifactDelivery struct {
	mutex           sync.Mutex
	flushLock       chan struct{}
	sealedDirectory string
	source          RemoteArtifactSource
	receipts        *RemoteArtifactReceipts
	targets         *RemoteArtifactTargets
	workers         []*remoteArtifactDeliveryWorker
	context         context.Context
	cancel          context.CancelFunc
	wait            sync.WaitGroup
	started         bool
	closed          bool
	closeOnce       sync.Once
	closeDone       chan struct{}
	closeErr        error
	progress        chan struct{}
	watcher         *fsnotify.Watcher
}

type remoteArtifactDeliveryWorker struct {
	entry         remoteArtifactTargetEntry
	source        RemoteArtifactSource
	receipts      *remoteArtifactReceiptStore
	options       remoteArtifactDeliveryOptions
	logger        log.Logger
	wake          chan struct{}
	discoveryWake chan struct{}
	progress      chan<- struct{}
	pending       *remoteArtifactDeliveryPending
	auditPending  *remoteArtifactDeliveryAuditPending
}

type remoteArtifactDeliveryPending struct {
	artifact       RemoteArtifact
	acknowledgedAt time.Time
}

type remoteArtifactDeliveryAuditPending struct {
	event    RemoteArtifactDeliveryAuditEvent
	recorded bool
}

type remoteArtifactDeliveryFlushGoal struct {
	fileName string
	entry    remoteArtifactTargetEntry
}

// NewRemoteArtifactDelivery prepares asynchronous delivery for a sealed source.
// The coordinator owns targets after a successful return, but does not own the
// source or receipt store.
func NewRemoteArtifactDelivery(ctx context.Context, sealedDirectory string, source RemoteArtifactSource, receipts *RemoteArtifactReceipts, targets *RemoteArtifactTargets, auditor RemoteArtifactDeliveryAuditor) (*RemoteArtifactDelivery, error) {
	if isNilRemoteValue(auditor) {
		return nil, errors.Config.Newf("nil remote artifact delivery auditor")
	}
	options := defaultRemoteArtifactDeliveryOptions()
	options.auditor = auditor
	return newRemoteArtifactDelivery(ctx, sealedDirectory, source, receipts, targets, options)
}

func newRemoteArtifactDelivery(ctx context.Context, sealedDirectory string, source RemoteArtifactSource, receipts *RemoteArtifactReceipts, targets *RemoteArtifactTargets, options remoteArtifactDeliveryOptions) (*RemoteArtifactDelivery, error) {
	if isNilRemoteValue(source) {
		return nil, errors.Config.Newf("nil remote artifact source")
	}
	if receipts == nil || receipts.store == nil {
		return nil, errors.Config.Newf("nil remote artifact receipts")
	}
	if targets == nil {
		return nil, errors.Config.Newf("nil remote artifact targets")
	}
	directory, err := canonicalRemoteArtifactSealedDirectory(sealedDirectory)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, entry := range targets.entries {
		if entry.scope.Auditlog != receipts.store.auditlog {
			return nil, errors.Config.Newf("remote artifact target %q belongs to auditlog %q instead of %q", entry.scope.Target, entry.scope.Auditlog, receipts.store.auditlog)
		}
		if isNilRemoteValue(entry.target) || entry.publishAttemptTimeout <= 0 || entry.destinationFingerprint.IsZero() {
			return nil, errors.Config.Newf("remote artifact target %q is incomplete", entry.scope.Target)
		}
	}
	if err := validateRemoteArtifactDeliverySnapshots(ctx, source, receipts.store, targets.entries); err != nil {
		return nil, err
	}
	newWatcher := options.newWatcher
	if newWatcher == nil {
		newWatcher = fsnotify.NewWatcher
	}
	addWatch := options.addWatch
	if addWatch == nil {
		addWatch = func(watcher *fsnotify.Watcher, directory string) error { return watcher.Add(directory) }
	}
	acknowledge := options.acknowledge
	if acknowledge == nil {
		acknowledge = defaultRemoteArtifactDeliveryOptions().acknowledge
	}
	options.acknowledge = acknowledge
	logger := log.GetLogger("audit.remote-artifact-delivery").With("auditlog", receipts.store.auditlog)
	watcher, watcherErr := newWatcher()
	if watcherErr != nil {
		logger.WithError(watcherErr).Warn("cannot create remote artifact delivery directory watcher; using periodic polling")
		watcher = nil
	} else if watcher == nil {
		logger.Warn("remote artifact delivery directory watcher factory returned nil; using periodic polling")
	} else if watchErr := addWatch(watcher, directory); watchErr != nil {
		_ = watcher.Close()
		logger.WithError(watchErr).With("directory", directory).Warn("cannot watch sealed artifact directory for delivery; using periodic polling")
		watcher = nil
	}
	workerContext, cancel := context.WithCancel(ctx)
	result := &RemoteArtifactDelivery{
		sealedDirectory: directory,
		source:          source,
		receipts:        receipts,
		targets:         targets,
		context:         workerContext,
		cancel:          cancel,
		closeDone:       make(chan struct{}),
		progress:        make(chan struct{}, 1),
		flushLock:       make(chan struct{}, 1),
		watcher:         watcher,
	}
	result.flushLock <- struct{}{}
	for _, entry := range targets.entries {
		result.workers = append(result.workers, &remoteArtifactDeliveryWorker{
			entry:         entry,
			source:        source,
			receipts:      receipts.store,
			options:       options,
			logger:        logger.With("target", entry.scope.Target),
			wake:          make(chan struct{}, 1),
			discoveryWake: make(chan struct{}, 1),
			progress:      result.progress,
		})
	}
	return result, nil
}

func validateRemoteArtifactDeliverySnapshots(ctx context.Context, source RemoteArtifactSource, receipts *remoteArtifactReceiptStore, entries []remoteArtifactTargetEntry) error {
	names, err := listRemoteArtifactSourceNames(ctx, source)
	if err != nil {
		return err
	}
	byTarget := make(map[configuration.AuditlogTargetName]remoteArtifactTargetEntry, len(entries))
	for _, entry := range entries {
		byTarget[entry.scope.Target] = entry
	}
	for _, name := range names {
		selected, err := receipts.deliveryTargets(ctx, name)
		if err != nil {
			return err
		}
		for _, receiptTarget := range selected {
			if receiptTarget.AcknowledgedAt != "" && receiptTarget.SuccessAuditedAt != "" {
				continue
			}
			entry, exists := byTarget[receiptTarget.Target]
			if !exists {
				return errors.Config.Newf("remote artifact %q selects unconfigured target %q", name, receiptTarget.Target)
			}
			if entry.destinationFingerprint != receiptTarget.DestinationFingerprint {
				return errors.Config.Newf("remote artifact target %q uses a different destination than the delivery receipt", receiptTarget.Target)
			}
		}
	}
	return nil
}

func canonicalRemoteArtifactSealedDirectory(directory string) (string, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", errors.Config.Newf("cannot resolve sealed artifact directory: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", errors.Config.Newf("cannot canonicalize sealed artifact directory %q: %w", absolute, err)
	}
	info, err := os.Lstat(canonical)
	if err != nil {
		return "", errors.Config.Newf("cannot inspect sealed artifact directory %q: %w", canonical, err)
	}
	if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return "", errors.Config.Newf("sealed artifact directory %q is not a regular directory", canonical)
	}
	return canonical, nil
}

func (this *RemoteArtifactDelivery) Start() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return errors.System.Newf("remote artifact delivery is closed")
	}
	if this.started {
		return nil
	}
	this.started = true
	if this.watcher != nil {
		this.wait.Add(1)
		go func() {
			defer this.wait.Done()
			this.watch(this.context)
		}()
	}
	for _, worker := range this.workers {
		this.wait.Add(1)
		go func(worker *remoteArtifactDeliveryWorker) {
			defer this.wait.Done()
			worker.run(this.context)
		}(worker)
	}
	return nil
}

func (this *RemoteArtifactDelivery) Close() error {
	if this == nil {
		return nil
	}
	this.closeOnce.Do(func() {
		this.mutex.Lock()
		this.closed = true
		this.cancel()
		this.mutex.Unlock()
		var watcherErr error
		if this.watcher != nil {
			watcherErr = this.watcher.Close()
		}
		targetErr := this.targets.Close()
		this.wait.Wait()
		this.closeErr = goerrors.Join(watcherErr, targetErr)
		close(this.closeDone)
	})
	<-this.closeDone
	return this.closeErr
}

// Flush captures the sealed names visible when it starts, explicitly wakes
// workers (including those in failure backoff), and waits for every destination
// selected by those artifacts' receipts to be durably acknowledged.
func (this *RemoteArtifactDelivery) Flush(ctx context.Context) error {
	if this == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return errors.System.Newf("cannot flush remote artifact delivery: %w", ctx.Err())
	case <-this.context.Done():
		return errors.System.Newf("remote artifact delivery stopped before flush")
	case <-this.flushLock:
	}
	defer func() { this.flushLock <- struct{}{} }()
	this.mutex.Lock()
	if this.closed || !this.started {
		this.mutex.Unlock()
		return errors.System.Newf("remote artifact delivery is not running")
	}
	workers := append([]*remoteArtifactDeliveryWorker(nil), this.workers...)
	this.mutex.Unlock()
	goals, err := this.flushGoals(ctx, workers)
	if err != nil {
		return err
	}
	for _, worker := range workers {
		worker.notify()
	}
	for {
		complete := true
		for _, goal := range goals {
			status, statusErr := this.receipts.store.targetStatus(ctx, goal.fileName, goal.entry)
			if statusErr != nil {
				return statusErr
			}
			if status != remoteArtifactReceiptTargetAcknowledged {
				complete = false
				break
			}
		}
		if complete {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.System.Newf("cannot flush remote artifact delivery: %w", ctx.Err())
		case <-this.context.Done():
			return errors.System.Newf("remote artifact delivery stopped before flush completed")
		case <-this.progress:
		}
	}
}

func (this *RemoteArtifactDelivery) flushGoals(ctx context.Context, workers []*remoteArtifactDeliveryWorker) ([]remoteArtifactDeliveryFlushGoal, error) {
	names, err := listRemoteArtifactSourceNames(ctx, this.source)
	if err != nil {
		return nil, err
	}
	byTarget := make(map[configuration.AuditlogTargetName]remoteArtifactTargetEntry, len(workers))
	for _, worker := range workers {
		byTarget[worker.entry.scope.Target] = worker.entry
	}
	var result []remoteArtifactDeliveryFlushGoal
	for _, name := range names {
		selected, err := this.receipts.store.deliveryTargets(ctx, name)
		if err != nil {
			return nil, err
		}
		for _, receiptTarget := range selected {
			if receiptTarget.AcknowledgedAt != "" && receiptTarget.SuccessAuditedAt != "" {
				continue
			}
			entry, exists := byTarget[receiptTarget.Target]
			if !exists {
				return nil, errors.Config.Newf("remote artifact %q selects unconfigured target %q", name, receiptTarget.Target)
			}
			if entry.destinationFingerprint != receiptTarget.DestinationFingerprint {
				return nil, errors.Config.Newf("remote artifact target %q uses a different destination than the delivery receipt", receiptTarget.Target)
			}
			result = append(result, remoteArtifactDeliveryFlushGoal{fileName: name, entry: entry})
		}
	}
	return result, nil
}

func (this *remoteArtifactDeliveryWorker) run(ctx context.Context) {
	failures := uint(0)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if this.pending != nil {
			if err := this.acknowledgePending(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				failures++
				if !this.waitAfterFailure(ctx, failures, this.pending.artifact.FileName(), err) {
					return
				}
				continue
			}
		}
		if this.auditPending != nil {
			if err := this.completeAuditPending(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				failures++
				if !this.waitAfterFailure(ctx, failures, this.auditPending.event.FileName, err) {
					return
				}
				continue
			}
		}
		if err := this.scan(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			name := ""
			if this.pending != nil {
				name = this.pending.artifact.FileName()
			}
			if !this.waitAfterFailure(ctx, failures, name, err) {
				return
			}
			continue
		}
		if failures > 0 {
			this.logger.Info("remote artifact delivery recovered")
		}
		failures = 0
		_, ok := waitRemoteDeliveryIdle(ctx, this.wake, this.discoveryWake, this.options.idleDelay)
		if !ok {
			return
		}
	}
}

func (this *remoteArtifactDeliveryWorker) scan(ctx context.Context) error {
	names, err := listRemoteArtifactSourceNames(ctx, this.source)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := this.deliver(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

func (this *remoteArtifactDeliveryWorker) deliver(ctx context.Context, name string) error {
	status, err := this.receipts.targetStatus(ctx, name, this.entry)
	if err != nil {
		return err
	}
	if status == remoteArtifactReceiptTargetFailureAuditPending {
		if err := this.resumePendingAudit(ctx, name); err != nil {
			return err
		}
		status = remoteArtifactReceiptTargetPending
	}
	if status == remoteArtifactReceiptTargetSuccessAuditPending {
		return this.resumePendingAudit(ctx, name)
	}
	if status != remoteArtifactReceiptTargetPending {
		return nil
	}
	handle, err := this.source.OpenSealedArtifact(ctx, name)
	if err != nil {
		return this.failDelivery(ctx, name, errors.System.Newf("cannot open sealed remote artifact %q: %w", name, err))
	}
	if isNilRemoteValue(handle) {
		return this.failDelivery(ctx, name, errors.System.Newf("remote artifact source returned a nil handle for %q", name))
	}
	closeHandle := closeRemoteArtifactHandleOnCancellation(ctx, handle)
	artifact, artifactErr := handle.RemoteArtifact()
	if artifactErr != nil {
		return this.failDelivery(ctx, name, goerrors.Join(errors.System.Newf("cannot obtain sealed remote artifact %q: %w", name, artifactErr), closeHandle()))
	}
	if artifact.FileName() != name {
		return this.failDelivery(ctx, name, goerrors.Join(errors.Config.Newf("remote artifact source opened %q as %q", name, artifact.FileName()), closeHandle()))
	}
	status, err = this.receipts.targetStatusForArtifact(ctx, artifact, this.entry)
	if err != nil {
		return goerrors.Join(err, closeHandle())
	}
	if status == remoteArtifactReceiptTargetFailureAuditPending {
		if err := this.resumePendingAudit(ctx, name); err != nil {
			return goerrors.Join(err, closeHandle())
		}
		status = remoteArtifactReceiptTargetPending
	}
	if status != remoteArtifactReceiptTargetPending {
		if status == remoteArtifactReceiptTargetSuccessAuditPending {
			return goerrors.Join(this.resumePendingAudit(ctx, name), closeHandle())
		}
		return closeHandle()
	}
	publishTarget := this.entry.publishTarget
	if isNilRemoteValue(publishTarget) {
		publishTarget = this.entry.target
	}
	attemptContext, cancelAttempt := context.WithTimeout(ctx, this.entry.publishAttemptTimeout)
	stopAttemptClose := context.AfterFunc(attemptContext, func() { _ = closeHandle() })
	publishErr := publishTarget.PublishArtifact(attemptContext, artifact)
	stopAttemptClose()
	cancelAttempt()
	closeErr := closeHandle()
	if publishErr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return this.failDelivery(ctx, name, goerrors.Join(publishErr, closeErr))
	}
	this.pending = &remoteArtifactDeliveryPending{artifact: artifact, acknowledgedAt: time.Now().UTC()}
	if closeErr != nil {
		this.logger.WithError(closeErr).With("artifact", name).Warn("cannot close delivered local remote artifact")
	}
	return this.acknowledgePending(ctx)
}

func (this *remoteArtifactDeliveryWorker) acknowledgePending(ctx context.Context) error {
	if this.pending == nil {
		return nil
	}
	if err := this.options.acknowledge(ctx, this.receipts, this.pending.artifact, this.entry, this.pending.acknowledgedAt); err != nil {
		return err
	}
	fileName := this.pending.artifact.FileName()
	this.pending = nil
	if this.options.auditor != nil {
		if err := this.resumePendingAudit(ctx, fileName); err != nil {
			return err
		}
	}
	notifyRemoteDelivery(this.progress)
	return nil
}

func (this *remoteArtifactDeliveryWorker) failDelivery(ctx context.Context, name string, deliveryErr error) error {
	if this.options.auditor == nil || ctx.Err() != nil {
		return deliveryErr
	}
	event, pending, err := this.receipts.beginDeliveryFailure(ctx, name, this.entry, remoteArtifactDeliveryErrorCategory(deliveryErr), time.Now().UTC())
	if err != nil {
		return goerrors.Join(deliveryErr, err)
	}
	if !pending {
		return deliveryErr
	}
	this.auditPending = &remoteArtifactDeliveryAuditPending{event: event}
	if err := this.completeAuditPending(ctx); err != nil {
		return goerrors.Join(deliveryErr, err)
	}
	return deliveryErr
}

func (this *remoteArtifactDeliveryWorker) resumePendingAudit(ctx context.Context, name string) error {
	if this.options.auditor == nil {
		return errors.Config.Newf("remote artifact delivery audit for %q is pending without an auditor", name)
	}
	event, pending, err := this.receipts.pendingDeliveryAudit(ctx, name, this.entry)
	if err != nil || !pending {
		return err
	}
	this.auditPending = &remoteArtifactDeliveryAuditPending{event: event}
	return this.completeAuditPending(ctx)
}

func (this *remoteArtifactDeliveryWorker) completeAuditPending(ctx context.Context) error {
	if this.auditPending == nil {
		return nil
	}
	if !this.auditPending.recorded {
		if err := this.options.auditor.RecordRemoteArtifactDelivery(ctx, this.auditPending.event); err != nil {
			return err
		}
		this.auditPending.recorded = true
	}
	if err := this.receipts.completeDeliveryAudit(ctx, this.auditPending.event, time.Now().UTC()); err != nil {
		return err
	}
	this.auditPending = nil
	notifyRemoteDelivery(this.progress)
	return nil
}

func newRemoteArtifactDeliveryAuditEvent(receipt remoteArtifactReceipt, target remoteArtifactReceiptTarget, state RemoteArtifactDeliveryAuditState) RemoteArtifactDeliveryAuditEvent {
	result := RemoteArtifactDeliveryAuditEvent{
		State:                  state,
		Scope:                  RemoteTargetScope{Auditlog: receipt.Auditlog, Target: target.Target},
		FileName:               receipt.FileName,
		OperationId:            target.AuditOperationId,
		destinationFingerprint: target.DestinationFingerprint,
	}
	if state == RemoteArtifactDeliveryAuditFailed {
		result.ErrorCategory = target.FailureErrorCategory
	}
	return result
}

func remoteArtifactDeliveryErrorCategory(err error) ErrorCategory {
	switch {
	case goerrors.Is(err, context.DeadlineExceeded):
		return ErrorCategoryNetwork
	case errors.IsType(err, errors.System):
		return ErrorCategorySystem
	case errors.IsType(err, errors.Config):
		return ErrorCategoryConfig
	case errors.IsType(err, errors.Network):
		return ErrorCategoryNetwork
	case errors.IsType(err, errors.User):
		return ErrorCategoryUser
	case errors.IsType(err, errors.Permission):
		return ErrorCategoryPermission
	case errors.IsType(err, errors.Expired):
		return ErrorCategoryExpired
	default:
		return ErrorCategoryUnknown
	}
}

func (this *remoteArtifactDeliveryWorker) waitAfterFailure(ctx context.Context, failures uint, name string, err error) bool {
	delay := remoteDeliveryBackoff(failures, remoteDeliveryOptions{
		initialBackoff: this.options.initialBackoff,
		maximumBackoff: this.options.maximumBackoff,
		jitter:         this.options.jitter,
	})
	logger := this.logger.WithError(err).With("retryIn", delay)
	if name != "" {
		logger = logger.With("artifact", name)
	}
	logger.Warn("remote artifact delivery failed; retaining local artifact")
	return waitRemoteDelivery(ctx, this.wake, delay)
}

func (this *remoteArtifactDeliveryWorker) notify() {
	notifyRemoteDelivery(this.wake)
}

func (this *remoteArtifactDeliveryWorker) notifyDiscovery() {
	notifyRemoteDelivery(this.discoveryWake)
}

func (this *RemoteArtifactDelivery) watch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-this.watcher.Events:
			if !ok {
				this.notifyDiscovery()
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Rename) != 0 {
				this.notifyDiscovery()
			}
		case _, ok := <-this.watcher.Errors:
			this.notifyDiscovery()
			if !ok {
				return
			}
		}
	}
}

func (this *RemoteArtifactDelivery) notifyDiscovery() {
	for _, worker := range this.workers {
		worker.notifyDiscovery()
	}
}

func listRemoteArtifactSourceNames(ctx context.Context, source RemoteArtifactSource) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	names, err := source.ListSealedArtifactNames(ctx)
	if err != nil {
		return nil, errors.System.Newf("cannot list sealed remote artifacts: %w", err)
	}
	names = append([]string(nil), names...)
	sort.Strings(names)
	for index, name := range names {
		if err := validateRemoteArtifactFileName(name); err != nil {
			return nil, errors.Config.Newf("remote artifact source returned an illegal sealed name: %w", err)
		}
		if index > 0 && names[index-1] == name {
			return nil, errors.Config.Newf("remote artifact source returned duplicate sealed name %q", name)
		}
	}
	return names, nil
}

func closeRemoteArtifactHandleOnCancellation(ctx context.Context, handle RemoteArtifactHandle) func() error {
	var once sync.Once
	var closeErr error
	closeHandle := func() {
		once.Do(func() { closeErr = handle.Close() })
	}
	stop := context.AfterFunc(ctx, closeHandle)
	return func() error {
		stop()
		closeHandle()
		return closeErr
	}
}
