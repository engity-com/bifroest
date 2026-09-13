package audit

import (
	"context"
	cryptorand "crypto/rand"
	goerrors "errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/fsnotify/fsnotify"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	defaultRemoteDeliveryIdleDelay      = time.Minute
	defaultRemoteDeliveryInitialBackoff = time.Second
	defaultRemoteDeliveryMaximumBackoff = 5 * time.Minute
	remoteDeliveryDirectoryReadBatch    = 128
	remoteDeliveryObservedSegmentBuffer = 256
)

type remoteDeliveryOptions struct {
	idleDelay      time.Duration
	initialBackoff time.Duration
	maximumBackoff time.Duration
	jitter         func(time.Duration) time.Duration
	newWatcher     func() (*fsnotify.Watcher, error)
	addWatch       func(*fsnotify.Watcher, string) error
}

func defaultRemoteDeliveryOptions() remoteDeliveryOptions {
	return remoteDeliveryOptions{
		idleDelay:      defaultRemoteDeliveryIdleDelay,
		initialBackoff: defaultRemoteDeliveryInitialBackoff,
		maximumBackoff: defaultRemoteDeliveryMaximumBackoff,
		jitter:         jitterRemoteDeliveryBackoff,
		newWatcher:     fsnotify.NewWatcher,
		addWatch:       func(watcher *fsnotify.Watcher, directory string) error { return watcher.Add(directory) },
	}
}

// RemoteDelivery owns one independent, sequential delivery worker per target.
// It never removes authoritative local journal segments.
type RemoteDelivery struct {
	mutex     sync.Mutex
	flushLock chan struct{}
	targets   *RemoteTargets
	stateLock *journalProcessLock
	workers   []*remoteDeliveryWorker
	context   context.Context
	cancel    context.CancelFunc
	wait      sync.WaitGroup
	started   bool
	closed    bool
	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
	progress  chan struct{}
	watcher   *fsnotify.Watcher
}

type remoteDeliveryWorker struct {
	scope                  RemoteTargetScope
	target                 RemoteTarget
	producerDirectory      string
	stateDirectory         string
	identity               *Identity
	destinationFingerprint remoteDeliveryDestinationFingerprint
	publishAttemptTimeout  time.Duration
	cursor                 remoteDeliveryCursor
	options                remoteDeliveryOptions
	logger                 log.Logger
	wake                   chan struct{}
	discoveryWake          chan struct{}
	progress               chan<- struct{}
	confirmed              atomic.Uint64
	observed               chan journalSegmentFile
	forceRescan            atomic.Bool
	reader                 remoteDeliverySegmentReader
}

type remoteDeliverySegmentReader struct {
	directory        string
	producerId       ProducerId
	iterator         *sortedJournalSegmentIterator
	scan             *remoteDeliverySegmentScan
	candidate        *journalSegmentFile
	exhausted        bool
	rescanPending    bool
	poisoned         error
	gapVerification  bool
	readBatchSize    int
	tempDirectory    string
	scanEntryHook    func(context.Context, journalSegmentFile) error
	scanCount        uint64
	maximumScanChunk int
}

type remoteDeliverySegmentResult struct {
	segment SealedSegment
	file    *os.File
	exists  bool
	more    bool
	err     error
}

type remoteDeliverySegmentScan struct {
	directory     string
	directoryFile *os.File
	sorter        *journalSegmentSorter
	entries       []os.DirEntry
	entryIndex    int
	atEOF         bool
	readBatchSize int
}

// NewRemoteDelivery prepares targets and their durable cursors without doing
// network I/O. Call Start after the surrounding service is fully prepared.
func NewRemoteDelivery(ctx context.Context, conf *configuration.Auditlog, identity *Identity) (*RemoteDelivery, error) {
	if conf == nil {
		return nil, errors.Config.Newf("nil auditlog configuration")
	}
	if !conf.Enabled || len(conf.Targets) == 0 {
		return nil, errors.Config.Newf("remote delivery requires an enabled auditlog with targets")
	}
	if identity == nil || identity.ProducerId().IsZero() {
		return nil, errors.Config.Newf("nil audit identity")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	targets, err := NewRemoteTargets(ctx, conf.Name, conf.Targets)
	if err != nil {
		return nil, err
	}
	delivery, err := newRemoteDelivery(ctx, conf, identity, targets, defaultRemoteDeliveryOptions())
	if err != nil {
		return nil, goerrors.Join(err, targets.Close())
	}
	return delivery, nil
}

func newRemoteDelivery(ctx context.Context, conf *configuration.Auditlog, identity *Identity, targets *RemoteTargets, options remoteDeliveryOptions) (*RemoteDelivery, error) {
	if targets == nil || len(targets.entries) != len(conf.Targets) {
		return nil, errors.System.Newf("remote delivery target set does not match configuration")
	}
	journalDirectory, err := canonicalJournalDirectory(conf.Journal.Directory)
	if err != nil {
		return nil, err
	}
	producerDirectory := filepath.Join(journalDirectory, identity.ProducerId().String())
	producerStateDirectory, err := prepareRemoteDeliveryState(journalDirectory, identity.ProducerId())
	if err != nil {
		return nil, err
	}
	stateLockPath := filepath.Join(filepath.Dir(producerStateDirectory), journalLockFileName)
	stateLock, err := acquireJournalProcessLock(stateLockPath, journalFileMode)
	if err != nil {
		return nil, errors.System.Newf("cannot lock remote delivery state %q: %w", stateLockPath, err)
	}
	stateLockCommitted := false
	defer func() {
		if !stateLockCommitted {
			_ = stateLock.Close()
		}
	}()
	producerStateDirectory, err = prepareRemoteDeliveryState(journalDirectory, identity.ProducerId())
	if err != nil {
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
	deliveryLogger := log.GetLogger("audit.remote-delivery").With("auditlog", conf.Name)
	watcher, watcherErr := newWatcher()
	if watcherErr != nil {
		deliveryLogger.WithError(watcherErr).Warn("cannot create audit delivery directory watcher; using periodic polling")
		watcher = nil
	} else if watcher == nil {
		deliveryLogger.Warn("audit delivery directory watcher factory returned nil; using periodic polling")
	} else if watchErr := addWatch(watcher, producerDirectory); watchErr != nil {
		_ = watcher.Close()
		deliveryLogger.WithError(watchErr).With("directory", producerDirectory).Warn("cannot watch audit producer directory for delivery; using periodic polling")
		watcher = nil
	}
	workerContext, cancel := context.WithCancel(ctx)
	result := &RemoteDelivery{
		targets:   targets,
		stateLock: stateLock,
		context:   workerContext,
		cancel:    cancel,
		closeDone: make(chan struct{}),
		progress:  make(chan struct{}, 1),
		flushLock: make(chan struct{}, 1),
		watcher:   watcher,
	}
	result.flushLock <- struct{}{}
	for index, entry := range targets.entries {
		targetStateDirectory := filepath.Join(producerStateDirectory, remoteDeliveryTargetStateName(entry.scope.Target))
		cursor, err := loadRemoteDeliveryCursor(producerStateDirectory, identity, entry.scope.Target, entry.destinationFingerprint)
		if err != nil {
			cancel()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil, err
		}
		if err := validateRemoteDeliveryCursor(cursor, producerDirectory, entry.scope.Target); err != nil {
			cancel()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil, err
		}
		observed := make(chan journalSegmentFile, remoteDeliveryObservedSegmentBuffer)
		worker := &remoteDeliveryWorker{
			scope:                  entry.scope,
			target:                 entry.target,
			producerDirectory:      producerDirectory,
			stateDirectory:         targetStateDirectory,
			identity:               identity,
			destinationFingerprint: entry.destinationFingerprint,
			publishAttemptTimeout:  entry.publishAttemptTimeout,
			cursor:                 cursor,
			options:                options,
			logger: log.GetLogger("audit.remote-delivery").
				With("auditlog", conf.Name).
				With("target", conf.Targets[index].Name),
			wake:          make(chan struct{}, 1),
			discoveryWake: make(chan struct{}, 1),
			progress:      result.progress,
			observed:      observed,
			reader: remoteDeliverySegmentReader{
				directory:  producerDirectory,
				producerId: identity.ProducerId(),
			},
		}
		worker.confirmed.Store(cursor.Sequence)
		result.workers = append(result.workers, worker)
	}
	stateLockCommitted = true
	return result, nil
}

func (this *RemoteDelivery) Start() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return errors.System.Newf("remote audit delivery is closed")
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
		go func() {
			defer this.wait.Done()
			worker.run(this.context)
		}()
	}
	return nil
}

func (this *RemoteDelivery) Close() error {
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
		this.closeErr = goerrors.Join(watcherErr, targetErr, this.stateLock.Close())
		close(this.closeDone)
	})
	<-this.closeDone
	return this.closeErr
}

// Flush wakes all workers and waits until every target has durably confirmed
// the sealed segments visible when Flush starts.
func (this *RemoteDelivery) Flush(ctx context.Context) error {
	if this == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return errors.System.Newf("cannot flush remote audit delivery: %w", ctx.Err())
	case <-this.context.Done():
		return errors.System.Newf("remote audit delivery stopped before flush")
	case <-this.flushLock:
	}
	defer func() { this.flushLock <- struct{}{} }()
	this.mutex.Lock()
	if this.closed || !this.started {
		this.mutex.Unlock()
		return errors.System.Newf("remote audit delivery is not running")
	}
	workers := append([]*remoteDeliveryWorker(nil), this.workers...)
	this.mutex.Unlock()
	if len(workers) == 0 {
		return nil
	}
	wanted, err := remoteDeliveryTailSequence(workers[0].producerDirectory)
	if err != nil {
		return err
	}
	if wanted == 0 {
		return nil
	}
	for _, worker := range workers {
		worker.requestRescan()
	}
	for {
		complete := true
		for _, worker := range workers {
			if worker.confirmed.Load() < wanted {
				complete = false
				break
			}
		}
		if complete {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.System.Newf("cannot flush remote audit delivery through segment %d: %w", wanted, ctx.Err())
		case <-this.context.Done():
			return errors.System.Newf("remote audit delivery stopped before segment %d was confirmed", wanted)
		case <-this.progress:
		}
	}
}

func (this *remoteDeliveryWorker) run(ctx context.Context) {
	defer this.reader.Close()
	var pending *remoteDeliveryCursor
	failures := uint(0)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if pending != nil {
			if err := this.commitPendingCursor(*pending); err != nil {
				failures++
				if !this.waitAfterFailure(ctx, failures, pending.Sequence, err) {
					return
				}
				continue
			}
			if failures > 0 {
				this.logger.With("sequence", pending.Sequence).Info("remote audit delivery recovered")
			}
			pending = nil
			failures = 0
			continue
		}

		next, err := this.publishNext(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			if !this.waitAfterFailure(ctx, failures, this.cursor.Sequence+1, err) {
				return
			}
			continue
		}
		if next == nil {
			failures = 0
			continue
		}
		pending = next
	}
}

func (this *remoteDeliveryWorker) commitPendingCursor(pending remoteDeliveryCursor) error {
	cursor, err := writeRemoteDeliveryCursor(this.stateDirectory, this.identity, this.scope.Target, this.destinationFingerprint, pending.Sequence, pending.SegmentHash)
	if err != nil {
		return err
	}
	this.cursor = cursor
	this.confirmed.Store(cursor.Sequence)
	notifyRemoteDelivery(this.progress)
	return nil
}

func (this *remoteDeliveryWorker) publishNext(ctx context.Context) (*remoteDeliveryCursor, error) {
	attemptContext, cancelAttempt := context.WithTimeout(ctx, this.publishAttemptTimeout)
	result := this.reader.Next(attemptContext, this.cursor.Sequence, this.observed, &this.forceRescan)
	if result.err != nil {
		cancelAttempt()
		return nil, result.err
	}
	if !result.exists {
		cancelAttempt()
		if result.more {
			return nil, nil
		}
		timedOut, ok := waitRemoteDeliveryIdle(ctx, this.wake, this.discoveryWake, this.options.idleDelay)
		if !ok {
			return nil, ctx.Err()
		}
		if timedOut {
			this.forceRescan.Store(true)
		}
		return nil, nil
	}

	stopClosingFile := closeRemoteDeliveryFileOnCancellation(attemptContext, result.file)
	publishErr := this.target.Publish(attemptContext, result.segment)
	stopClosingFile()
	cancelAttempt()
	closeErr := result.file.Close()
	if publishErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, goerrors.Join(publishErr, this.reader.Invalidate())
	}
	pending := &remoteDeliveryCursor{remoteDeliveryCursorContent: remoteDeliveryCursorContent{
		Sequence:    result.segment.Sequence(),
		SegmentHash: result.segment.Hash(),
	}}
	if closeErr != nil {
		this.logger.WithError(closeErr).With("sequence", result.segment.Sequence()).Warn("cannot close delivered local audit segment")
	}
	return pending, nil
}

func (this *remoteDeliveryWorker) waitAfterFailure(ctx context.Context, failures uint, sequence uint64, err error) bool {
	delay := remoteDeliveryBackoff(failures, this.options)
	this.logger.WithError(err).
		With("sequence", sequence).
		With("retryIn", delay).
		Warn("remote audit delivery failed; retaining local segment")
	return waitRemoteDelivery(ctx, this.wake, delay)
}

func (this *remoteDeliveryWorker) notify() {
	notifyRemoteDelivery(this.wake)
}

func (this *remoteDeliveryWorker) requestRescan() {
	this.forceRescan.Store(true)
	this.notify()
}

func (this *remoteDeliveryWorker) requestDiscoveryRescan() {
	this.forceRescan.Store(true)
	notifyRemoteDelivery(this.discoveryWake)
}

func (this *RemoteDelivery) watch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-this.watcher.Events:
			if !ok {
				for _, worker := range this.workers {
					worker.requestDiscoveryRescan()
				}
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			name := filepath.Base(event.Name)
			sequence, hash, valid := parseSealedJournalFileName(name)
			if !valid {
				if name != journalActiveFileName && name != journalHeadFileName && name != journalHeadTempFileName {
					for _, worker := range this.workers {
						worker.requestDiscoveryRescan()
					}
				}
				continue
			}
			candidate := journalSegmentFile{name: name, path: filepath.Join(filepath.Dir(event.Name), name), sequence: sequence, hash: hash}
			for _, worker := range this.workers {
				worker.observe(candidate)
			}
		case _, ok := <-this.watcher.Errors:
			for _, worker := range this.workers {
				worker.requestDiscoveryRescan()
			}
			if !ok {
				return
			}
		}
	}
}

func (this *remoteDeliveryWorker) observe(candidate journalSegmentFile) {
	select {
	case this.observed <- candidate:
	default:
		this.forceRescan.Store(true)
	}
	notifyRemoteDelivery(this.discoveryWake)
}

func validateRemoteDeliveryCursor(cursor remoteDeliveryCursor, directory string, target configuration.AuditlogTargetName) error {
	matches := 0
	hashMatches := false
	err := inspectRemoteDeliveryDirectory(directory, func(candidate journalSegmentFile) {
		if candidate.sequence == cursor.Sequence {
			matches++
			hashMatches = hashMatches || SegmentHash(candidate.hash) == cursor.SegmentHash
		}
	})
	if err != nil {
		return err
	}
	if cursor.Sequence == 0 || matches == 1 && hashMatches {
		return nil
	}
	return errors.System.Newf("remote delivery cursor for target %q conflicts with or confirms missing local segment %d", target, cursor.Sequence)
}

func remoteDeliveryTailSequence(directory string) (uint64, error) {
	var result uint64
	err := inspectRemoteDeliveryDirectory(directory, func(candidate journalSegmentFile) {
		if candidate.sequence > result {
			result = candidate.sequence
		}
	})
	return result, err
}

func inspectRemoteDeliveryDirectory(directory string, accept func(journalSegmentFile)) error {
	file, err := os.Open(directory)
	if err != nil {
		return errors.System.Newf("cannot inspect audit producer directory %q for delivery: %w", directory, err)
	}
	defer file.Close()
	for {
		entries, readErr := file.ReadDir(remoteDeliveryDirectoryReadBatch)
		for _, entry := range entries {
			candidate, parseErr := parseRemoteDeliveryDirectoryEntry(directory, entry)
			if parseErr != nil {
				return parseErr
			}
			if candidate.sequence != 0 {
				accept(candidate)
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return errors.System.Newf("cannot inspect audit producer directory %q for delivery: %w", directory, readErr)
		}
	}
}

func parseRemoteDeliveryDirectoryEntry(directory string, entry os.DirEntry) (journalSegmentFile, error) {
	switch entry.Name() {
	case journalActiveFileName, journalHeadFileName, journalHeadTempFileName:
		return journalSegmentFile{}, nil
	}
	sequence, hash, ok := parseSealedJournalFileName(entry.Name())
	if !ok || !entry.Type().IsRegular() {
		return journalSegmentFile{}, errors.Config.Newf("audit producer directory %q contains unsupported delivery entry %q", directory, entry.Name())
	}
	return journalSegmentFile{name: entry.Name(), path: filepath.Join(directory, entry.Name()), sequence: sequence, hash: hash}, nil
}

func (this *remoteDeliverySegmentReader) Next(ctx context.Context, confirmed uint64, observed <-chan journalSegmentFile, forceRescan *atomic.Bool) remoteDeliverySegmentResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return remoteDeliverySegmentResult{err: err}
	}
	if this.poisoned != nil {
		return remoteDeliverySegmentResult{err: this.poisoned}
	}
	expected := confirmed + 1
	if expected == 0 {
		return remoteDeliverySegmentResult{err: errors.System.Newf("remote delivery sequence overflow after %d", confirmed)}
	}
	if err := this.observeChanges(ctx, observed, forceRescan); err != nil {
		return remoteDeliverySegmentResult{err: err}
	}

	ready, err := this.ensureIterator(ctx)
	if err != nil {
		return remoteDeliverySegmentResult{err: err}
	}
	if !ready {
		return remoteDeliverySegmentResult{more: this.scan != nil || this.rescanPending}
	}

	for {
		if this.candidate == nil {
			candidate, found, err := this.iterator.Next(ctx)
			if err != nil {
				return remoteDeliverySegmentResult{err: err}
			}
			if !found {
				return this.finishIteratorWithoutCandidate()
			}
			this.candidate = &candidate
		}
		next, found, err := this.iterator.Next(ctx)
		if err != nil {
			return remoteDeliverySegmentResult{err: err}
		}
		candidate := *this.candidate
		this.candidate = nil
		if found {
			if next.sequence == candidate.sequence {
				return this.poisonDuplicate(candidate.sequence)
			}
			this.candidate = &next
		} else {
			if err := this.closeIterator(); err != nil {
				return remoteDeliverySegmentResult{err: err}
			}
			this.exhausted = true
		}
		if candidate.sequence <= confirmed {
			if this.iterator == nil {
				return this.finishIteratorWithoutCandidate()
			}
			continue
		}
		if candidate.sequence > expected {
			if err := this.observeChanges(ctx, observed, forceRescan); err != nil {
				return remoteDeliverySegmentResult{err: err}
			}
			return this.handleGap(expected, candidate.sequence)
		}
		this.gapVerification = false
		segment, file, err := openRemoteDeliverySegment(ctx, this.producerId, candidate)
		if err != nil {
			return remoteDeliverySegmentResult{err: goerrors.Join(err, this.Invalidate())}
		}
		return remoteDeliverySegmentResult{segment: segment, file: file, exists: true, more: this.iterator != nil || this.rescanPending}
	}
}

func (this *remoteDeliverySegmentReader) ensureIterator(ctx context.Context) (bool, error) {
	if this.iterator != nil {
		return true, nil
	}
	if this.scan == nil && this.exhausted && !this.rescanPending {
		this.gapVerification = false
		return false, nil
	}
	if this.scan == nil {
		if err := this.startScan(); err != nil {
			return false, err
		}
		this.rescanPending = false
	}
	iterator, complete, err := this.scan.advance(ctx, this.scanEntryHook, &this.maximumScanChunk)
	if err != nil {
		if ctx.Err() == nil {
			_ = this.discardScan()
		}
		return false, err
	}
	if !complete {
		return false, nil
	}
	this.scan = nil
	this.iterator = iterator
	this.candidate = nil
	this.exhausted = false
	return true, nil
}

func (this *remoteDeliverySegmentReader) observeChanges(ctx context.Context, observed <-chan journalSegmentFile, forceRescan *atomic.Bool) error {
	if forceRescan != nil && forceRescan.Swap(false) {
		this.rescanPending = true
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, open := <-observed:
			if !open {
				return nil
			}
			this.rescanPending = true
		default:
			return nil
		}
	}
}

func (this *remoteDeliverySegmentReader) startScan() error {
	file, err := os.Open(this.directory)
	if err != nil {
		return errors.System.Newf("cannot inspect audit producer directory %q for delivery: %w", this.directory, err)
	}
	readBatchSize := this.readBatchSize
	if readBatchSize <= 0 {
		readBatchSize = remoteDeliveryDirectoryReadBatch
	}
	this.scan = &remoteDeliverySegmentScan{
		directory:     this.directory,
		directoryFile: file,
		readBatchSize: readBatchSize,
		sorter: &journalSegmentSorter{
			directory:     this.directory,
			tempDirectory: this.tempDirectory,
			chunk:         make([]journalSegmentFile, 0, journalSegmentSortChunkSize),
		},
	}
	if this.scan.sorter.tempDirectory == "" {
		this.scan.sorter.tempDirectory = os.TempDir()
	}
	this.scanCount++
	return nil
}

func (this *remoteDeliverySegmentScan) advance(ctx context.Context, hook func(context.Context, journalSegmentFile) error, maximumChunk *int) (*sortedJournalSegmentIterator, bool, error) {
	if err := this.sorter.resume(ctx); err != nil {
		return nil, false, err
	}
	for this.entryIndex < len(this.entries) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		candidate, err := parseRemoteDeliveryDirectoryEntry(this.directory, this.entries[this.entryIndex])
		if err != nil {
			return nil, false, err
		}
		if candidate.sequence != 0 {
			err := this.sorter.add(ctx, candidate)
			this.entryIndex++
			if err != nil {
				return nil, false, err
			}
			if len(this.sorter.chunk) > *maximumChunk {
				*maximumChunk = len(this.sorter.chunk)
			}
		} else {
			this.entryIndex++
		}
		if hook != nil && candidate.sequence != 0 {
			if err := hook(ctx, candidate); err != nil {
				return nil, false, err
			}
		}
	}
	this.entries = nil
	this.entryIndex = 0
	if this.atEOF {
		if this.directoryFile != nil {
			if err := this.directoryFile.Close(); err != nil {
				return nil, false, errors.System.Newf("cannot close audit producer directory %q after delivery scan: %w", this.directory, err)
			}
			this.directoryFile = nil
		}
		iterator, err := this.sorter.finish(ctx)
		if err != nil {
			return nil, false, err
		}
		return iterator, true, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	entries, err := this.directoryFile.ReadDir(this.readBatchSize)
	this.entries = entries
	this.atEOF = err == io.EOF
	if err != nil && err != io.EOF {
		return nil, false, errors.System.Newf("cannot inspect audit producer directory %q for delivery: %w", this.directory, err)
	}
	return nil, false, nil
}

func (this *remoteDeliverySegmentReader) finishIteratorWithoutCandidate() remoteDeliverySegmentResult {
	if this.iterator != nil {
		if err := this.closeIterator(); err != nil {
			return remoteDeliverySegmentResult{err: err}
		}
	}
	this.exhausted = true
	this.gapVerification = false
	if this.rescanPending {
		return remoteDeliverySegmentResult{more: true}
	}
	return remoteDeliverySegmentResult{}
}

func (this *remoteDeliverySegmentReader) handleGap(expected, later uint64) remoteDeliverySegmentResult {
	changesDuringScan := this.rescanPending
	if err := this.closeIterator(); err != nil {
		return remoteDeliverySegmentResult{err: err}
	}
	this.exhausted = false
	this.rescanPending = true
	if !this.gapVerification || changesDuringScan {
		this.gapVerification = true
		return remoteDeliverySegmentResult{more: true}
	}
	return this.poisonGap(expected, later)
}

func (this *remoteDeliverySegmentReader) poisonDuplicate(sequence uint64) remoteDeliverySegmentResult {
	this.poisoned = errors.System.Newf("remote delivery found multiple local segments with sequence %d", sequence)
	_ = this.Close()
	this.exhausted = true
	return remoteDeliverySegmentResult{err: this.poisoned}
}

func (this *remoteDeliverySegmentReader) poisonGap(expected, later uint64) remoteDeliverySegmentResult {
	this.poisoned = errors.System.Newf("remote delivery is missing local segment sequence %d before later sequence %d", expected, later)
	_ = this.Close()
	this.exhausted = true
	return remoteDeliverySegmentResult{err: this.poisoned}
}

func (this *remoteDeliverySegmentReader) closeIterator() error {
	err := this.iterator.Close()
	this.iterator = nil
	this.candidate = nil
	return err
}

func (this *remoteDeliverySegmentReader) discardScan() error {
	if this.scan == nil {
		return nil
	}
	err := this.scan.Close()
	this.scan = nil
	return err
}

func (this *remoteDeliverySegmentReader) Close() error {
	return goerrors.Join(this.closeIterator(), this.discardScan())
}

func (this *remoteDeliverySegmentReader) Invalidate() error {
	err := this.Close()
	this.exhausted = false
	this.rescanPending = true
	this.gapVerification = false
	return err
}

func (this *remoteDeliverySegmentScan) Close() error {
	if this == nil {
		return nil
	}
	var closeErr error
	if this.directoryFile != nil {
		closeErr = this.directoryFile.Close()
		this.directoryFile = nil
	}
	return goerrors.Join(closeErr, this.sorter.cleanup())
}

func openRemoteDeliverySegment(ctx context.Context, producerId ProducerId, candidate journalSegmentFile) (SealedSegment, *os.File, error) {
	if err := ctx.Err(); err != nil {
		return SealedSegment{}, nil, err
	}
	file, err := openSealedJournal(candidate.path)
	if err != nil {
		return SealedSegment{}, nil, err
	}
	stopClosingFile := closeRemoteDeliveryFileOnCancellation(ctx, file)
	defer stopClosingFile()
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return SealedSegment{}, nil, errors.System.Newf("cannot inspect sealed audit segment %q for delivery: %w", candidate.path, err)
	}
	segment, err := newSealedSegmentContext(ctx, producerId, candidate.sequence, SegmentHash(candidate.hash), info.Size(), file)
	if err != nil {
		_ = file.Close()
		return SealedSegment{}, nil, err
	}
	return segment, file, nil
}

func closeRemoteDeliveryFileOnCancellation(ctx context.Context, file *os.File) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = file.Close()
		close(done)
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}

func remoteDeliveryBackoff(failures uint, options remoteDeliveryOptions) time.Duration {
	nominal := options.initialBackoff
	for attempt := uint(1); attempt < failures && nominal < options.maximumBackoff; attempt++ {
		if nominal > options.maximumBackoff/2 {
			nominal = options.maximumBackoff
		} else {
			nominal *= 2
		}
	}
	if nominal > options.maximumBackoff {
		nominal = options.maximumBackoff
	}
	if options.jitter == nil {
		return nominal
	}
	return options.jitter(nominal)
}

func jitterRemoteDeliveryBackoff(nominal time.Duration) time.Duration {
	if nominal <= 1 {
		return nominal
	}
	minimum := nominal / 2
	spread := nominal - minimum
	random, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(spread)+1))
	if err != nil {
		return nominal
	}
	return minimum + time.Duration(random.Int64())
}

func waitRemoteDelivery(ctx context.Context, wake <-chan struct{}, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	case <-timer.C:
		return true
	}
}

func waitRemoteDeliveryIdle(ctx context.Context, wake, discoveryWake <-chan struct{}, delay time.Duration) (bool, bool) {
	if delay <= 0 {
		return true, ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false, false
	case <-wake:
		return false, true
	case <-discoveryWake:
		return false, true
	case <-timer.C:
		return true, true
	}
}

func notifyRemoteDelivery(target chan<- struct{}) {
	select {
	case target <- struct{}{}:
	default:
	}
}
