package audit

import (
	"context"
	cryptorand "crypto/rand"
	goerrors "errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/fsnotify/fsnotify"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/nativeformat"
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
	encrypted              bool
	destinationFingerprint remoteDeliveryDestinationFingerprint
	publishAttemptTimeout  time.Duration
	cursor                 remoteDeliveryCursor
	lastRecord             journalHash
	options                remoteDeliveryOptions
	logger                 log.Logger
	wake                   chan struct{}
	discoveryWake          chan struct{}
	progress               chan<- struct{}
	confirmed              atomic.Uint64
	observed               chan journalSegmentFile
	forceRescan            atomic.Bool
	commitCursorHook       func() error
	reader                 remoteDeliverySegmentReader
}

type remoteDeliverySegmentReader struct {
	directory        string
	producerId       ProducerId
	identity         *Identity
	encrypted        bool
	previousSegment  journalHash
	previousRecord   journalHash
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
	segment    SealedSegment
	file       *os.File
	lastRecord journalHash
	exists     bool
	more       bool
	err        error
}

type remoteDeliveryPending struct {
	cursor     remoteDeliveryCursor
	lastRecord journalHash
}

type remoteDeliverySegmentScan struct {
	directory     string
	encrypted     bool
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
	journalDirectory, err := canonicalJournalDirectory(conf.Directory)
	if err != nil {
		return nil, err
	}
	producerDirectory := filepath.Join(journalDirectory, identity.ProducerId().String())
	keys, err := ResolveEncryptionPublicKey(conf.EncryptionPublicKey, conf.EncryptionPublicKeyFile)
	if err != nil {
		return nil, err
	}
	encrypted := !keys.IsZero()
	if err := inspectRemoteDeliveryDirectory(producerDirectory, encrypted, func(journalSegmentFile) {}); err != nil {
		return nil, err
	}
	producerStateDirectory, err := prepareRemoteDeliveryState(journalDirectory, identity.ProducerId())
	if err != nil {
		return nil, err
	}
	stateLockPath := filepath.Join(filepath.Dir(producerStateDirectory), journalLockFileName)
	stateLock, err := acquireJournalProcessLock(stateLockPath, journalFileMode)
	if err != nil {
		return nil, errors.System.Newf("cannot lock remote delivery state %q: %w", stateLockPath, err)
	}
	if err := validateLockedJournalPath(stateLock, stateLockPath); err != nil {
		_ = stateLock.Close()
		return nil, err
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
		if err := ensureJournalDirectory(targetStateDirectory, true); err != nil {
			cancel()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil, err
		}
		if err := validateRemoteDeliveryTargetState(targetStateDirectory); err != nil {
			cancel()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil, err
		}
		// Validate both signed bindings before the loader can promote cursor.tmp.
		var stored [2]remoteDeliveryCursor
		var storedExists [2]bool
		stored[0], storedExists[0], err = readRemoteDeliveryCursor(filepath.Join(targetStateDirectory, remoteDeliveryCursorFileName), identity, entry.scope.Target, entry.destinationFingerprint)
		if err == nil {
			var temporaryErr error
			stored[1], storedExists[1], temporaryErr = readRemoteDeliveryCursor(filepath.Join(targetStateDirectory, remoteDeliveryCursorTempFileName), identity, entry.scope.Target, entry.destinationFingerprint)
			if temporaryErr != nil {
				stored[1] = remoteDeliveryCursor{} // The loader discards invalid temporary files.
				storedExists[1] = false
			}
		}
		var recordTips [2]journalHash
		if err == nil {
			recordTips, err = validateRemoteDeliveryCursors(ctx, stored, producerDirectory, entry.scope.Target, encrypted, identity,
				func() (*journalSegmentWorkspace, error) { return newJournalSegmentWorkspaceInJournal(journalDirectory) })
		}
		if err != nil {
			cancel()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil, err
		}
		cursor, err := loadRemoteDeliveryCursor(producerStateDirectory, identity, entry.scope.Target, entry.destinationFingerprint)
		if err != nil {
			cancel()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil, err
		}
		var lastRecord journalHash
		validated := cursor.Sequence == 0 && !storedExists[0] && !storedExists[1]
		for i, candidate := range stored {
			if storedExists[i] && cursor.Sequence == candidate.Sequence && cursor.SegmentHash == candidate.SegmentHash {
				lastRecord = recordTips[i]
				validated = true
				break
			}
		}
		if !validated {
			cancel()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil, errors.System.Newf("loaded remote delivery cursor for target %q differs from validated local chain", entry.scope.Target)
		}
		observed := make(chan journalSegmentFile, remoteDeliveryObservedSegmentBuffer)
		worker := &remoteDeliveryWorker{
			scope:                  entry.scope,
			target:                 entry.target,
			producerDirectory:      producerDirectory,
			stateDirectory:         targetStateDirectory,
			identity:               identity,
			encrypted:              encrypted,
			destinationFingerprint: entry.destinationFingerprint,
			publishAttemptTimeout:  entry.publishAttemptTimeout,
			cursor:                 cursor,
			lastRecord:             lastRecord,
			options:                options,
			logger: log.GetLogger("audit.remote-delivery").
				With("auditlog", conf.Name).
				With("target", conf.Targets[index].Name),
			wake:          make(chan struct{}, 1),
			discoveryWake: make(chan struct{}, 1),
			progress:      result.progress,
			observed:      observed,
			reader: remoteDeliverySegmentReader{
				directory:       producerDirectory,
				producerId:      identity.ProducerId(),
				identity:        identity,
				encrypted:       encrypted,
				previousSegment: journalHash(cursor.SegmentHash),
				previousRecord:  lastRecord,
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
	wanted, err := remoteDeliveryTailSequence(workers[0].producerDirectory, workers[0].encrypted)
	if err != nil {
		return err
	}
	for _, worker := range workers {
		if wanted < worker.confirmed.Load() {
			return errors.System.Newf("remote delivery is missing locally confirmed segments for target %q", worker.scope.Target)
		}
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
	var pending *remoteDeliveryPending
	failures := uint(0)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if pending != nil {
			if err := this.commitPendingCursor(pending.cursor); err != nil {
				failures++
				if !this.waitAfterFailure(ctx, failures, pending.cursor.Sequence, err) {
					return
				}
				continue
			}
			if failures > 0 {
				this.logger.With("sequence", pending.cursor.Sequence).Info("remote audit delivery recovered")
			}
			this.lastRecord = pending.lastRecord
			this.reader.previousSegment = journalHash(pending.cursor.SegmentHash)
			this.reader.previousRecord = this.lastRecord
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
	if this.commitCursorHook != nil {
		if err := this.commitCursorHook(); err != nil {
			return err
		}
	}
	cursor, err := writeRemoteDeliveryCursor(this.stateDirectory, this.identity, this.scope.Target, this.destinationFingerprint, pending.Sequence, pending.SegmentHash)
	if err != nil {
		return err
	}
	this.cursor = cursor
	this.confirmed.Store(cursor.Sequence)
	notifyRemoteDelivery(this.progress)
	return nil
}

func (this *remoteDeliveryWorker) publishNext(ctx context.Context) (*remoteDeliveryPending, error) {
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
	pending := &remoteDeliveryPending{cursor: remoteDeliveryCursor{remoteDeliveryCursorContent: remoteDeliveryCursorContent{
		Sequence:    result.segment.Sequence(),
		SegmentHash: result.segment.Hash(),
	}}, lastRecord: result.lastRecord}
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
			sequence, hash, valid := parseNativeSegmentName(name, this.workers[0].encrypted)
			if !valid {
				if name != nativeActiveClear && name != nativeActiveEncrypted && name != nativeHeadFileName && !strings.HasPrefix(name, ".head-cbor-") {
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

func validateRemoteDeliveryCursors(ctx context.Context, cursors [2]remoteDeliveryCursor, directory string, target configuration.AuditlogTargetName, encrypted bool, identity *Identity, workspace func() (*journalSegmentWorkspace, error)) (records [2]journalHash, result error) {
	maximum := cursors[0].Sequence
	if cursors[1].Sequence > maximum {
		maximum = cursors[1].Sequence
	}
	if maximum == 0 {
		return records, ctx.Err()
	}
	iterator, err := newSortedJournalSegmentIteratorWithWorkspace(ctx, directory, workspace, func(entry os.DirEntry) (*journalSegmentFile, error) {
		candidate, err := parseRemoteDeliveryDirectoryEntry(directory, entry, encrypted)
		if err != nil || candidate.sequence == 0 {
			return nil, err
		}
		return &candidate, nil
	})
	if err != nil {
		return records, err
	}
	defer func() { result = goerrors.Join(result, iterator.Close()) }()
	expected := uint64(1)
	var previousSegment journalHash
	var lastRecord journalHash
	var pending *journalSegmentFile
	for {
		var candidate journalSegmentFile
		found := pending != nil
		if found {
			candidate, pending = *pending, nil
		} else {
			var err error
			candidate, found, err = iterator.Next(ctx)
			if err != nil {
				return records, err
			}
		}
		if !found || candidate.sequence > maximum {
			break
		}
		if candidate.sequence != expected {
			return records, errors.System.Newf("remote delivery cursor for target %q confirms missing or duplicate local segment %d", target, expected)
		}
		next, nextFound, err := iterator.Next(ctx)
		if err != nil {
			return records, err
		}
		if nextFound {
			if next.sequence == expected {
				return records, errors.System.Newf("remote delivery cursor for target %q confirms missing or duplicate local segment %d", target, expected)
			}
			pending = &next
		}
		segment, file, tip, err := openRemoteDeliverySegment(ctx, identity, identity.ProducerId(), candidate, encrypted, previousSegment, lastRecord)
		if err != nil {
			return records, errors.System.Newf("remote delivery cursor for target %q confirms invalid local segment %d: %w", target, expected, err)
		}
		if err := file.Close(); err != nil {
			return records, err
		}
		previousSegment, lastRecord = journalHash(segment.Hash()), tip
		for i, cursor := range cursors {
			if expected == cursor.Sequence {
				if segment.Hash() != cursor.SegmentHash {
					return records, errors.System.Newf("remote delivery cursor for target %q conflicts with or confirms missing local segment %d", target, cursor.Sequence)
				}
				records[i] = lastRecord
			}
		}
		if expected == maximum {
			return records, nil
		}
		expected++
	}
	return records, errors.System.Newf("remote delivery cursor for target %q conflicts with or confirms missing local segment %d", target, maximum)
}

func remoteDeliveryTailSequence(directory string, encrypted bool) (uint64, error) {
	var result uint64
	err := inspectRemoteDeliveryDirectory(directory, encrypted, func(candidate journalSegmentFile) {
		if candidate.sequence > result {
			result = candidate.sequence
		}
	})
	return result, err
}

func inspectRemoteDeliveryDirectory(directory string, encrypted bool, accept func(journalSegmentFile)) error {
	file, err := os.Open(directory)
	if err != nil {
		return errors.System.Newf("cannot inspect audit producer directory %q for delivery: %w", directory, err)
	}
	defer file.Close()
	for {
		entries, readErr := file.ReadDir(remoteDeliveryDirectoryReadBatch)
		for _, entry := range entries {
			candidate, parseErr := parseRemoteDeliveryDirectoryEntry(directory, entry, encrypted)
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

func parseRemoteDeliveryDirectoryEntry(directory string, entry os.DirEntry, encrypted bool) (journalSegmentFile, error) {
	switch entry.Name() {
	case nativeHeadFileName:
		if entry.Type().IsRegular() {
			return journalSegmentFile{}, nil
		}
	}
	if entry.Name() == nativeActiveClear && !encrypted || entry.Name() == nativeActiveEncrypted && encrypted || strings.HasPrefix(entry.Name(), ".head-cbor-") {
		if entry.Type().IsRegular() {
			return journalSegmentFile{}, nil
		}
	}
	sequence, hash, ok := parseNativeSegmentName(entry.Name(), encrypted)
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
		candidate.name = nativeSegmentName(candidate.sequence, candidate.hash, this.encrypted)
		candidate.path = filepath.Join(this.directory, candidate.name)
		segment, file, tip, err := openRemoteDeliverySegment(ctx, this.identity, this.producerId, candidate, this.encrypted, this.previousSegment, this.previousRecord)
		if err != nil {
			return remoteDeliverySegmentResult{err: goerrors.Join(err, this.Invalidate())}
		}
		return remoteDeliverySegmentResult{segment: segment, file: file, lastRecord: tip, exists: true, more: this.iterator != nil || this.rescanPending}
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
		encrypted:     this.encrypted,
		directoryFile: file,
		readBatchSize: readBatchSize,
		sorter: &journalSegmentSorter{
			directory:     this.directory,
			tempDirectory: this.tempDirectory,
			chunk:         make([]journalSegmentFile, 0, journalSegmentSortChunkSize),
		},
	}
	if this.scan.sorter.tempDirectory == "" {
		this.scan.sorter.newWorkspace = func() (*journalSegmentWorkspace, error) {
			return newJournalSegmentWorkspaceInJournal(filepath.Dir(this.directory))
		}
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
		candidate, err := parseRemoteDeliveryDirectoryEntry(this.directory, this.entries[this.entryIndex], this.encrypted)
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
		iterator.workspace = this.sorter.workspace
		this.sorter.workspace = nil
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

func openRemoteDeliverySegment(ctx context.Context, identity *Identity, producerId ProducerId, candidate journalSegmentFile, encrypted bool, previousSegment, previousRecord journalHash) (SealedSegment, *os.File, journalHash, error) {
	if err := ctx.Err(); err != nil {
		return SealedSegment{}, nil, journalHash{}, err
	}
	file, err := nativeOpenRegular(candidate.path)
	if err != nil {
		return SealedSegment{}, nil, journalHash{}, err
	}
	stopClosingFile := closeRemoteDeliveryFileOnCancellation(ctx, file)
	defer stopClosingFile()
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return SealedSegment{}, nil, journalHash{}, errors.System.Newf("cannot inspect sealed audit segment %q for delivery: %w", candidate.path, err)
	}
	if info.Size() <= int64(len(nativeformat.AuditMagic)) || info.Size() > nativeMaxSize {
		_ = file.Close()
		return SealedSegment{}, nil, journalHash{}, errors.System.Newf("invalid native audit segment size: %s", candidate.path)
	}
	var lastRecord journalHash
	if identity != nil {
		magic := make([]byte, len(nativeformat.AuditMagic))
		if _, err := file.ReadAt(magic, 0); err != nil || string(magic) != nativeformat.AuditMagic {
			_ = file.Close()
			return SealedSegment{}, nil, journalHash{}, errors.System.Newf("invalid native audit segment magic: %s: %v", candidate.path, err)
		}
		unit, _, tail, err := nativeformat.ReadUnitAt(file, int64(len(magic)), info.Size(), nativeformat.MaxAuditRecordPayload)
		if err != nil || tail || unit.Type != nativeformat.HeaderUnit {
			_ = file.Close()
			return SealedSegment{}, nil, journalHash{}, errors.System.Newf("invalid native audit segment header: %s: %v", candidate.path, err)
		}
		header, err := nativeformat.Unmarshal[nativeAuditHeader](unit.Payload, nativeformat.MaxMetadataPayload)
		if err != nil || (header.Recipient != "") != encrypted {
			_ = file.Close()
			return SealedSegment{}, nil, journalHash{}, errors.System.Newf("invalid native audit segment mode or header: %s: %v", candidate.path, err)
		}
		scanned, err := nativeScan(file, identity, candidate.sequence, previousSegment, previousRecord, journalHash{}, true, header.Recipient, false)
		if err != nil || !scanned.sealed || scanned.segmentHash != candidate.hash {
			_ = file.Close()
			return SealedSegment{}, nil, journalHash{}, errors.System.Newf("invalid sealed native audit segment %q (scan: %v, expected hash: %s, actual hash: %s)", candidate.path, err, candidate.hash, scanned.segmentHash)
		}
		lastRecord = scanned.lastRecord
	}
	segment, err := newSealedSegmentContext(ctx, producerId, candidate.sequence, SegmentHash(candidate.hash), info.Size(), file)
	if err != nil {
		_ = file.Close()
		return SealedSegment{}, nil, journalHash{}, err
	}
	segment.encrypted = encrypted
	return segment, file, lastRecord, nil
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
