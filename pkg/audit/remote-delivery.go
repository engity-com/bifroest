package audit

import (
	"context"
	cryptorand "crypto/rand"
	goerrors "errors"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	defaultRemoteDeliveryIdleDelay      = time.Second
	defaultRemoteDeliveryInitialBackoff = time.Second
	defaultRemoteDeliveryMaximumBackoff = 5 * time.Minute
)

type remoteDeliveryOptions struct {
	idleDelay      time.Duration
	initialBackoff time.Duration
	maximumBackoff time.Duration
	jitter         func(time.Duration) time.Duration
}

func defaultRemoteDeliveryOptions() remoteDeliveryOptions {
	return remoteDeliveryOptions{
		idleDelay:      defaultRemoteDeliveryIdleDelay,
		initialBackoff: defaultRemoteDeliveryInitialBackoff,
		maximumBackoff: defaultRemoteDeliveryMaximumBackoff,
		jitter:         jitterRemoteDeliveryBackoff,
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
}

type remoteDeliveryWorker struct {
	scope             RemoteTargetScope
	target            RemoteTarget
	producerDirectory string
	stateDirectory    string
	identity          *Identity
	cursor            remoteDeliveryCursor
	options           remoteDeliveryOptions
	logger            log.Logger
	wake              chan struct{}
	progress          chan<- struct{}
	confirmed         atomic.Uint64
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
	segments, err := listRemoteDeliverySegments(producerDirectory)
	if err != nil {
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
	workerContext, cancel := context.WithCancel(ctx)
	result := &RemoteDelivery{
		targets:   targets,
		stateLock: stateLock,
		context:   workerContext,
		cancel:    cancel,
		closeDone: make(chan struct{}),
		progress:  make(chan struct{}, 1),
		flushLock: make(chan struct{}, 1),
	}
	result.flushLock <- struct{}{}
	for index, entry := range targets.entries {
		targetStateDirectory := filepath.Join(producerStateDirectory, remoteDeliveryTargetStateName(entry.scope.Target))
		cursor, err := loadRemoteDeliveryCursor(producerStateDirectory, identity, entry.scope.Target)
		if err != nil {
			cancel()
			return nil, err
		}
		if err := validateRemoteDeliveryCursor(cursor, segments, entry.scope.Target); err != nil {
			cancel()
			return nil, err
		}
		worker := &remoteDeliveryWorker{
			scope:             entry.scope,
			target:            entry.target,
			producerDirectory: producerDirectory,
			stateDirectory:    targetStateDirectory,
			identity:          identity,
			cursor:            cursor,
			options:           options,
			logger: log.GetLogger("audit.remote-delivery").
				With("auditlog", conf.Name).
				With("target", conf.Targets[index].Name),
			wake:     make(chan struct{}, 1),
			progress: result.progress,
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
		this.wait.Wait()
		this.closeErr = goerrors.Join(this.targets.Close(), this.stateLock.Close())
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
	segments, err := listRemoteDeliverySegments(workers[0].producerDirectory)
	if err != nil {
		return err
	}
	if len(segments) == 0 {
		return nil
	}
	wanted := segments[len(segments)-1].sequence
	for _, worker := range workers {
		worker.notify()
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
	var pending *remoteDeliveryCursor
	failures := uint(0)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if pending != nil {
			cursor, err := writeRemoteDeliveryCursor(this.stateDirectory, this.identity, this.scope.Target, pending.Sequence, pending.SegmentHash)
			if err != nil {
				failures++
				if !this.waitAfterFailure(ctx, failures, pending.Sequence, err) {
					return
				}
				continue
			}
			this.cursor = cursor
			this.confirmed.Store(cursor.Sequence)
			notifyRemoteDelivery(this.progress)
			pending = nil
			if failures > 0 {
				this.logger.With("sequence", cursor.Sequence).Info("remote audit delivery recovered")
			}
			failures = 0
			continue
		}

		segment, file, exists, err := nextRemoteDeliverySegment(this.producerDirectory, this.identity.ProducerId(), this.cursor.Sequence)
		if err != nil {
			failures++
			if !this.waitAfterFailure(ctx, failures, this.cursor.Sequence+1, err) {
				return
			}
			continue
		}
		if !exists {
			failures = 0
			if !waitRemoteDelivery(ctx, this.wake, this.options.idleDelay) {
				return
			}
			continue
		}

		publishErr := this.target.Publish(ctx, segment)
		closeErr := file.Close()
		if publishErr != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			if !this.waitAfterFailure(ctx, failures, segment.Sequence(), publishErr) {
				return
			}
			continue
		}
		pending = &remoteDeliveryCursor{remoteDeliveryCursorContent: remoteDeliveryCursorContent{
			Sequence:    segment.Sequence(),
			SegmentHash: segment.Hash(),
		}}
		if closeErr != nil {
			this.logger.WithError(closeErr).With("sequence", segment.Sequence()).Warn("cannot close delivered local audit segment")
		}
	}
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

func listRemoteDeliverySegments(directory string) ([]journalSegmentFile, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, errors.System.Newf("cannot inspect audit producer directory %q for delivery: %w", directory, err)
	}
	result := make([]journalSegmentFile, 0, len(entries))
	for _, entry := range entries {
		switch entry.Name() {
		case journalActiveFileName, journalHeadFileName, journalHeadTempFileName:
			continue
		}
		sequence, hash, ok := parseSealedJournalFileName(entry.Name())
		if !ok || !entry.Type().IsRegular() {
			return nil, errors.Config.Newf("audit producer directory %q contains unsupported delivery entry %q", directory, entry.Name())
		}
		result = append(result, journalSegmentFile{name: entry.Name(), path: filepath.Join(directory, entry.Name()), sequence: sequence, hash: hash})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].sequence < result[right].sequence })
	return result, nil
}

func validateRemoteDeliveryCursor(cursor remoteDeliveryCursor, segments []journalSegmentFile, target configuration.AuditlogTargetName) error {
	if cursor.Sequence == 0 {
		return nil
	}
	for _, segment := range segments {
		if segment.sequence == cursor.Sequence {
			if SegmentHash(segment.hash) != cursor.SegmentHash {
				return errors.System.Newf("remote delivery cursor for target %q conflicts with local segment %d", target, cursor.Sequence)
			}
			return nil
		}
	}
	return errors.System.Newf("remote delivery cursor for target %q confirms missing local segment %d", target, cursor.Sequence)
}

func nextRemoteDeliverySegment(directory string, producerId ProducerId, confirmed uint64) (SealedSegment, *os.File, bool, error) {
	segments, err := listRemoteDeliverySegments(directory)
	if err != nil {
		return SealedSegment{}, nil, false, err
	}
	next := confirmed + 1
	for _, candidate := range segments {
		if candidate.sequence < next {
			continue
		}
		if candidate.sequence != next {
			return SealedSegment{}, nil, false, errors.System.Newf("remote delivery segment sequence jumps from %d to %d", confirmed, candidate.sequence)
		}
		file, err := openSealedJournal(candidate.path)
		if err != nil {
			return SealedSegment{}, nil, false, err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return SealedSegment{}, nil, false, errors.System.Newf("cannot inspect sealed audit segment %q for delivery: %w", candidate.path, err)
		}
		segment, err := newSealedSegment(producerId, candidate.sequence, SegmentHash(candidate.hash), info.Size(), file)
		if err != nil {
			_ = file.Close()
			return SealedSegment{}, nil, false, err
		}
		return segment, file, true, nil
	}
	return SealedSegment{}, nil, false, nil
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

func notifyRemoteDelivery(target chan<- struct{}) {
	select {
	case target <- struct{}{}:
	default:
	}
}
