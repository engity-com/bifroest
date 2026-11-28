package configuration

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/fsnotify/fsnotify"
)

type FileWatchOptions struct {
	// Debounce coalesces filesystem events. Zero selects 200 milliseconds.
	Debounce time.Duration
	// PollInterval also bounds event coalescing. Polling detects lost events,
	// changes to external symlink targets and replacement of watched directories.
	// Zero selects two seconds.
	PollInterval time.Duration
	// OnError is required so failed candidates and watcher degradation cannot
	// silently leave an operator believing the latest file is active.
	OnError func(error)
	// OnReload observes every accepted attempt, including unchanged files.
	// Callbacks execute synchronously and must return promptly.
	OnReload func(ReloadChanges)
	// OnReady runs once after native watch setup, before the first reload.
	// It can synchronize service startup, and must honor shutdown cancellation.
	OnReady func()
}

// FileWatchError reports native watch degradation, not a rejected candidate.
// Callers must not expose its underlying operating-system error as metric labels.
type FileWatchError struct{ Err error }

func (this *FileWatchError) Error() string { return this.Err.Error() }
func (this *FileWatchError) Unwrap() error { return this.Err }

func (this FileWatchOptions) withDefaults() (FileWatchOptions, error) {
	if this.Debounce < 0 || this.PollInterval < 0 {
		return this, fmt.Errorf("configuration watch intervals must not be negative")
	}
	if this.OnError == nil {
		return this, fmt.Errorf("configuration watch requires an error observer")
	}
	if this.Debounce == 0 {
		this.Debounce = 200 * time.Millisecond
	}
	if this.PollInterval == 0 {
		this.PollInterval = 2 * time.Second
	}
	return this, nil
}

// Watch runs until cancellation without starting any unowned goroutines. It
// watches the configured parent directory, not a replaceable file inode, and
// periodically rereads the original path as a fallback for missed native events.
// Failed candidates are reported and retried; the last accepted snapshot stays
// active. Initial watcher setup failure is returned to the caller.
func (this *FileReloader) Watch(ctx context.Context, options FileWatchOptions) error {
	options, err := options.withDefaults()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !this.watching.CompareAndSwap(false, true) {
		return fmt.Errorf("configuration watch is already running")
	}
	defer this.watching.Store(false)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("cannot create configuration watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()
	directory := filepath.Dir(this.filename)
	if err := watcher.Add(directory); err != nil {
		return fmt.Errorf("cannot watch configuration directory: %w", err)
	}
	if options.OnReady != nil {
		options.OnReady()
	}
	events, failures := watcher.Events, watcher.Errors
	poll := time.NewTicker(options.PollInterval)
	defer poll.Stop()

	timer := time.NewTimer(min(options.Debounce, options.PollInterval))
	defer timer.Stop()
	scheduled := (<-chan time.Time)(timer.C)
	firstEvent := time.Now()
	schedule := func(reset bool) {
		now := time.Now()
		if scheduled == nil {
			firstEvent = now
		} else if !reset {
			return
		}
		deadline := now.Add(options.Debounce)
		// Unrelated events in a busy directory must not postpone a reload
		// indefinitely, and polling must not continually reset its timer.
		if latest := firstEvent.Add(options.PollInterval); deadline.After(latest) {
			deadline = latest
		}
		timer.Reset(max(time.Duration(0), time.Until(deadline)))
		scheduled = timer.C
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-events:
			if !ok {
				events = nil
				options.OnError(&FileWatchError{fmt.Errorf("configuration watcher stopped delivering events; polling remains active")})
				continue
			}
			// Directory events include atomic rename and projected-volume
			// symlink swaps, which need not use the configuration's basename.
			schedule(true)
		case err, ok := <-failures:
			if !ok {
				failures = nil
				continue
			}
			options.OnError(&FileWatchError{fmt.Errorf("configuration watcher failed; polling remains active: %w", err)})
		case <-poll.C:
			if !slices.Contains(watcher.WatchList(), directory) {
				if err := watcher.Add(directory); err != nil {
					options.OnError(&FileWatchError{fmt.Errorf("cannot restore configuration watch; polling remains active: %w", err)})
				}
			}
			schedule(false)
		case <-scheduled:
			scheduled = nil
			changes, err := this.Reload(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				options.OnError(err)
			} else if options.OnReload != nil {
				options.OnReload(changes)
			}
		}
	}
}
