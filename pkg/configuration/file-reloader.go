package configuration

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
)

// ApplyReload prepares and activates a complete runtime change. A non-nil error
// must leave the previous runtime active; nil means activation has committed.
// The callback must honor cancellation before committing, must not call Reload
// recursively, and must not log configuration secrets.
//
// The file reloader does not itself make a mutable service reload-safe. Runtime
// integration must implement resource ownership, admission and revocation.
type ApplyReload func(context.Context, *Snapshot, ReloadChanges) error

// FileReloader serializes loading, validation and runtime activation. Current
// always refers to the last successfully accepted snapshot, not the latest file.
// Only Reload invokes the callback; constructing a reloader does not start work.
type FileReloader struct {
	filename string
	apply    ApplyReload
	current  atomic.Pointer[Snapshot]
	watching atomic.Bool
	gate     chan struct{}
}

func NewFileReloader(initial Configuration, apply ApplyReload) (*FileReloader, error) {
	if initial.Filename == "" {
		return nil, fmt.Errorf("configuration reload requires a file source")
	}
	if apply == nil {
		return nil, fmt.Errorf("configuration reload requires a runtime activation callback")
	}
	filename, err := filepath.Abs(initial.Filename)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve configuration reload source: %w", err)
	}
	// Keep the configured symlink, not its current target. Projected files and
	// atomic replacement must resolve the current generation on every attempt.
	initial.Filename = filename
	snapshot, err := NewSnapshot(initial)
	if err != nil {
		return nil, err
	}
	result := &FileReloader{filename: filename, apply: apply, gate: make(chan struct{}, 1)}
	result.current.Store(snapshot)
	return result, nil
}

func (this *FileReloader) Current() *Snapshot {
	return this.current.Load()
}

// Reload rereads the configured path while holding the reload gate, so queued
// requests cannot publish a candidate read before a newer accepted candidate.
// Parse, validation and activation failures never publish a partial snapshot.
func (this *FileReloader) Reload(ctx context.Context) (ReloadChanges, error) {
	select {
	case <-ctx.Done():
		return ReloadChanges{}, ctx.Err()
	case this.gate <- struct{}{}:
		defer func() { <-this.gate }()
	}
	if err := ctx.Err(); err != nil {
		return ReloadChanges{}, err
	}
	var candidate Configuration
	if err := candidate.LoadFromFile(this.filename); err != nil {
		return ReloadChanges{}, fmt.Errorf("cannot reload configuration: %w", err)
	}
	next, err := NewSnapshot(candidate)
	if err != nil {
		return ReloadChanges{}, err
	}
	changes := this.Current().ChangesTo(next)
	if err := ctx.Err(); err != nil {
		return changes, err
	}
	if changes.RuntimeChanged() {
		if err := this.apply(ctx, next, changes); err != nil {
			return changes, fmt.Errorf("cannot activate reloaded configuration: %w", err)
		}
	}
	// Do not check cancellation after a successful callback: its activation has
	// already committed, so the accepted snapshot must agree with the runtime.
	this.current.Store(next)
	return changes, nil
}
