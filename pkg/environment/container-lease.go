package environment

import (
	"context"
	"sync"

	"github.com/engity-com/bifroest/pkg/errors"
)

// Each repository acquisition owns one reference to the cached raw environment.
type containerLease struct {
	Environment
	ReverseTCPListener

	mu       sync.Mutex
	released bool
}

// Embedding Environment promotes only its base methods, not optional execution
// capabilities of the raw container. Preserve neutral execution at the owned
// acquisition boundary without manufacturing an SSH task or a new reference.
func (this *containerLease) RunTerminal(task TerminalTask) (int, error) {
	this.mu.Lock()
	if this.released {
		this.mu.Unlock()
		return -1, errors.System.Newf("cannot run environment: lease already closed")
	}
	runner, ok := this.Environment.(TerminalRunner)
	this.mu.Unlock()
	if !ok {
		return -1, errors.User.Newf("environment does not support neutral terminal execution")
	}
	// Do not hold the release mutex while executing: cancellation must still be
	// able to close the owning acquisition and interrupt backend work.
	return runner.RunTerminal(task)
}

func (this *containerLease) Close() error {
	this.mu.Lock()
	defer this.mu.Unlock()
	if this.released {
		return nil
	}
	this.released = true
	return this.Environment.Close()
}

func (this *containerLease) Dispose(ctx context.Context) (bool, error) {
	this.mu.Lock()
	defer this.mu.Unlock()
	if this.released {
		return false, errors.System.Newf("cannot dispose environment: lease already closed")
	}
	this.released = true
	// Raw Dispose already releases this owner's reference, including on error.
	return this.Environment.Dispose(ctx)
}
