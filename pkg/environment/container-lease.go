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
