package authorization

import (
	"context"
	"sync"
)

// OidcSessionLocks serializes retained grants across authorizer instances.
// Its zero value is usable. A service with several configuration generations
// must share one instance; this does not share their authentication policies.
type OidcSessionLocks struct {
	shards [64]struct {
		once  sync.Once
		ready chan struct{}
	}
}

type oidcSessionLocksContextKey struct{}

func WithOidcSessionLocks(ctx context.Context, locks *OidcSessionLocks) context.Context {
	return context.WithValue(ctx, oidcSessionLocksContextKey{}, locks)
}
