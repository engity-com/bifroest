package common

import (
	"context"
	"errors"
)

var ErrProviderBootstrapDisabled = errors.New("configuration reload cannot create provider files; provision required files before reloading or restart")

type providerBootstrapDisabledContextKey struct{}

// WithProviderBootstrapDisabled limits provider construction, not authenticated
// session provisioning. The restriction travels with candidate lifetime contexts
// so a preflight check cannot race with a later file-creation fallback.
func WithProviderBootstrapDisabled(ctx context.Context) context.Context {
	return context.WithValue(ctx, providerBootstrapDisabledContextKey{}, true)
}

func ProviderBootstrapAllowed(ctx context.Context) bool {
	disabled, _ := ctx.Value(providerBootstrapDisabledContextKey{}).(bool)
	return !disabled
}
