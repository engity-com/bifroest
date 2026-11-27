package common

import (
	"context"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
)

// ServiceRunner starts the executable's SSH service. It is supplied when the
// executable CLI is built; management invocations cannot activate serve.
type ServiceRunner func(context.Context, configuration.Configuration, sys.Version) error

// ServiceRunOptions are invocation options, not mutable YAML settings.
type ServiceRunOptions struct {
	Watch configuration.WatchMode `flag:"watch" default:"off" placeholder:"<mode>" description:"Watch configuration: off, preserve, reconnect or reuse; a bare flag selects preserve. Off aliases: false, no, 0."`
}

type serviceRunOptionsContextKey struct{}

func WithServiceRunOptions(ctx context.Context, options ServiceRunOptions) context.Context {
	return context.WithValue(ctx, serviceRunOptionsContextKey{}, options)
}

func ServiceRunOptionsFromContext(ctx context.Context) ServiceRunOptions {
	options, _ := ctx.Value(serviceRunOptionsContextKey{}).(ServiceRunOptions)
	return options
}
