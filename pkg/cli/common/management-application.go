package common

import (
	"context"

	cli "github.com/echocat/cli4g"
)

// ManagementApplication is the already compiled command definition. The
// service borrows it; its owner closes it after the service has stopped.
type ManagementApplication interface {
	ParseAndExecute(context.Context, *cli.ParseOpts, ...string) error
}

type managementApplicationKey struct{}

func ContextWithManagementApplication(ctx context.Context, application ManagementApplication) context.Context {
	return context.WithValue(ctx, managementApplicationKey{}, application)
}

func ManagementApplicationFromContext(ctx context.Context) ManagementApplication {
	application, _ := ctx.Value(managementApplicationKey{}).(ManagementApplication)
	return application
}
