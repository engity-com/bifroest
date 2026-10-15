package common

import (
	"context"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

// ManagementAccess is bound to one authorized SSH invocation, never to the
// shared, compiled command schema.
type ManagementAccess struct {
	Configuration         *configuration.Configuration
	Sessions              session.Repository
	IncludingCredentials  bool
	AllowArtifactTransfer bool
}

type managementAccessKey struct{}

func ContextWithManagementAccess(ctx context.Context, access ManagementAccess) context.Context {
	return context.WithValue(ctx, managementAccessKey{}, access)
}

func ManagementAccessFromContext(ctx context.Context) (ManagementAccess, bool) {
	access, ok := ctx.Value(managementAccessKey{}).(ManagementAccess)
	return access, ok
}
