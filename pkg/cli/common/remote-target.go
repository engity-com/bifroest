package common

import (
	"context"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

type remoteTargetKey struct{}

func ContextWithRemoteTarget(ctx context.Context, target management.Target) context.Context {
	return context.WithValue(configuration.ContextWithoutLocalConfiguration(ctx), remoteTargetKey{}, target)
}

func RemoteTargetFromContext(ctx context.Context) (management.Target, bool) {
	target, found := ctx.Value(remoteTargetKey{}).(management.Target)
	return target, found
}
