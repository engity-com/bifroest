package common

import (
	"context"

	"github.com/engity-com/bifroest/pkg/managementclient"
)

type remoteTargetKey struct{}

func ContextWithRemoteTarget(ctx context.Context, target managementclient.Target) context.Context {
	return context.WithValue(ctx, remoteTargetKey{}, target)
}

func RemoteTargetFromContext(ctx context.Context) (managementclient.Target, bool) {
	target, found := ctx.Value(remoteTargetKey{}).(managementclient.Target)
	return target, found
}
