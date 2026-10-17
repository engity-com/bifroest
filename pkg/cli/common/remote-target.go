package common

import (
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/management"
)

type remoteTargetKey struct{}

func ContextWithRemoteTarget(ctx context.Context, target management.Target) context.Context {
	return context.WithValue(ctx, remoteTargetKey{}, target)
}

func RemoteTargetFromContext(ctx context.Context) (management.Target, error) {
	target, found := ctx.Value(remoteTargetKey{}).(management.Target)
	if !found {
		return management.Target{}, fmt.Errorf("remote target is unavailable")
	}
	return target, nil
}
