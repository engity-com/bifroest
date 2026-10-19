package common

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

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
	if path, supplied := cli.FlagFromContext[string](ctx, "sshConfig"); supplied {
		if path == "" {
			return management.Target{}, fmt.Errorf("--sshConfig must not be empty")
		}
		target.SSHConfigFile = path
	}
	return target, nil
}
