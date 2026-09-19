//go:build local_build && local_kind && !linux

package alternatives

import (
	"context"
	"io"
	"os/exec"
	"time"
)

func runLocalKindProviderProbe(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	return cmd.Run()
}
