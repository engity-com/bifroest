//go:build local_build && local_kind && linux

package alternatives

import (
	"context"
	stderrors "errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func runLocalKindProviderProbe(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := killLocalKindProviderProbeGroup(cmd)
		if stderrors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return err
	}
	pidfd, pidfdErr := unix.PidfdOpen(cmd.Process.Pid, 0)
	if pidfdErr != nil {
		return cmd.Wait()
	}
	defer unix.Close(pidfd)
	poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	for {
		if _, err := unix.Poll(poll, -1); err == unix.EINTR {
			continue
		} else if err != nil {
			return cmd.Wait()
		}
		break
	}
	_ = killLocalKindProviderProbeGroup(cmd)
	return cmd.Wait()
}

func killLocalKindProviderProbeGroup(cmd *exec.Cmd) error {
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
