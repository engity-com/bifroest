//go:build e2e && linux

package e2e_test

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func configureCommandCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := terminateCommandProcessGroup(cmd)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}

func terminateCommandProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func waitAndCleanupCommand(cmd *exec.Cmd) error {
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
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
	_ = terminateCommandProcessGroup(cmd)
	return cmd.Wait()
}
