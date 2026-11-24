//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureCommand(cmd *exec.Cmd) (func() error, func(), error) {
	// go test starts compiler and test subprocesses. Cancel the whole group, not
	// only the go driver, so inherited output pipes cannot keep Wait blocked.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Cancel = kill
	return func() error { return nil }, func() {
		if cmd.Process != nil {
			_ = kill()
		}
	}, nil
}

func signalExitCode(state *os.ProcessState) int {
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 1
}

func rss(state *os.ProcessState) (*uint64, string) {
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage.Maxrss <= 0 {
		return nil, ""
	}
	bytes := uint64(usage.Maxrss) * rssUnit
	return &bytes, "OS wait4 maximum for the command and OS-accounted waited descendants; a single-process peak, not summed parallel RAM"
}
