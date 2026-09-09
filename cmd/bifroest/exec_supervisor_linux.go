package main

import (
	goos "os"
	"os/exec"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const execDescendantCleanupTimeout = 3 * time.Second

var openExecPidfd = unix.PidfdOpen

type execProcessSupervisor struct {
	previousSubreaper int
	pidfdSupported    bool
}

func newExecProcessSupervisor() (*execProcessSupervisor, error) {
	pidfd, err := openExecPidfd(goos.Getpid(), 0)
	pidfdSupported := err == nil
	if err != nil && err != unix.ENOSYS && err != unix.ENODEV && err != unix.EPERM && err != unix.EINVAL {
		return nil, err
	}
	if pidfdSupported {
		_ = unix.Close(pidfd)
	}
	var previous int
	if err := unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&previous)), 0, 0, 0); err != nil {
		return nil, err
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return nil, err
	}
	return &execProcessSupervisor{previousSubreaper: previous, pidfdSupported: pidfdSupported}, nil
}

func (*execProcessSupervisor) Prepare(cmd *exec.Cmd) error {
	if stdin, ok := cmd.Stdin.(*goos.File); ok && term.IsTerminal(int(stdin.Fd())) {
		cmd.SysProcAttr.Foreground = true
		cmd.SysProcAttr.Ctty = int(stdin.Fd())
	}
	return nil
}
func (*execProcessSupervisor) Attach(*exec.Cmd) error { return nil }

func (this *execProcessSupervisor) Cleanup() (rErr error) {
	defer func() {
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(this.previousSubreaper), 0, 0, 0); err != nil && rErr == nil {
			rErr = err
		}
	}()
	deadline := time.Now().Add(execDescendantCleanupTimeout)
	for {
		parent, err := process.NewProcess(int32(goos.Getpid()))
		if err != nil {
			return err
		}
		children, err := parent.Children()
		if err != nil {
			return err
		}
		if len(children) == 0 {
			return nil
		}
		for _, child := range children {
			expectedCreatedAt, err := child.CreateTime()
			if err != nil {
				continue
			}
			pidfd := -1
			if this.pidfdSupported {
				pidfd, err = openExecPidfd(int(child.Pid), 0)
				if err != nil {
					if err == unix.ESRCH {
						continue
					}
					return err
				}
			}
			current, processErr := process.NewProcess(child.Pid)
			if processErr != nil {
				if pidfd >= 0 {
					_ = unix.Close(pidfd)
				}
				continue
			}
			currentCreatedAt, createdAtErr := current.CreateTime()
			parentPid, parentErr := current.Ppid()
			if createdAtErr != nil || parentErr != nil || currentCreatedAt != expectedCreatedAt || parentPid != int32(goos.Getpid()) {
				if pidfd >= 0 {
					_ = unix.Close(pidfd)
				}
				continue
			}
			var signalErr error
			if pidfd >= 0 {
				signalErr = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
				_ = unix.Close(pidfd)
			} else {
				signalErr = unix.Kill(int(child.Pid), unix.SIGKILL)
			}
			if signalErr != nil && signalErr != unix.ESRCH {
				return signalErr
			}
		}
		for {
			var status unix.WaitStatus
			pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
			if err == unix.ECHILD || pid == 0 {
				break
			}
			if err != nil {
				return err
			}
		}
		if time.Now().After(deadline) {
			return goos.ErrDeadlineExceeded
		}
		time.Sleep(10 * time.Millisecond)
	}
}
