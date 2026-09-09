//go:build linux

package protocol

import (
	"context"
	"syscall"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const pidfdSignalProcessGroup = 1 << 2

func (this *imp) kill(ctx context.Context, target processTarget, signal sys.Signal, signaledGroups signaledProcessGroups) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pidfd, err := unix.PidfdOpen(target.pid, 0)
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENODEV) {
		return this.killWithoutPidfd(target, signal)
	}
	if errors.Is(err, syscall.ESRCH) {
		return ErrNoSuchProcess
	}
	if err != nil {
		return err
	}
	defer unix.Close(pidfd)
	if !target.matchesIdentity() {
		return ErrNoSuchProcess
	}
	if !target.processGroup {
		return sendPidfdSignal(pidfd, signal, 0)
	}

	pgid, err := pinnedProcessGroup(pidfd, target.pid)
	if err != nil {
		return err
	}
	ownPgid, err := syscall.Getpgid(0)
	if err != nil {
		return err
	}
	if pgid == ownPgid {
		return sendPidfdSignal(pidfd, signal, 0)
	}
	if _, ok := signaledGroups[pgid]; ok {
		return nil
	}

	leaderPidfd := pidfd
	if pgid != target.pid {
		leaderPidfd, err = unix.PidfdOpen(pgid, 0)
		if errors.Is(err, syscall.ESRCH) {
			if err := signalPinnedProcessGroup(ctx, target.pid, pidfd, pgid, signal); err != nil {
				return err
			}
			signaledGroups[pgid] = struct{}{}
			return nil
		}
		if err != nil {
			return err
		}
		defer unix.Close(leaderPidfd)
		leaderExited, err := pidfdExited(leaderPidfd)
		if err != nil {
			return err
		}
		if leaderExited {
			if err := signalPinnedProcessGroup(ctx, target.pid, pidfd, pgid, signal); err != nil {
				return err
			}
			signaledGroups[pgid] = struct{}{}
			return nil
		}
		if target.groupExpectedEnv == "" {
			return ErrNoSuchProcess
		}
		if !processHasEnvironment(pgid, target.groupExpectedEnv) {
			leaderExited, err = pidfdExited(leaderPidfd)
			if err != nil {
				return err
			}
			if !leaderExited {
				return ErrNoSuchProcess
			}
			if err := signalPinnedProcessGroup(ctx, target.pid, pidfd, pgid, signal); err != nil {
				return err
			}
			signaledGroups[pgid] = struct{}{}
			return nil
		}
		leaderPgid, err := pinnedProcessGroup(leaderPidfd, pgid)
		if errors.Is(err, ErrNoSuchProcess) {
			if err := signalPinnedProcessGroup(ctx, target.pid, pidfd, pgid, signal); err != nil {
				return err
			}
			signaledGroups[pgid] = struct{}{}
			return nil
		}
		if err != nil {
			return err
		}
		if leaderPgid != pgid {
			return ErrNoSuchProcess
		}
	}

	if err := sendPidfdSignal(leaderPidfd, signal, pidfdSignalProcessGroup); !errors.Is(err, syscall.EINVAL) && !errors.Is(err, ErrNoSuchProcess) {
		if err == nil {
			signaledGroups[pgid] = struct{}{}
		}
		return err
	}
	if err := signalPinnedProcessGroup(ctx, target.pid, pidfd, pgid, signal); err != nil {
		return err
	}
	signaledGroups[pgid] = struct{}{}
	return nil
}

func pidfdExited(pidfd int) (bool, error) {
	poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	if _, err := unix.Poll(poll, 0); err != nil {
		return false, err
	}
	return poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0, nil
}

func pinnedProcessGroup(pidfd, pid int) (int, error) {
	if err := sendPidfdSignal(pidfd, 0, 0); err != nil {
		return 0, err
	}
	pgid, err := syscall.Getpgid(pid)
	if errors.Is(err, syscall.ESRCH) {
		return 0, ErrNoSuchProcess
	}
	if err != nil {
		return 0, err
	}
	if err := sendPidfdSignal(pidfd, 0, 0); err != nil {
		return 0, err
	}
	return pgid, nil
}

func signalPinnedProcessGroup(ctx context.Context, anchorPid, anchorPidfd, pgid int, signal sys.Signal) error {
	candidates, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return err
	}
	type member struct {
		pid       int
		createdAt int64
	}
	members := make([]member, 0)
	for _, candidate := range candidates {
		pid := int(candidate.Pid)
		if pid == anchorPid {
			continue
		}
		candidatePgid, err := syscall.Getpgid(pid)
		if err != nil || candidatePgid != pgid {
			continue
		}
		createdAt, err := candidate.CreateTime()
		if err != nil {
			continue
		}
		members = append(members, member{pid: pid, createdAt: createdAt})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	anchorPgid, err := pinnedProcessGroup(anchorPidfd, anchorPid)
	if err != nil {
		return err
	}
	if anchorPgid != pgid {
		return ErrNoSuchProcess
	}

	delivered := false
	var firstErr error
	for _, candidate := range members {
		pid := candidate.pid
		candidatePidfd, err := unix.PidfdOpen(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		expectedCreatedAt := candidate.createdAt
		if !(processTarget{pid: pid, expectedCreatedAt: &expectedCreatedAt}).matchesIdentity() {
			_ = unix.Close(candidatePidfd)
			continue
		}
		candidatePgid, err := pinnedProcessGroup(candidatePidfd, pid)
		if errors.Is(err, ErrNoSuchProcess) || candidatePgid != pgid {
			_ = unix.Close(candidatePidfd)
			continue
		}
		if err != nil {
			_ = unix.Close(candidatePidfd)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := sendPidfdSignal(candidatePidfd, signal, 0); err == nil {
			delivered = true
		} else if !errors.Is(err, ErrNoSuchProcess) {
			_ = unix.Close(candidatePidfd)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		_ = unix.Close(candidatePidfd)
	}
	anchorPgid, err = pinnedProcessGroup(anchorPidfd, anchorPid)
	if err != nil {
		if delivered {
			return nil
		}
		if firstErr != nil {
			return firstErr
		}
		return err
	}
	if anchorPgid != pgid {
		if delivered {
			return nil
		}
		if firstErr != nil {
			return firstErr
		}
		return ErrNoSuchProcess
	}
	if err := sendPidfdSignal(anchorPidfd, signal, 0); err == nil {
		return nil
	} else if delivered {
		return nil
	} else if firstErr != nil {
		return firstErr
	} else {
		return err
	}
}

func (*imp) killWithoutPidfd(target processTarget, signal sys.Signal) error {
	if target.processGroup || target.expectedCreatedAt != nil || target.expectedEnv != "" {
		return errors.System.Newf("secure process signaling requires pidfd support")
	}
	if !target.matchesIdentity() {
		return ErrNoSuchProcess
	}
	pid := target.pid
	if err := syscall.Kill(pid, signal.Native()); errors.Is(err, syscall.ESRCH) {
		return ErrNoSuchProcess
	} else {
		return err
	}
}

var sendPidfdSignal = func(pidfd int, signal sys.Signal, flags int) error {
	if err := unix.PidfdSendSignal(pidfd, unix.Signal(signal.Native()), nil, flags); errors.Is(err, syscall.ESRCH) {
		return ErrNoSuchProcess
	} else {
		return err
	}
}
