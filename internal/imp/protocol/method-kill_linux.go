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

func (this *imp) kill(ctx context.Context, target processTarget, signal sys.Signal) error {
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

	pgid, err := syscall.Getpgid(target.pid)
	if errors.Is(err, syscall.ESRCH) {
		return ErrNoSuchProcess
	}
	if err != nil {
		return err
	}
	if err := sendPidfdSignal(pidfd, 0, 0); err != nil {
		return err
	}
	confirmedPgid, err := syscall.Getpgid(target.pid)
	if err != nil || confirmedPgid != pgid {
		return ErrNoSuchProcess
	}
	ownPgid, err := syscall.Getpgid(0)
	if err != nil {
		return err
	}
	if pgid == ownPgid {
		return sendPidfdSignal(pidfd, signal, 0)
	}

	leaderPidfd := pidfd
	if pgid != target.pid {
		leaderPidfd, err = unix.PidfdOpen(pgid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return ErrNoSuchProcess
		}
		if err != nil {
			return err
		}
		defer unix.Close(leaderPidfd)
		if target.groupExpectedEnv == "" || !processHasEnvironment(pgid, target.groupExpectedEnv) {
			return ErrNoSuchProcess
		}
		if err := sendPidfdSignal(leaderPidfd, 0, 0); err != nil {
			return err
		}
		leaderPgid, err := syscall.Getpgid(pgid)
		if err != nil || leaderPgid != pgid {
			return ErrNoSuchProcess
		}
	}

	if err := sendPidfdSignal(leaderPidfd, signal, pidfdSignalProcessGroup); !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return signalPinnedProcessGroup(ctx, map[int]int{
		target.pid: pidfd,
		pgid:       leaderPidfd,
	}, leaderPidfd, pgid, signal)
}

func signalPinnedProcessGroup(ctx context.Context, pinned map[int]int, leaderPidfd int, pgid int, signal sys.Signal) error {
	owned := make([]int, 0)
	defer func() {
		for _, fd := range owned {
			_ = unix.Close(fd)
		}
	}()
	candidates, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		pid := int(candidate.Pid)
		if existingPidfd, exists := pinned[pid]; exists {
			if err := sendPidfdSignal(existingPidfd, 0, 0); err == nil {
				continue
			} else if !errors.Is(err, ErrNoSuchProcess) {
				return err
			}
			delete(pinned, pid)
		}
		candidatePidfd, err := unix.PidfdOpen(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return err
		}
		candidatePgid, err := syscall.Getpgid(pid)
		if err != nil || candidatePgid != pgid || sendPidfdSignal(candidatePidfd, 0, 0) != nil {
			_ = unix.Close(candidatePidfd)
			continue
		}
		pinned[pid] = candidatePidfd
		owned = append(owned, candidatePidfd)
	}
	if err := sendPidfdSignal(leaderPidfd, 0, 0); err != nil {
		return err
	}
	leaderPgid, err := syscall.Getpgid(pgid)
	if err != nil || leaderPgid != pgid {
		return ErrNoSuchProcess
	}
	if err := sendPidfdSignal(leaderPidfd, 0, 0); err != nil {
		return err
	}
	delivered := false
	for _, fd := range pinned {
		if err := sendPidfdSignal(fd, signal, 0); err == nil {
			delivered = true
		} else if !errors.Is(err, ErrNoSuchProcess) {
			return err
		}
	}
	if !delivered {
		return ErrNoSuchProcess
	}
	return nil
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

func sendPidfdSignal(pidfd int, signal sys.Signal, flags int) error {
	if err := unix.PidfdSendSignal(pidfd, unix.Signal(signal.Native()), nil, flags); errors.Is(err, syscall.ESRCH) {
		return ErrNoSuchProcess
	} else {
		return err
	}
}
