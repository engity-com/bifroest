//go:build unix && !linux

package protocol

import (
	"context"
	"syscall"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *imp) kill(_ context.Context, target processTarget, signal sys.Signal, _ signaledProcessGroups) error {
	if !target.matchesIdentity() {
		return ErrNoSuchProcess
	}
	pid := target.pid
	if target.processGroup {
		pgid, err := syscall.Getpgid(target.pid)
		if errors.Is(err, syscall.ESRCH) {
			return ErrNoSuchProcess
		} else if err != nil {
			return err
		}
		ownPgid, err := syscall.Getpgid(0)
		if err != nil {
			return err
		}
		if pgid != ownPgid {
			if pgid != target.pid {
				return ErrNoSuchProcess
			}
			pid = -pgid
		}
	}
	if err := syscall.Kill(pid, signal.Native()); errors.Is(err, syscall.ESRCH) {
		return ErrNoSuchProcess
	} else if err != nil {
		return err
	}
	return nil
}
