//go:build unix

package protocol

import (
	"context"
	"syscall"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *imp) kill(_ context.Context, pid int, signal sys.Signal, processGroup bool) error {
	if processGroup {
		pgid, err := syscall.Getpgid(pid)
		if errors.Is(err, syscall.ESRCH) {
			return ErrNoSuchProcess
		} else if err != nil {
			return err
		}
		if pgid == pid {
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
