//go:build windows

package protocol

import (
	"context"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *imp) kill(ctx context.Context, pid int, signal sys.Signal) error {
	p, err := process.NewProcess(int32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, process.ErrorProcessNotRunning) {
		return ErrNoSuchProcess
	}
	if err != nil {
		return err
	}
	switch signal {
	case sys.SIGKILL:
		return p.KillWithContext(ctx)
	case sys.SIGTERM:
		return p.TerminateWithContext(ctx)
	default:
		return errors.Config.Newf("unsupported signal: %v", signal)
	}
}
