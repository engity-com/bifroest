//go:build windows

package protocol

import (
	"context"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *imp) kill(ctx context.Context, target processTarget, signal sys.Signal, _ signaledProcessGroups) error {
	switch signal {
	case sys.SIGKILL, sys.SIGTERM:
	default:
		return errors.Config.Newf("unsupported signal: %v", signal)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	processHandle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE,
		false,
		uint32(target.pid),
	)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return ErrNoSuchProcess
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(processHandle)
	if !target.matchesIdentity() {
		return ErrNoSuchProcess
	}
	return windows.TerminateProcess(processHandle, uint32(128+signal))
}
