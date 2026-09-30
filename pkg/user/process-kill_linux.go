//go:build linux

package user

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

func killVerifiedUserProcess(ctx context.Context, candidate *process.Process, uid uint32) error {
	fd, err := unix.PidfdOpen(int(candidate.Pid), 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot pin process %d: %w", candidate.Pid, err)
	}
	defer func() { _ = unix.Close(fd) }()
	current, err := candidate.UidsWithContext(ctx)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(current) == 0 || current[0] != uid {
		return fmt.Errorf("process %d changed UID during cleanup", candidate.Pid)
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); errors.Is(err, unix.ESRCH) {
		return nil
	} else {
		return err
	}
}
