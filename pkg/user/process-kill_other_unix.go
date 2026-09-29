//go:build unix && !linux

package user

import (
	"context"
	"fmt"
	"os"

	"github.com/shirou/gopsutil/v4/process"
)

func killVerifiedUserProcess(ctx context.Context, candidate *process.Process, uid uint32) error {
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
	return candidate.KillWithContext(ctx)
}
