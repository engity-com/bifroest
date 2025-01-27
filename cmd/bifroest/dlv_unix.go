//go:build unix && embedded_dlv

package main

import (
	"context"
	"syscall"
	"time"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

func waitForDlvTargetProcess(ctx context.Context, pid int) (int, error) {
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return 0, nil
			}
			return -1, err
		}
		_ = common.Sleep(ctx, 100*time.Millisecond)
	}
}
