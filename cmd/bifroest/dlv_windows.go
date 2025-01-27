//go:build windows && embedded_dlv

package main

import (
	"context"
	goos "os"

	"github.com/engity-com/bifroest/pkg/errors"
)

func waitForDlvTargetProcess(_ context.Context, pid int) (int, error) {
	p, err := goos.FindProcess(pid)
	if err != nil {
		return -1, errors.System.Newf("cannot find process with PID %d we want to debug: %w", pid, err)
	}

	ps, err := p.Wait()
	if err != nil {
		return -1, errors.System.Newf("cannot wait with PID %d: %w", pid, err)
	}

	return ps.ExitCode(), nil
}
