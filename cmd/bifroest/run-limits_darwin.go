//go:build darwin

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const darwinOpenFileLimit = 65536

func configureProcessLimits() error {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("cannot read open-file limit: %w", err)
	}
	desired := desiredDarwinOpenFileLimit(limit.Cur, limit.Max)
	if desired == limit.Cur {
		return nil
	}
	limit.Cur = desired
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("cannot raise open-file limit to %d: %w", desired, err)
	}
	return nil
}

func desiredDarwinOpenFileLimit(current, maximum uint64) uint64 {
	desired := min(uint64(darwinOpenFileLimit), maximum)
	return max(current, desired)
}
