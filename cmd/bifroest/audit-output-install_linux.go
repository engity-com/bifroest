//go:build linux

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func installAuditOutputFile(parent int, temporary, target string, force bool) error {
	if force {
		if err := unix.Renameat(parent, temporary, parent, target); err != nil {
			return fmt.Errorf("cannot atomically replace output: %w", err)
		}
		return nil
	}
	if err := unix.Renameat2(parent, temporary, parent, target, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) {
			return fmt.Errorf("cannot atomically install output without replacement: %w", err)
		}
		if err := unix.Linkat(parent, temporary, parent, target, 0); err != nil {
			return fmt.Errorf("cannot atomically install output without replacement: %w", err)
		}
		if err := unix.Unlinkat(parent, temporary, 0); err != nil {
			return fmt.Errorf("cannot remove linked temporary output: %w", err)
		}
	}
	return nil
}
