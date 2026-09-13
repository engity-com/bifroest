//go:build unix && !linux

package main

import (
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
	if err := unix.Linkat(parent, temporary, parent, target, 0); err != nil {
		return fmt.Errorf("cannot atomically install output without replacement: %w", err)
	}
	if err := unix.Unlinkat(parent, temporary, 0); err != nil {
		return fmt.Errorf("cannot remove linked temporary output: %w", err)
	}
	return nil
}
