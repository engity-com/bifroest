//go:build !windows

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
)

func replaceFileAtomically(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(to))
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
