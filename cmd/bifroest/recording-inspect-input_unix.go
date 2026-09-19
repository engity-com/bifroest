//go:build unix

package main

import (
	stdos "os"

	"golang.org/x/sys/unix"
)

func openRecordingFile(path string) (*stdos.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return stdos.NewFile(uintptr(descriptor), path), nil
}
