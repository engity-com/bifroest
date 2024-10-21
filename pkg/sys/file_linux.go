//go:build unix

package sys

import (
	"os"
	"syscall"
)

func cloneFile(f CloneableFile) (*os.File, error) {
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return nil, err
	}
	cloned := os.NewFile(uintptr(fd), f.Name())
	return cloned, nil
}
