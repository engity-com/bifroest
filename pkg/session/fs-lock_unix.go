//go:build unix

package session

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type fsRepositoryProcessLock struct {
	file *os.File
	once sync.Once
	err  error
}

func acquireFsRepositoryProcessLock(path string, mode os.FileMode) (*fsRepositoryProcessLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, mode)
	if err != nil {
		return nil, fmt.Errorf("cannot open repository lock file %q: %w", path, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("session repository %q is already locked by another process", path)
		}
		return nil, fmt.Errorf("cannot determine lock state of session repository %q: %w", path, err)
	}
	return &fsRepositoryProcessLock{file: file}, nil
}

func (this *fsRepositoryProcessLock) Close() error {
	if this == nil {
		return nil
	}
	this.once.Do(func() {
		if err := unix.Flock(int(this.file.Fd()), unix.LOCK_UN); err != nil {
			this.err = err
		}
		if err := this.file.Close(); err != nil && this.err == nil {
			this.err = err
		}
	})
	return this.err
}
