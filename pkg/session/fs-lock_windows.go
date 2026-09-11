//go:build windows

package session

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/windows"
)

type fsRepositoryProcessLock struct {
	file       *os.File
	overlapped windows.Overlapped
	once       sync.Once
	err        error
}

func acquireFsRepositoryProcessLock(path string, mode os.FileMode) (*fsRepositoryProcessLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, mode)
	if err != nil {
		return nil, fmt.Errorf("cannot open repository lock file %q: %w", path, err)
	}
	result := &fsRepositoryProcessLock{file: file}
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &result.overlapped)
	if err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, fmt.Errorf("session repository %q is already locked by another process", path)
		}
		return nil, fmt.Errorf("cannot determine lock state of session repository %q: %w", path, err)
	}
	return result, nil
}

func (this *fsRepositoryProcessLock) Close() error {
	if this == nil {
		return nil
	}
	this.once.Do(func() {
		if err := windows.UnlockFileEx(windows.Handle(this.file.Fd()), 0, 1, 0, &this.overlapped); err != nil {
			this.err = err
		}
		if err := this.file.Close(); err != nil && this.err == nil {
			this.err = err
		}
	})
	return this.err
}
