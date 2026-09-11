//go:build windows

package crypto

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

type bootstrapFileLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireBootstrapFileLock(path string) (*bootstrapFileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open trust file lock %q: %w", path, err)
	}
	result := &bootstrapFileLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &result.overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("cannot lock trust file %q: %w", path, err)
	}
	return result, nil
}

func (this *bootstrapFileLock) Close() error {
	if err := windows.UnlockFileEx(windows.Handle(this.file.Fd()), 0, 1, 0, &this.overlapped); err != nil {
		_ = this.file.Close()
		return err
	}
	return this.file.Close()
}
