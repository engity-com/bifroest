//go:build unix

package crypto

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type bootstrapFileLock struct{ file *os.File }

func acquireBootstrapFileLock(path string) (*bootstrapFileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open trust file lock %q: %w", path, err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("cannot lock trust file %q: %w", path, err)
	}
	return &bootstrapFileLock{file: file}, nil
}

func (this *bootstrapFileLock) Close() error {
	if err := unix.Flock(int(this.file.Fd()), unix.LOCK_UN); err != nil {
		_ = this.file.Close()
		return err
	}
	return this.file.Close()
}
