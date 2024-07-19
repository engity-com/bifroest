//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

package sys

import (
	"io"
	"io/fs"
	"os"
	"syscall"
)

type File interface {
	Name() string
	Fd() uintptr
	io.ReadWriteCloser
	io.ReadWriteSeeker
}

func LockFileForRead(which File) (io.Closer, error) {
	if err := lockFile(which, syscall.LOCK_SH, "file-read-lock"); err != nil {
		return nil, err
	}
	return lockCloser{which}, nil
}

func LockFileForWrite(which File) (io.Closer, error) {
	if err := lockFile(which, syscall.LOCK_SH, "file-write-lock"); err != nil {
		return nil, err
	}
	return lockCloser{which}, nil
}

func OpenAndLockFileForRead(fn string) (File, error) {
	return openAndLockFileForRead(fn)
}

func openAndLockFileForRead(fn string) (_ File, rErr error) {
	succes := false
	f, err := os.OpenFile(fn, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !succes {
			if err := f.Close(); err != nil && rErr == nil {
				rErr = err
			}
		}
	}()

	if err := lockFile(f, syscall.LOCK_SH, "file-read-lock"); err != nil {
		return nil, err
	}
	succes = true
	return lockAndFileCloser{f}, nil
}

func OpenAndLockFileForWrite(fn string, flag int, perm os.FileMode) (File, error) {
	return openAndLockFileForWrite(fn, flag, perm)
}

func openAndLockFileForWrite(fn string, flag int, perm os.FileMode) (_ File, rErr error) {
	succes := false
	f, err := os.OpenFile(fn, flag, perm)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !succes {
			if err := f.Close(); err != nil && rErr == nil {
				rErr = err
			}
		}
	}()

	if err := lockFile(f, syscall.LOCK_EX, "write-read-lock"); err != nil {
		return nil, err
	}
	succes = true
	return lockAndFileCloser{f}, nil
}

func lockFile(which File, how int, op string) (err error) {
	for {
		err = syscall.Flock(int(which.Fd()), how)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		return &fs.PathError{
			Op:   op,
			Path: which.Name(),
			Err:  err,
		}
	}
	return nil
}

func unlockFile(which File) error {
	return lockFile(which, syscall.LOCK_UN, "file-unlock")
}

type lockCloser struct {
	File
}

func (this lockCloser) Close() error {
	return unlockFile(this.File)
}

type lockAndFileCloser struct {
	File
}

func (this lockAndFileCloser) Close() (rErr error) {
	defer func() {
		if err := this.File.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()
	return unlockFile(this.File)
}
