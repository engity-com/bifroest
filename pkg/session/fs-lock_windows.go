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
	path       string
	overlapped windows.Overlapped
	once       sync.Once
	err        error
}

func acquireFsRepositoryProcessLock(path string, _ os.FileMode) (*fsRepositoryProcessLock, error) {
	file, err := openFsRepositoryProcessLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open repository lock file %q: %w", path, err)
	}
	result := &fsRepositoryProcessLock{file: file, path: path}
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

func openFsRepositoryProcessLockFile(path string) (*os.File, error) {
	encodedPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(encodedPath, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("cannot create file handle")
	}
	return file, nil
}

func sameFsRepositoryProcessLockFile(file *os.File, path string) (bool, error) {
	var openInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &openInfo); err != nil {
		return false, err
	}
	encodedPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	pathHandle, err := windows.CreateFile(encodedPath, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = windows.CloseHandle(pathHandle) }()
	var pathInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(pathHandle, &pathInfo); err != nil {
		return false, err
	}
	if pathInfo.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return false, nil
	}
	return openInfo.VolumeSerialNumber == pathInfo.VolumeSerialNumber &&
		openInfo.FileIndexHigh == pathInfo.FileIndexHigh && openInfo.FileIndexLow == pathInfo.FileIndexLow, nil
}

func (this *fsRepositoryProcessLock) Close() error {
	if this == nil {
		return nil
	}
	this.once.Do(func() {
		this.err = removeFsRepositoryProcessLock(this, this.path)
		if err := windows.UnlockFileEx(windows.Handle(this.file.Fd()), 0, 1, 0, &this.overlapped); err != nil {
			this.err = errors.Join(this.err, err)
		}
		if err := this.file.Close(); err != nil {
			this.err = errors.Join(this.err, err)
		}
	})
	return this.err
}
