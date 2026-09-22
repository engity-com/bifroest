//go:build windows

package audit

import (
	goerrors "errors"
	"os"
	"sync"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
)

type journalProcessLock struct {
	file       *os.File
	path       string
	overlapped windows.Overlapped
	once       sync.Once
	err        error
}

func acquireJournalProcessLock(path string, _ os.FileMode) (*journalProcessLock, error) {
	file, err := openWindowsJournalLockFile(path)
	if err != nil {
		return nil, errors.System.Newf("cannot open audit journal lock file %q: %w", path, err)
	}
	result := &journalProcessLock{file: file, path: path}
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &result.overlapped)
	if err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.System.Newf("audit journal %q is already locked by another process", path)
		}
		return nil, errors.System.Newf("cannot determine lock state of audit journal %q: %w", path, err)
	}
	return result, nil
}

func openWindowsJournalLockFile(path string) (*os.File, error) {
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
		return nil, errors.System.Newf("cannot create audit journal lock file handle")
	}
	return prepareJournalLockFile(path, file)
}

func sameJournalProcessLockFile(file *os.File, path string) (bool, error) {
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

func (this *journalProcessLock) Close() error {
	if this == nil {
		return nil
	}
	this.once.Do(func() {
		this.err = removeJournalProcessLock(this, this.path)
		if err := windows.UnlockFileEx(windows.Handle(this.file.Fd()), 0, 1, 0, &this.overlapped); err != nil {
			this.err = goerrors.Join(this.err, errors.System.Newf("cannot release audit journal lock: %w", err))
		}
		if err := this.file.Close(); err != nil {
			this.err = goerrors.Join(this.err, errors.System.Newf("cannot close audit journal lock: %w", err))
		}
	})
	return this.err
}
