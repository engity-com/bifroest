//go:build windows

package recording

import (
	goerrors "errors"
	"io/fs"
	"os"
	"sync"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type localProcessLock struct {
	file       *os.File
	overlapped windows.Overlapped
	once       sync.Once
	err        error
}

func removeLocalFile(path string) error {
	return os.Remove(path)
}

func removeLocalRetentionTombstone(path string) (int64, bool, error) {
	info, err := os.Stat(path)
	if goerrors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return 0, false, errors.Config.Newf("local recording retention tombstone is invalid")
	}
	if err := os.Remove(path); err != nil {
		return 0, false, err
	}
	return info.Size(), true, nil
}

func acquireLocalProcessLock(path string) (*localProcessLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, localFileMode)
	if err != nil {
		return nil, err
	}
	lock := &localProcessLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return lock, nil
}

func (this *localProcessLock) Close() error {
	if this == nil {
		return nil
	}
	this.once.Do(func() {
		if this.file == nil {
			return
		}
		if err := windows.UnlockFileEx(windows.Handle(this.file.Fd()), 0, 1, 0, &this.overlapped); err != nil {
			this.err = err
		}
		if err := this.file.Close(); err != nil && this.err == nil {
			this.err = err
		}
	})
	return this.err
}

func validateLocalLock(lock *localProcessLock, _ string) error {
	if lock == nil || lock.file == nil {
		return errors.System.Newf("local recording lock is closed")
	}
	return nil
}

func secureLocalDirectory(_ string, info os.FileInfo) error {
	if !info.IsDir() {
		return errors.Config.Newf("local recording path is not a directory")
	}
	return nil
}

func secureLocalFile(_ string, file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.Config.Newf("local recording path is not a regular file")
	}
	return nil
}

func protectLocalReadOnlyFile(_ string, file *os.File) error {
	return file.Sync()
}

func openProtectedLocalFile(path string) (*os.File, error) {
	return openRegularLocalFile(path, os.O_RDONLY)
}

func openReadOnlyLocalFile(path string) (*os.File, error) {
	return openRegularLocalFile(path, os.O_RDONLY)
}

func openMutablePrivateLocalFile(path string) (*os.File, error) {
	return openRegularLocalFile(path, os.O_RDWR)
}

func openRegularLocalFile(path string, flag int) (*os.File, error) {
	file, err := os.OpenFile(path, flag, localFileMode)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.Config.Newf("local recording path is not a regular file")
	}
	return file, nil
}

func sealLocalFile(_ string, file *os.File) error {
	return file.Sync()
}

func openSealedLocalFile(path string) (*os.File, error) {
	return openRegularLocalFile(path, os.O_RDONLY)
}

func replaceLocalFile(source, target string) error {
	return moveLocalPath(source, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func publishLocalDirectory(source, target string) error {
	return moveLocalPath(source, target, windows.MOVEFILE_WRITE_THROUGH)
}

func publishLocalFile(source, target string) error {
	return moveLocalPath(source, target, windows.MOVEFILE_WRITE_THROUGH)
}

func moveLocalPath(source, target string, flags uint32) error {
	sourcePointer, err := sys.WindowsPathPointer(source)
	if err != nil {
		return err
	}
	targetPointer, err := sys.WindowsPathPointer(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourcePointer, targetPointer, flags)
}

func syncLocalDirectory(string) error {
	return nil
}
