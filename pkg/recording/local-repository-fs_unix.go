//go:build unix

package recording

import (
	goerrors "errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/errors"
)

type localProcessLock struct {
	file *os.File
	path string
	once sync.Once
	err  error
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
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &localProcessLock{file: file, path: path}, nil
}

func sameLocalProcessLockFile(file *os.File, path string) (bool, error) {
	openInfo, err := file.Stat()
	if err != nil {
		return false, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return pathInfo.Mode().IsRegular() && os.SameFile(openInfo, pathInfo), nil
}

func (this *localProcessLock) Close() error {
	if this == nil {
		return nil
	}
	this.once.Do(func() {
		if this.file == nil {
			return
		}
		this.err = removeLocalProcessLock(this, this.path)
		if err := unix.Flock(int(this.file.Fd()), unix.LOCK_UN); err != nil {
			this.err = goerrors.Join(this.err, err)
		}
		if err := this.file.Close(); err != nil {
			this.err = goerrors.Join(this.err, err)
		}
	})
	return this.err
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
	return os.Rename(source, target)
}

func publishLocalDirectory(source, target string) error {
	return renameLocalNoReplace(source, target)
}

func publishLocalFile(source, target string) error {
	return renameLocalNoReplace(source, target)
}

func renameLocalNoReplace(source, target string) error {
	if _, err := os.Stat(target); err == nil {
		return fs.ErrExist
	} else if !goerrors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(source, target); err != nil {
		return err
	}
	if err := syncLocalDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	if sourceDirectory := filepath.Dir(source); sourceDirectory != filepath.Dir(target) {
		return syncLocalDirectory(sourceDirectory)
	}
	return nil
}

func syncLocalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	return goerrors.Join(directory.Sync(), directory.Close())
}
