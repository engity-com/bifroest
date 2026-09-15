//go:build unix

package recording

import (
	goerrors "errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/errors"
)

type localProcessLock struct {
	file *os.File
	once sync.Once
	err  error
}

func acquireLocalProcessLock(path string) (*localProcessLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, localFileMode)
	if goerrors.Is(err, os.ErrExist) {
		info, inspectErr := os.Lstat(path)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if !info.Mode().IsRegular() {
			return nil, errors.Config.Newf("local recording lock is not a regular file")
		}
		file, err = os.OpenFile(path, os.O_RDWR, localFileMode)
	}
	if err != nil {
		return nil, err
	}
	if err := validateOpenLocalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := secureLocalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &localProcessLock{file: file}, nil
}

func (this *localProcessLock) Close() error {
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

func validateLocalLock(lock *localProcessLock, path string) error {
	if lock == nil || lock.file == nil {
		return errors.System.Newf("local recording lock is closed")
	}
	return validateOpenLocalFile(path, lock.file)
}

func secureLocalDirectory(path string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode().Perm() != localDirectoryMode {
		return errors.Config.Newf("local recording directory has insecure permissions")
	}
	return validateLocalOwner(path, info, false)
}

func secureLocalFile(path string, file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != localFileMode {
		return errors.Config.Newf("local recording file has insecure permissions")
	}
	return validateLocalOwner(path, info, true)
}

func validateLocalOwner(_ string, info os.FileInfo, requireSingleLink bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.System.Newf("cannot determine local recording owner")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.Config.Newf("local recording path is owned by another user")
	}
	if requireSingleLink && stat.Nlink != 1 {
		return errors.Config.Newf("local recording file has multiple hard links")
	}
	return nil
}

func protectLocalHead(_ string, file *os.File) error {
	if err := file.Chmod(0400); err != nil {
		return err
	}
	return file.Sync()
}

func openLocalHead(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("local recording head is not a regular file")
	}
	file, err := openLocalNoFollow(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.Mode().Perm() != 0400 {
		_ = file.Close()
		return nil, errors.Config.Newf("local recording head is not read-only")
	}
	if !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, errors.System.Newf("local recording head changed while opening")
	}
	if err := validateLocalOwner(path, info, true); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func makeActiveLocalWritable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.Config.Newf("active local recording is not a regular file")
	}
	if err := validateLocalOwner(path, info, true); err != nil {
		return err
	}
	if info.Mode().Perm() == localFileMode {
		return nil
	}
	if info.Mode().Perm() != 0400 {
		return errors.Config.Newf("active local recording has unexpected permissions")
	}
	return os.Chmod(path, localFileMode)
}

func sealLocalFile(_ string, file *os.File) error {
	if err := file.Chmod(0400); err != nil {
		return err
	}
	return file.Sync()
}

func openSealedLocalFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("sealed local recording is not a regular file")
	}
	file, err := openLocalNoFollow(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.Mode().Perm() != 0400 {
		_ = file.Close()
		return nil, errors.Config.Newf("sealed local recording is not read-only")
	}
	if !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, errors.System.Newf("sealed local recording changed while opening")
	}
	if err := validateLocalOwner(path, info, true); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openLocalNoFollow(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil
}

func replaceLocalFile(source, target string) error {
	return os.Rename(source, target)
}

func publishLocalDirectory(source, target string) error {
	return os.Rename(source, target)
}

func publishLocalFile(source, target string) error {
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !sourceInfo.Mode().IsRegular() || hardLinkCount(sourceInfo) != 1 {
		return errors.Config.Newf("active recording has an unsafe link count")
	}
	if err := os.Link(source, target); err != nil {
		if goerrors.Is(err, os.ErrExist) {
			sourceInfo, sourceErr := os.Lstat(source)
			targetInfo, targetErr := os.Lstat(target)
			if sourceErr == nil && targetErr == nil && sourceInfo.Mode().IsRegular() && targetInfo.Mode().IsRegular() && os.SameFile(sourceInfo, targetInfo) {
				if err := syncLocalDirectory(filepath.Dir(target)); err != nil {
					return err
				}
				if err := os.Remove(source); err != nil {
					return err
				}
				return syncLocalDirectory(filepath.Dir(source))
			}
		}
		return err
	}
	linkedSource, sourceErr := os.Lstat(source)
	linkedTarget, targetErr := os.Lstat(target)
	if sourceErr != nil || targetErr != nil || !linkedSource.Mode().IsRegular() || !linkedTarget.Mode().IsRegular() || !os.SameFile(linkedSource, linkedTarget) || hardLinkCount(linkedSource) != 2 || hardLinkCount(linkedTarget) != 2 {
		return errors.System.Newf("recording publish did not create the expected hard-link pair")
	}
	if err := syncLocalDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	return syncLocalDirectory(filepath.Dir(source))
}

func completeLocalPublishAlias(source, target string) (bool, error) {
	sourceInfo, sourceErr := os.Lstat(source)
	targetInfo, targetErr := os.Lstat(target)
	if goerrors.Is(sourceErr, os.ErrNotExist) || goerrors.Is(targetErr, os.ErrNotExist) {
		return false, nil
	}
	if sourceErr != nil {
		return false, sourceErr
	}
	if targetErr != nil {
		return false, targetErr
	}
	if !sourceInfo.Mode().IsRegular() || !targetInfo.Mode().IsRegular() {
		return false, errors.Config.Newf("recording publish path is not a regular file")
	}
	if !os.SameFile(sourceInfo, targetInfo) {
		return false, nil
	}
	if hardLinkCount(sourceInfo) != 2 || hardLinkCount(targetInfo) != 2 {
		return false, errors.Config.Newf("interrupted recording publish has an unsafe link count")
	}
	if err := syncLocalDirectory(filepath.Dir(target)); err != nil {
		return false, err
	}
	if err := os.Remove(source); err != nil {
		return false, err
	}
	if err := syncLocalDirectory(filepath.Dir(source)); err != nil {
		return false, err
	}
	return true, nil
}

func hardLinkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 0
}

func syncLocalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
