//go:build unix

package recording

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type localRecordingProcessLock struct {
	file *os.File
	once sync.Once
	err  error
}

func acquireLocalRecordingProcessLock(path string) (*localRecordingProcessLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, localRecordingFileMode)
	if errors.Is(err, os.ErrExist) {
		info, inspectErr := os.Lstat(path)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("local recording lock is not a regular file")
		}
		file, err = os.OpenFile(path, os.O_RDWR, localRecordingFileMode)
	}
	if err != nil {
		return nil, err
	}
	if err := validateOpenLocalRecordingFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := secureLocalRecordingFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &localRecordingProcessLock{file: file}, nil
}

func (this *localRecordingProcessLock) Close() error {
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

func validateLocalRecordingLock(lock *localRecordingProcessLock, path string) error {
	if lock == nil || lock.file == nil {
		return errors.New("local recording lock is closed")
	}
	return validateOpenLocalRecordingFile(path, lock.file)
}

func secureLocalRecordingDirectory(path string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode().Perm() != localRecordingDirectoryMode {
		return errors.New("local recording directory has insecure permissions")
	}
	return validateLocalRecordingOwner(path, info, false)
}

func secureLocalRecordingFile(path string, file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != localRecordingFileMode {
		return errors.New("local recording file has insecure permissions")
	}
	return validateLocalRecordingOwner(path, info, true)
}

func validateLocalRecordingOwner(_ string, info os.FileInfo, requireSingleLink bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine local recording owner")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("local recording path is owned by another user")
	}
	if requireSingleLink && stat.Nlink != 1 {
		return errors.New("local recording file has multiple hard links")
	}
	return nil
}

func protectLocalRecordingHead(_ string, file *os.File) error {
	if err := file.Chmod(0400); err != nil {
		return err
	}
	return file.Sync()
}

func openLocalRecordingHead(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("local recording head is not a regular file")
	}
	file, err := openLocalRecordingNoFollow(path)
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
		return nil, errors.New("local recording head is not read-only")
	}
	if !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, errors.New("local recording head changed while opening")
	}
	if err := validateLocalRecordingOwner(path, info, true); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func makeActiveLocalRecordingWritable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("active local recording is not a regular file")
	}
	if err := validateLocalRecordingOwner(path, info, true); err != nil {
		return err
	}
	if info.Mode().Perm() == localRecordingFileMode {
		return nil
	}
	if info.Mode().Perm() != 0400 {
		return errors.New("active local recording has unexpected permissions")
	}
	return os.Chmod(path, localRecordingFileMode)
}

func sealLocalRecordingFile(_ string, file *os.File) error {
	if err := file.Chmod(0400); err != nil {
		return err
	}
	return file.Sync()
}

func openSealedLocalRecordingFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("sealed local recording is not a regular file")
	}
	file, err := openLocalRecordingNoFollow(path)
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
		return nil, errors.New("sealed local recording is not read-only")
	}
	if !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, errors.New("sealed local recording changed while opening")
	}
	if err := validateLocalRecordingOwner(path, info, true); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openLocalRecordingNoFollow(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil
}

func replaceLocalRecordingFile(source, target string) error {
	return os.Rename(source, target)
}

func publishLocalRecordingDirectory(source, target string) error {
	return os.Rename(source, target)
}

func publishLocalRecordingFile(source, target string) error {
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !sourceInfo.Mode().IsRegular() || localRecordingLinkCount(sourceInfo) != 1 {
		return errors.New("active recording has an unsafe link count")
	}
	if err := os.Link(source, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			sourceInfo, sourceErr := os.Lstat(source)
			targetInfo, targetErr := os.Lstat(target)
			if sourceErr == nil && targetErr == nil && sourceInfo.Mode().IsRegular() && targetInfo.Mode().IsRegular() && os.SameFile(sourceInfo, targetInfo) {
				if err := syncLocalRecordingDirectory(filepath.Dir(target)); err != nil {
					return err
				}
				if err := os.Remove(source); err != nil {
					return err
				}
				return syncLocalRecordingDirectory(filepath.Dir(source))
			}
		}
		return err
	}
	linkedSource, sourceErr := os.Lstat(source)
	linkedTarget, targetErr := os.Lstat(target)
	if sourceErr != nil || targetErr != nil || !linkedSource.Mode().IsRegular() || !linkedTarget.Mode().IsRegular() || !os.SameFile(linkedSource, linkedTarget) || localRecordingLinkCount(linkedSource) != 2 || localRecordingLinkCount(linkedTarget) != 2 {
		return errors.New("recording publish did not create the expected hard-link pair")
	}
	if err := syncLocalRecordingDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	if err := os.Remove(source); err != nil {
		return err
	}
	return syncLocalRecordingDirectory(filepath.Dir(source))
}

func completeLocalRecordingPublishAlias(source, target string) (bool, error) {
	sourceInfo, sourceErr := os.Lstat(source)
	targetInfo, targetErr := os.Lstat(target)
	if errors.Is(sourceErr, os.ErrNotExist) || errors.Is(targetErr, os.ErrNotExist) {
		return false, nil
	}
	if sourceErr != nil {
		return false, sourceErr
	}
	if targetErr != nil {
		return false, targetErr
	}
	if !sourceInfo.Mode().IsRegular() || !targetInfo.Mode().IsRegular() {
		return false, errors.New("recording publish path is not a regular file")
	}
	if !os.SameFile(sourceInfo, targetInfo) {
		return false, nil
	}
	if localRecordingLinkCount(sourceInfo) != 2 || localRecordingLinkCount(targetInfo) != 2 {
		return false, errors.New("interrupted recording publish has an unsafe link count")
	}
	if err := syncLocalRecordingDirectory(filepath.Dir(target)); err != nil {
		return false, err
	}
	if err := os.Remove(source); err != nil {
		return false, err
	}
	if err := syncLocalRecordingDirectory(filepath.Dir(source)); err != nil {
		return false, err
	}
	return true, nil
}

func localRecordingLinkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 0
}

func syncLocalRecordingDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
