//go:build windows

package recording

import (
	goerrors "errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const sealedLocalRecordingWindowsAccess = "0x00130189"

type localRecordingProcessLock struct {
	file       *os.File
	overlapped windows.Overlapped
	once       sync.Once
	err        error
}

func acquireLocalRecordingProcessLock(path string) (*localRecordingProcessLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, localRecordingFileMode)
	if goerrors.Is(err, os.ErrExist) {
		info, inspectErr := os.Lstat(path)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if !info.Mode().IsRegular() {
			return nil, errors.Config.Newf("local recording lock is not a regular file")
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
	result := &localRecordingProcessLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &result.overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return result, nil
}

func (this *localRecordingProcessLock) Close() error {
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

func validateLocalRecordingLock(lock *localRecordingProcessLock, path string) error {
	if lock == nil || lock.file == nil {
		return errors.System.Newf("local recording lock is closed")
	}
	return validateOpenLocalRecordingFile(path, lock.file)
}

func secureLocalRecordingDirectory(path string, _ os.FileInfo) error {
	return secureLocalRecordingPath(path, "FA")
}

func secureLocalRecordingFile(path string, file *os.File) error {
	if err := requireSingleLocalRecordingLink(file); err != nil {
		return err
	}
	return secureLocalRecordingPath(path, "FA")
}

func protectLocalRecordingHead(path string, file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	return secureLocalRecordingPath(path, "FRSD")
}

func openLocalRecordingHead(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("local recording head is not a regular file")
	}
	if err := secureLocalRecordingPath(path, "FRSD"); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, errors.System.Newf("local recording head changed while opening")
	}
	if err := requireSingleLocalRecordingLink(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func makeActiveLocalRecordingWritable(path string) error {
	if err := secureLocalRecordingPath(path, "FA"); err != nil {
		return err
	}
	return os.Chmod(path, localRecordingFileMode)
}

func sealLocalRecordingFile(path string, file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	if err := os.Chmod(path, 0400); err != nil {
		return err
	}
	return secureLocalRecordingPath(path, sealedLocalRecordingWindowsAccess)
}

func openSealedLocalRecordingFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("sealed local recording is not a regular file")
	}
	if err := secureLocalRecordingPath(path, sealedLocalRecordingWindowsAccess); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, errors.System.Newf("sealed local recording changed while opening")
	}
	if info.Mode().Perm()&0200 != 0 {
		_ = file.Close()
		return nil, errors.Config.Newf("sealed local recording is writable")
	}
	if err := requireSingleLocalRecordingLink(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func secureLocalRecordingPath(path, access string) error {
	userSid, ownerSid, err := localRecordingProcessSids()
	if err != nil {
		return err
	}
	nativePath, err := sys.WindowsExtendedPath(path)
	if err != nil {
		return err
	}
	existing, err := windows.GetNamedSecurityInfo(nativePath, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := existing.Owner()
	if err != nil {
		return err
	}
	if owner == nil || (!owner.Equals(userSid) && !owner.Equals(ownerSid)) {
		return errors.Config.Newf("local recording path is owned by another user")
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;%s;;;SY)(A;;%s;;;%s)", access, access, userSid.String()))
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(nativePath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func localRecordingProcessSids() (*windows.SID, *windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, nil, errors.System.Newf("cannot determine local recording process user")
	}
	userSid, err := user.User.Sid.Copy()
	if err != nil {
		return nil, nil, err
	}
	token := windows.GetCurrentProcessToken()
	var required uint32
	err = windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &required)
	if err != nil && !goerrors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, nil, err
	}
	if required == 0 {
		return nil, nil, errors.System.Newf("local recording process has no owner information")
	}
	raw := make([]byte, required)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &raw[0], uint32(len(raw)), &required); err != nil {
		return nil, nil, err
	}
	owner := (*localRecordingTokenOwner)(unsafe.Pointer(&raw[0])).owner
	if owner == nil {
		return nil, nil, errors.System.Newf("local recording process has no owner")
	}
	ownerSid, err := owner.Copy()
	return userSid, ownerSid, err
}

type localRecordingTokenOwner struct {
	owner *windows.SID
}

func requireSingleLocalRecordingLink(file *os.File) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information); err != nil {
		return err
	}
	if information.NumberOfLinks != 1 {
		return errors.Config.Newf("local recording file has multiple hard links")
	}
	return nil
}

func replaceLocalRecordingFile(source, target string) error {
	return moveLocalRecordingFile(source, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func publishLocalRecordingDirectory(source, target string) error {
	return moveLocalRecordingFile(source, target, windows.MOVEFILE_WRITE_THROUGH)
}

func publishLocalRecordingFile(source, target string) error {
	return moveLocalRecordingFile(source, target, windows.MOVEFILE_WRITE_THROUGH)
}

func completeLocalRecordingPublishAlias(source, target string) (bool, error) {
	if _, err := os.Lstat(source); err != nil && !goerrors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if info, err := os.Lstat(target); err == nil && !info.Mode().IsRegular() {
		return false, errors.Config.Newf("sealed recording target is not a regular file")
	} else if err != nil && !goerrors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
}

func moveLocalRecordingFile(source, target string, flags uint32) error {
	from, err := sys.WindowsPathPointer(source)
	if err != nil {
		return err
	}
	to, err := sys.WindowsPathPointer(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, flags)
}

func syncLocalRecordingDirectory(string) error {
	return nil
}
