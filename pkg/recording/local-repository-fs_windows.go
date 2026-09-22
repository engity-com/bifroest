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

const sealedLocalWindowsAccess = "0x00130189"

type localProcessLock struct {
	file       *os.File
	overlapped windows.Overlapped
	once       sync.Once
	err        error
}

func removeLocalFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.Config.Newf("local recording path is not a regular file")
	}
	changedMode := info.Mode().Perm()&0200 == 0
	if changedMode {
		if err := setLocalFileMode(path, localFileMode); err != nil {
			return err
		}
	} else {
		file, err := openLocalMetadataPath(path, false, false)
		if err != nil {
			return err
		}
		if err := validateLocalMetadataHandle(path, file, info, true); err != nil {
			return goerrors.Join(err, file.Close())
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	from, err := sys.WindowsPathPointer(path)
	if err != nil {
		return err
	}
	tombstone := path + localRetentionTombstone
	to, err := sys.WindowsPathPointer(tombstone)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		if changedMode {
			return goerrors.Join(err, setLocalFileMode(path, 0400))
		}
		return err
	}
	_, destroyed, err := removeLocalRetentionTombstone(tombstone)
	if destroyed {
		return nil
	}
	return err
}

func removeLocalRetentionTombstone(path string) (int64, bool, error) {
	pathInfo, err := os.Lstat(path)
	if goerrors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Size() < 0 {
		return 0, false, errors.Config.Newf("local recording retention tombstone is invalid")
	}
	if err := setLocalFileMetadata(path, "FA", localFileMode); err != nil {
		return 0, false, err
	}
	file, err := os.OpenFile(path, os.O_RDWR, localFileMode)
	if err != nil {
		return 0, false, err
	}
	if err := validateOpenLocalFile(path, file); err != nil {
		_ = file.Close()
		return 0, false, err
	}
	info, err := file.Stat()
	if err != nil {
		return 0, false, goerrors.Join(err, file.Close())
	}
	if !os.SameFile(pathInfo, info) {
		return 0, false, goerrors.Join(errors.System.Newf("local recording retention tombstone changed while opening"), file.Close())
	}
	if err := requireSingleHardLink(file); err != nil {
		return 0, false, goerrors.Join(err, file.Close())
	}
	if err := file.Truncate(0); err != nil {
		return 0, false, goerrors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return 0, false, goerrors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return 0, false, err
	}
	if err := os.Remove(path); err != nil {
		return info.Size(), true, err
	}
	return info.Size(), true, nil
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
	result := &localProcessLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &result.overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return result, nil
}

func (this *localProcessLock) Close() error {
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

func validateLocalLock(lock *localProcessLock, path string) error {
	if lock == nil || lock.file == nil {
		return errors.System.Newf("local recording lock is closed")
	}
	return validateOpenLocalFile(path, lock.file)
}

func secureLocalDirectory(path string, _ os.FileInfo) error {
	return secureLocalPath(path, "FA")
}

func secureLocalFile(path string, file *os.File) error {
	return secureLocalFileWithAccess(path, file, "FA")
}

func protectLocalReadOnlyFile(path string, file *os.File) error {
	if err := file.Sync(); err != nil {
		return err
	}
	return secureLocalFileWithAccess(path, file, "FRSD")
}

func openProtectedLocalFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("protected local recording file is not a regular file")
	}
	metadata, err := openLocalMetadataPath(path, false, false)
	if err != nil {
		return nil, err
	}
	if err := secureLocalMetadataHandle(path, metadata, pathInfo, true, "FRSD"); err != nil {
		return nil, goerrors.Join(err, metadata.Close())
	}
	file, err := openProtectedLocalData(path)
	if err != nil {
		return nil, goerrors.Join(err, metadata.Close())
	}
	if err := metadata.Close(); err != nil {
		_ = file.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return nil, errors.System.Newf("protected local recording file changed while opening")
	}
	if err := secureLocalFileWithAccess(path, file, "FRSD"); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openProtectedLocalData(path string) (*os.File, error) {
	nativePath, err := sys.WindowsPathPointer(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		nativePath,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func openReadOnlyLocalFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("local recording file is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(pathInfo, info) || !os.SameFile(current, info) {
		_ = file.Close()
		return nil, errors.System.Newf("local recording file changed while opening")
	}
	if err := requireSingleHardLink(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openMutablePrivateLocalFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("mutable local recording file is not a regular file")
	}
	file, err := os.OpenFile(path, os.O_RDWR, localFileMode)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(pathInfo, info) || !os.SameFile(current, info) {
		_ = file.Close()
		return nil, errors.System.Newf("mutable local recording file changed while opening")
	}
	if err := requireSingleHardLink(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validatePrivateLocalFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validatePrivateLocalFile(file *os.File) error {
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	userSid, ownerSid, err := localProcessSIDs()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(userSid) && !owner.Equals(ownerSid) {
		return errors.Config.Newf("local recording file is owned by another user")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.Config.Newf("local recording file does not have a protected access-control list")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return errors.Config.Newf("local recording file has an unrestricted access-control list")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.Config.Newf("local recording file has an unsupported access-control entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(userSid) && !sid.Equals(ownerSid) && !sid.Equals(system) {
			return errors.Config.Newf("local recording file grants access to another identity")
		}
	}
	return nil
}

func makeActiveLocalWritable(path string) error {
	return setLocalFileMetadata(path, "FA", localFileMode)
}

func sealLocalFile(path string, file *os.File) error {
	if err := requireSingleHardLink(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := secureLocalFileWithAccess(path, file, sealedLocalWindowsAccess); err != nil {
		return err
	}
	return file.Chmod(0400)
}

func openSealedLocalFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("sealed local recording is not a regular file")
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
	if err := secureLocalFileWithAccess(path, file, sealedLocalWindowsAccess); err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.Mode().Perm()&0200 != 0 {
		_ = file.Close()
		return nil, errors.Config.Newf("sealed local recording is writable")
	}
	return file, nil
}

func secureLocalPath(path, access string) (result error) {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	regular := info.Mode().IsRegular()
	if !regular && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return errors.Config.Newf("local recording path is neither a regular file nor directory")
	}
	file, err := openLocalMetadataPath(path, !regular, false)
	if err != nil {
		return err
	}
	defer func() {
		result = goerrors.Join(result, file.Close())
	}()
	return secureLocalMetadataHandle(path, file, info, regular, access)
}

func openLocalMetadataPath(path string, directory, writeAttributes bool) (*os.File, error) {
	nativePath, err := sys.WindowsPathPointer(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.READ_CONTROL | windows.WRITE_DAC)
	if writeAttributes {
		access |= windows.FILE_WRITE_ATTRIBUTES
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		nativePath,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func setLocalFileMetadata(path, access string, mode os.FileMode) error {
	expected, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !expected.Mode().IsRegular() {
		return errors.Config.Newf("local recording path is not a regular file")
	}
	security, err := openLocalMetadataPath(path, false, false)
	if err != nil {
		return err
	}
	if err := secureLocalMetadataHandle(path, security, expected, true, access); err != nil {
		return goerrors.Join(err, security.Close())
	}
	file, err := openLocalMetadataPath(path, false, true)
	if err != nil {
		return goerrors.Join(err, security.Close())
	}
	if err := validateLocalMetadataHandle(path, file, expected, true); err != nil {
		return goerrors.Join(err, file.Close(), security.Close())
	}
	return goerrors.Join(file.Chmod(mode), file.Close(), security.Close())
}

func setLocalFileMode(path string, mode os.FileMode) error {
	expected, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !expected.Mode().IsRegular() {
		return errors.Config.Newf("local recording path is not a regular file")
	}
	file, err := openLocalMetadataPath(path, false, true)
	if err != nil {
		return err
	}
	if err := validateLocalMetadataHandle(path, file, expected, true); err != nil {
		return goerrors.Join(err, file.Close())
	}
	return goerrors.Join(file.Chmod(mode), file.Close())
}

func secureLocalFileWithAccess(path string, file *os.File, access string) error {
	if file == nil {
		return errors.System.Newf("cannot secure nil local recording file")
	}
	if err := validateOpenLocalFile(path, file); err != nil {
		return err
	}
	if err := requireSingleHardLink(file); err != nil {
		return err
	}
	expected, err := file.Stat()
	if err != nil {
		return err
	}
	metadata, err := openLocalMetadataPath(path, false, false)
	if err != nil {
		return err
	}
	return goerrors.Join(secureLocalMetadataHandle(path, metadata, expected, true, access), metadata.Close())
}

func secureLocalMetadataHandle(path string, file *os.File, expected os.FileInfo, regular bool, access string) error {
	if err := validateLocalMetadataHandle(path, file, expected, regular); err != nil {
		return err
	}
	userSid, ownerSid, err := localProcessSIDs()
	if err != nil {
		return err
	}
	existing, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
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
	return windows.SetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func validateLocalMetadataHandle(path string, file *os.File, expected os.FileInfo, regular bool) error {
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if regular {
		if !opened.Mode().IsRegular() || !current.Mode().IsRegular() {
			return errors.System.Newf("local recording path changed while opening metadata")
		}
	} else if !opened.IsDir() || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 {
		return errors.System.Newf("local recording directory changed while opening metadata")
	}
	if expected == nil || !os.SameFile(expected, opened) || !os.SameFile(current, opened) {
		return errors.System.Newf("local recording path changed while opening metadata")
	}
	if regular {
		return requireSingleHardLink(file)
	}
	return nil
}

func localProcessSIDs() (*windows.SID, *windows.SID, error) {
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
	owner := (*localTokenOwner)(unsafe.Pointer(&raw[0])).owner
	if owner == nil {
		return nil, nil, errors.System.Newf("local recording process has no owner")
	}
	ownerSid, err := owner.Copy()
	return userSid, ownerSid, err
}

type localTokenOwner struct {
	owner *windows.SID
}

func requireSingleHardLink(file *os.File) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information); err != nil {
		return err
	}
	if information.NumberOfLinks != 1 {
		return errors.Config.Newf("local recording file has multiple hard links")
	}
	return nil
}

func replaceLocalFile(source, target string) error {
	return moveLocalFile(source, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func publishLocalDirectory(source, target string) error {
	return moveLocalFile(source, target, windows.MOVEFILE_WRITE_THROUGH)
}

func publishLocalFile(source, target string) error {
	return moveLocalFile(source, target, windows.MOVEFILE_WRITE_THROUGH)
}

func completeLocalPublishAlias(source, target string) (bool, error) {
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

func moveLocalFile(source, target string, flags uint32) error {
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

func syncLocalDirectory(string) error {
	return nil
}
