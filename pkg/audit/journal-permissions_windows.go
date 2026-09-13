//go:build windows

package audit

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func secureJournalDirectory(path string, _ os.FileInfo) error {
	return secureJournalPath(path)
}

func secureJournalFile(path string, _ *os.File) error {
	return secureJournalPath(path)
}

func secureJournalPath(path string) error {
	return secureJournalPathWithAccess(path, "FA")
}

func secureJournalPathWithAccess(path, access string) error {
	ownerSid, err := currentProcessOwnerSid()
	if err != nil {
		return err
	}
	nativePath, err := sys.WindowsExtendedPath(path)
	if err != nil {
		return errors.System.Newf("cannot resolve native audit journal path %q: %w", path, err)
	}
	existing, err := windows.GetNamedSecurityInfo(nativePath, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return errors.System.Newf("cannot inspect owner of %q: %w", path, err)
	}
	if existing == nil {
		return errors.Config.Newf("%q has no security descriptor", path)
	}
	owner, _, err := existing.Owner()
	if err != nil {
		return errors.System.Newf("cannot resolve owner of %q: %w", path, err)
	}
	if owner == nil || !owner.Equals(ownerSid) {
		return errors.Config.Newf("%q is not owned by the current process token owner", path)
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;%s;;;SY)(A;;%s;;;%s)", access, access, ownerSid.String()))
	if err != nil {
		return errors.System.Newf("cannot create audit journal security descriptor: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return errors.System.Newf("cannot create audit journal access-control list: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(nativePath, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return errors.System.Newf("cannot protect audit journal path %q: %w", path, err)
	}
	return nil
}

func makeActiveJournalWritable(path string) error {
	if err := secureJournalPath(path); err != nil {
		return err
	}
	if err := os.Chmod(path, journalFileMode); err != nil {
		return errors.System.Newf("cannot make active audit segment writable %q: %w", path, err)
	}
	return nil
}

func sealJournalFile(path string, file *os.File) error {
	if err := file.Sync(); err != nil {
		return errors.System.Newf("cannot flush sealed audit segment %q: %w", path, err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		return errors.System.Newf("cannot mark sealed audit segment read-only %q: %w", path, err)
	}
	return secureJournalPathWithAccess(path, "FR")
}

func openSealedJournal(path string) (*os.File, error) {
	if err := secureJournalPathWithAccess(path, "FR"); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.System.Newf("cannot open sealed audit segment %q: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, errors.System.Newf("cannot inspect sealed audit segment %q: %w", path, err)
	}
	if info.Mode().Perm()&0200 != 0 {
		_ = file.Close()
		return nil, errors.Config.Newf("sealed audit segment %q is writable", path)
	}
	return file, nil
}

type tokenOwner struct {
	owner *windows.SID
}

func currentProcessOwnerSid() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	var required uint32
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &required)
	if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, errors.System.Newf("cannot determine current process token owner size: %w", err)
	}
	if required == 0 {
		return nil, errors.System.Newf("current process token has no owner information")
	}
	raw := make([]byte, required)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &raw[0], uint32(len(raw)), &required); err != nil {
		return nil, errors.System.Newf("cannot read current process token owner: %w", err)
	}
	owner := (*tokenOwner)(unsafe.Pointer(&raw[0])).owner
	if owner == nil {
		return nil, errors.System.Newf("current process token has no owner SID")
	}
	return owner, nil
}
