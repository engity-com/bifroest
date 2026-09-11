//go:build windows

package audit

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
)

func secureJournalDirectory(path string, _ os.FileInfo) error {
	return secureJournalPath(path)
}

func secureJournalFile(path string, _ *os.File) error {
	return secureJournalPath(path)
}

func secureJournalPath(path string) error {
	ownerSid, err := currentProcessOwnerSid()
	if err != nil {
		return err
	}
	existing, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
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
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;FA;;;SY)(A;;FA;;;%s)", ownerSid.String()))
	if err != nil {
		return errors.System.Newf("cannot create audit journal security descriptor: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return errors.System.Newf("cannot create audit journal access-control list: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return errors.System.Newf("cannot protect audit journal path %q: %w", path, err)
	}
	return nil
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
