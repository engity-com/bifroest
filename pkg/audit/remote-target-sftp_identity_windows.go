//go:build windows

package audit

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validateSftpIdentityFilePermissions(identityPath string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(identityPath, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot inspect access control of private key %q: %w", identityPath, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("cannot determine owner of private key %q: %w", identityPath, err)
	}
	processOwner, err := currentProcessOwnerSid()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(processOwner) {
		return fmt.Errorf("private key %q is not owned by the current process token owner", identityPath)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("cannot inspect access-control flags of private key %q: %w", identityPath, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private key %q does not have a protected access-control list", identityPath)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("cannot inspect access-control list of private key %q: %w", identityPath, err)
	}
	if dacl == nil {
		return fmt.Errorf("private key %q has an unrestricted access-control list", identityPath)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("cannot resolve local SYSTEM identity: %w", err)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("cannot inspect access-control entry %d of private key %q: %w", index, identityPath, err)
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("private key %q has unsupported access-control entry type %d", identityPath, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(processOwner) && !sid.Equals(system) {
			return fmt.Errorf("private key %q grants access to an identity other than its owner or SYSTEM", identityPath)
		}
	}
	return nil
}
