//go:build windows

package crypto

import (
	goerrors "errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validateSecurePrivateKeyFile(path string, file *os.File, _ os.FileInfo) error {
	var fileInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &fileInfo); err != nil {
		return fmt.Errorf("cannot inspect link count of private key %q: %w", path, err)
	}
	if fileInfo.NumberOfLinks != 1 {
		return fmt.Errorf("private key %q has %d hard links instead of one", path, fileInfo.NumberOfLinks)
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot inspect access control of private key %q: %w", path, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("cannot determine owner of private key %q: %w", path, err)
	}
	processUser, err := currentProcessUserSid()
	if err != nil {
		return err
	}
	processOwner, err := currentProcessOwnerSid()
	if err != nil {
		return err
	}
	if owner == nil || (!owner.Equals(processUser) && !owner.Equals(processOwner)) {
		return fmt.Errorf("private key %q is owned by %v instead of the current process user %s or token owner %s", path, owner, processUser, processOwner)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("cannot inspect access-control flags of private key %q: %w", path, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private key %q does not have a protected access-control list", path)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("cannot inspect access-control list of private key %q: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("private key %q has an unrestricted access-control list", path)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("cannot resolve local SYSTEM identity: %w", err)
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return fmt.Errorf("cannot resolve OWNER RIGHTS identity: %w", err)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("cannot inspect access-control entry %d of private key %q: %w", index, path, err)
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("private key %q has unsupported access-control entry type %d", path, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(processUser) && !sid.Equals(processOwner) && !sid.Equals(system) && !sid.Equals(ownerRights) {
			return fmt.Errorf("private key %q grants access to an identity other than its owner, OWNER RIGHTS, or SYSTEM", path)
		}
	}
	return nil
}

func currentProcessUserSid() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("cannot read current process user: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return nil, fmt.Errorf("current process token has no user SID")
	}
	result, err := user.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("cannot copy current process user SID: %w", err)
	}
	return result, nil
}

type privateKeyTokenOwner struct {
	owner *windows.SID
}

func currentProcessOwnerSid() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	var required uint32
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &required)
	if err != nil && !goerrors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("cannot determine current process token owner size: %w", err)
	}
	if required == 0 {
		return nil, fmt.Errorf("current process token has no owner information")
	}
	raw := make([]byte, required)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &raw[0], uint32(len(raw)), &required); err != nil {
		return nil, fmt.Errorf("cannot read current process token owner: %w", err)
	}
	owner := (*privateKeyTokenOwner)(unsafe.Pointer(&raw[0])).owner
	if owner == nil {
		return nil, fmt.Errorf("current process token has no owner SID")
	}
	result, err := owner.Copy()
	if err != nil {
		return nil, fmt.Errorf("cannot copy current process token owner SID: %w", err)
	}
	return result, nil
}
