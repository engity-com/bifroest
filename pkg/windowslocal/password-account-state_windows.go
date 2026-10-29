//go:build windows

package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type userInfo3 struct {
	userInfo2
	UserID, PrimaryGroupID uint32
	Profile, HomeDirDrive  *uint16
	PasswordExpired        uint32
}

type userModalsInfo0 struct {
	MinimumPasswordLength, MaximumPasswordAge, MinimumPasswordAge, ForceLogoff, PasswordHistoryLength uint32
}

// This is only a fresh native restriction snapshot. An empty denial reason is
// NOT eligibility: S4U/account rights, blank-password policy, identity/template
// revalidation and all error/cleanup checks remain separate mandatory work.
type preliminaryPasswordAccountState struct {
	Account                                                Account
	Flags, AccountExpires, PasswordAge, MaximumPasswordAge uint32
	PasswordExpired                                        bool
}

func (this preliminaryPasswordAccountState) denialReason(now time.Time) string {
	if this.Flags&0x2 != 0 {
		return "account-disabled"
	}
	if this.Flags&0x10 != 0 {
		return "account-locked"
	}
	if this.AccountExpires != ^uint32(0) && int64(this.AccountExpires) <= now.Unix() {
		return "account-expired"
	}
	if this.PasswordExpired || this.Flags&0x800000 != 0 {
		return "password-must-change"
	}
	if this.Flags&0x10000 == 0 && this.MaximumPasswordAge != ^uint32(0) && this.PasswordAge >= this.MaximumPasswordAge {
		return "password-expired"
	}
	return ""
}

func inspectPreliminaryPasswordAccount(ctx context.Context, account Account) (result *preliminaryPasswordAccountState, resultErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("missing native password-account context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, ctx.Err())
		if resultErr != nil {
			result = nil
		}
	}()
	current, err := currentAccount(account)
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(current.Name)
	if err != nil {
		return nil, err
	}
	var info *userInfo3
	err = netCall("NetUserGetInfo", 0, uintptr(unsafe.Pointer(name)), 3, uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(name)
	if info != nil {
		defer func() {
			resultErr = errors.Join(resultErr, netCall("NetApiBufferFree", uintptr(unsafe.Pointer(info))))
			if resultErr != nil {
				result = nil
			}
		}()
	}
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, fmt.Errorf("NetUserGetInfo returned no password-account state")
	}
	sid, err := windows.StringToSid(current.SID)
	if err != nil || sid.SubAuthorityCount() == 0 {
		return nil, fmt.Errorf("invalid local password-account SID")
	}
	if info.UserID != sid.SubAuthority(uint32(sid.SubAuthorityCount()-1)) {
		return nil, fmt.Errorf("native password-account RID differs from the selected SID")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result = &preliminaryPasswordAccountState{Account: current, Flags: info.Flags, AccountExpires: info.AccountExpires, PasswordAge: info.PasswordAge, PasswordExpired: info.PasswordExpired != 0}
	var policy *userModalsInfo0
	err = netCall("NetUserModalsGet", 0, 0, uintptr(unsafe.Pointer(&policy)))
	if policy != nil {
		defer func() {
			resultErr = errors.Join(resultErr, netCall("NetApiBufferFree", uintptr(unsafe.Pointer(policy))))
			if resultErr != nil {
				result = nil
			}
		}()
	}
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, fmt.Errorf("NetUserModalsGet returned no password policy")
	}
	result.MaximumPasswordAge = policy.MaximumPasswordAge
	if _, err := currentAccount(current); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
