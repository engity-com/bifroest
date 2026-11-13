//go:build windows

package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The profile primitive retains legacy flags0/Network3/PI_NOUI behavior. It
// verifies process LocalSystem as before; prospective password-checker callers
// additionally run it inside withS4USystemContext for thread-context isolation.
func profileDirectoryContext(ctx context.Context, account Account) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("missing native profile context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	for _, procedure := range []*windows.LazyProc{s4uLoadProfile, s4uUnloadProfile} {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := procedure.Find(); err != nil {
			return "", err
		}
	}
	var current Account
	return readSAMProfileDirectory(ctx, samProfileOperations{
		identity: func() error { var err error; current, err = currentAccount(account); return err },
		system: func() error {
			system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
			if err != nil {
				return fmt.Errorf("resolve LocalSystem SID: %w", err)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			self, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err != nil {
				return fmt.Errorf("read process identity for local S4U: %w", err)
			}
			if self == nil || self.User.Sid == nil || !self.User.Sid.Equals(system) {
				return errors.New("local S4U requires a LocalSystem process")
			}
			return nil
		},
		s4u: func() (uintptr, error) {
			token, err := s4uImpersonationTokenWithFlagsContext(ctx, current.Name, 0)
			return uintptr(token), err
		},
		duplicate: func(value uintptr) (uintptr, error) {
			var token windows.Token
			err := windows.DuplicateTokenEx(windows.Token(value), windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token)
			if err != nil {
				return uintptr(token), fmt.Errorf("DuplicateTokenEx: %w", err)
			}
			return uintptr(token), nil
		},
		tokenIdentity: func(value uintptr) error {
			user, err := windows.Token(value).GetTokenUser()
			if err != nil {
				return fmt.Errorf("read S4U token SID: %w", err)
			}
			if user == nil || !sameSID(account.SID, user.User.Sid) {
				return errors.New("S4U token SID differs from local SAM account")
			}
			return nil
		},
		load: func(value uintptr) (uintptr, error) {
			name, err := windows.UTF16PtrFromString(current.Name)
			if err != nil {
				return 0, err
			}
			info := s4uProfileInfo{Flags: 1, UserName: name}
			info.Size = uint32(unsafe.Sizeof(info)) // PI_NOUI.
			ok, _, callErr := s4uLoadProfile.Call(value, uintptr(unsafe.Pointer(&info)))
			runtime.KeepAlive(name)
			if ok == 0 {
				return uintptr(info.Profile), fmt.Errorf("LoadUserProfileW: %w", s4uCallError(callErr))
			}
			return uintptr(info.Profile), nil
		},
		directory: func(value uintptr) (string, error) {
			home, err := windows.Token(value).GetUserProfileDirectory()
			if err != nil {
				return "", fmt.Errorf("GetUserProfileDirectoryW: %w", err)
			}
			return home, nil
		},
		unload: func(token, profile uintptr) error {
			if ok, _, err := s4uUnloadProfile.Call(token, profile); ok == 0 {
				return fmt.Errorf("UnloadUserProfile: %w", s4uCallError(err))
			}
			return nil
		},
		closeToken: func(value uintptr) error { return windows.Token(value).Close() },
	})
}
