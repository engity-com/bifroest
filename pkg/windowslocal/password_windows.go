//go:build windows

package windowslocal

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var logonUser = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")

// ValidatePassword authenticates against the local SAM, without S4U or a
// persistent credential. An ordinary logon rejection returns false, nil.
func ValidatePassword(a Account, password string) (valid bool, retErr error) {
	current, err := currentAccount(a)
	if err != nil {
		return false, err
	}
	if !utf8.ValidString(password) {
		return false, nil
	}
	username, _ := windows.UTF16PtrFromString(current.Name)
	secret, err := windows.UTF16FromString(password)
	if err != nil {
		return false, nil // An embedded NUL is not a valid password input.
	}
	defer clear(secret)
	domain := [...]uint16{'.', 0}
	var token windows.Token
	ok, _, callErr := logonUser.Call(
		uintptr(unsafe.Pointer(username)), uintptr(unsafe.Pointer(&domain[0])),
		uintptr(unsafe.Pointer(&secret[0])), 3, 0, // LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT
		uintptr(unsafe.Pointer(&token)),
	)
	runtime.KeepAlive(username)
	runtime.KeepAlive(domain)
	runtime.KeepAlive(secret)
	if token != 0 {
		defer func() {
			if err := token.Close(); err != nil {
				valid = false
				retErr = errors.Join(retErr, err)
			}
		}()
	}
	if ok == 0 {
		if invalidCredentials(callErr) {
			return false, nil
		}
		if callErr == nil || callErr == syscall.Errno(0) {
			callErr = syscall.EINVAL
		}
		return false, fmt.Errorf("LogonUserW: %w", callErr)
	}
	if token == 0 {
		return false, errors.New("LogonUserW returned no token")
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("read logon token SID: %w", err)
	}
	if user == nil || user.User.Sid == nil || !sameSID(current.SID, user.User.Sid) {
		return false, errors.New("logon token SID differs from local SAM account")
	}
	if _, err := currentAccount(a); err != nil {
		return false, err
	}
	return true, nil
}

func invalidCredentials(err error) bool {
	for _, code := range []syscall.Errno{
		86,   // ERROR_INVALID_PASSWORD
		1326, // ERROR_LOGON_FAILURE
		1327, // ERROR_ACCOUNT_RESTRICTION
		1328, // ERROR_INVALID_LOGON_HOURS
		1329, // ERROR_INVALID_WORKSTATION
		1330, // ERROR_PASSWORD_EXPIRED
		1331, // ERROR_ACCOUNT_DISABLED
		1907, // ERROR_PASSWORD_MUST_CHANGE
		1909, // ERROR_ACCOUNT_LOCKED_OUT
	} {
		if errors.Is(err, code) {
			return true
		}
	}
	return false
}
