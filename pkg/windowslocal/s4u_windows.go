//go:build windows

package windowslocal

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	s4uSecur32       = windows.NewLazySystemDLL("secur32.dll")
	s4uRegister      = s4uSecur32.NewProc("LsaRegisterLogonProcess")
	s4uLookupPackage = s4uSecur32.NewProc("LsaLookupAuthenticationPackage")
	s4uLogon         = s4uSecur32.NewProc("LsaLogonUser")
	s4uDeregister    = s4uSecur32.NewProc("LsaDeregisterLogonProcess")
	s4uFreeBuffer    = s4uSecur32.NewProc("LsaFreeReturnBuffer")
	s4uAllocateLUID  = windows.NewLazySystemDLL("advapi32.dll").NewProc("AllocateLocallyUniqueId")
	s4uLoadProfile   = windows.NewLazySystemDLL("userenv.dll").NewProc("LoadUserProfileW")
	s4uUnloadProfile = windows.NewLazySystemDLL("userenv.dll").NewProc("UnloadUserProfile")
)

type s4uString struct {
	Length, MaximumLength uint16
	Buffer                *byte
}

type s4uUnicodeString struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

type s4uAuth struct {
	MessageType uint32
	Flags       uint32
	User        s4uUnicodeString
	Domain      s4uUnicodeString
}

type s4uTokenSource struct {
	Name [8]byte
	ID   windows.LUID
}

type s4uQuotaLimits struct {
	PagedPool, NonPagedPool, MinimumWorkingSet, MaximumWorkingSet, PageFile uintptr
	TimeLimit                                                               int64
}

type s4uProfileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     windows.Handle
}

// profileDirectory loads the real profile for a key-only account without
// knowing its password. S4U registration requires a LocalSystem process.
func profileDirectory(a Account) (home string, retErr error) {
	current, err := currentAccount(a)
	if err != nil {
		return "", err
	}
	expected, _ := windows.StringToSid(current.SID)
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return "", fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read process identity for local S4U: %w", err)
	}
	if self == nil || self.User.Sid == nil || !self.User.Sid.Equals(system) {
		return "", errors.New("local S4U requires a LocalSystem process")
	}

	impersonation, err := s4uImpersonationToken(current.Name)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := impersonation.Close(); err != nil {
			home = ""
			retErr = errors.Join(retErr, fmt.Errorf("close S4U impersonation token: %w", err))
		}
	}()
	var primary windows.Token
	err = windows.DuplicateTokenEx(impersonation, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary)
	if primary != 0 {
		defer func() {
			if err := primary.Close(); err != nil {
				home = ""
				retErr = errors.Join(retErr, fmt.Errorf("close S4U primary token: %w", err))
			}
		}()
	}
	if err != nil {
		return "", fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	if primary == 0 {
		return "", errors.New("DuplicateTokenEx returned no token")
	}
	user, err := primary.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read S4U token SID: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.Equals(expected) {
		return "", errors.New("S4U token SID differs from local SAM account")
	}
	if _, err := currentAccount(a); err != nil {
		return "", err
	}

	name, err := windows.UTF16PtrFromString(current.Name)
	if err != nil {
		return "", err
	}
	info := s4uProfileInfo{Flags: 1, UserName: name} // PI_NOUI
	info.Size = uint32(unsafe.Sizeof(info))
	ok, _, callErr := s4uLoadProfile.Call(uintptr(primary), uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(name)
	if info.Profile != 0 {
		defer func() {
			if ok, _, err := s4uUnloadProfile.Call(uintptr(primary), uintptr(info.Profile)); ok == 0 {
				home = ""
				retErr = errors.Join(retErr, fmt.Errorf("UnloadUserProfile: %w", s4uCallError(err)))
			}
		}()
	}
	if ok == 0 {
		return "", fmt.Errorf("LoadUserProfileW: %w", s4uCallError(callErr))
	}
	if info.Profile == 0 {
		return "", errors.New("LoadUserProfileW returned no profile handle")
	}
	home, err = primary.GetUserProfileDirectory()
	if err != nil {
		return "", fmt.Errorf("GetUserProfileDirectoryW: %w", err)
	}
	if home == "" {
		return "", errors.New("GetUserProfileDirectoryW returned an empty path")
	}
	if _, err := currentAccount(a); err != nil {
		return "", err
	}
	return home, nil
}

func s4uLogonBuffer(name string) ([]uint64, int, error) {
	user, err := windows.UTF16FromString(name)
	if err != nil {
		return nil, 0, err
	}
	if len(user)*2 > 65535 {
		return nil, 0, errors.New("local SAM name exceeds S4U buffer limit")
	}
	domain := [...]uint16{'.', 0}
	base := int(unsafe.Sizeof(s4uAuth{}))
	length := base + (len(user)+len(domain))*2
	buffer := make([]uint64, (length+7)/8)
	units := unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[0])), len(buffer)*4)
	userUnits := units[base/2 : base/2+len(user)]
	domainUnits := units[base/2+len(user) : base/2+len(user)+len(domain)]
	copy(userUnits, user)
	copy(domainUnits, domain[:])
	auth := (*s4uAuth)(unsafe.Pointer(&buffer[0]))
	auth.MessageType = 12 // MsV1_0S4ULogon
	auth.User = s4uUnicodeString{uint16((len(user) - 1) * 2), uint16(len(user) * 2), &userUnits[0]}
	auth.Domain = s4uUnicodeString{2, 4, &domainUnits[0]}
	return buffer, length, nil
}

func s4uImpersonationToken(name string) (result windows.Token, retErr error) {
	originBytes := []byte("BifS4U\x00")
	origin := s4uString{uint16(len(originBytes) - 1), uint16(len(originBytes)), &originBytes[0]}
	var handle uintptr
	var mode uint64
	status, _, _ := s4uRegister.Call(uintptr(unsafe.Pointer(&origin)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&mode)))
	runtime.KeepAlive(originBytes)
	if status != 0 {
		return 0, fmt.Errorf("LsaRegisterLogonProcess: NTSTATUS 0x%08x", uint32(status))
	}
	defer func() {
		if status, _, _ := s4uDeregister.Call(handle); status != 0 {
			retErr = errors.Join(retErr, fmt.Errorf("LsaDeregisterLogonProcess: NTSTATUS 0x%08x", uint32(status)))
		}
		if retErr != nil && result != 0 {
			retErr = errors.Join(retErr, result.Close())
			result = 0
		}
	}()

	packageBytes := []byte("MICROSOFT_AUTHENTICATION_PACKAGE_V1_0\x00")
	packageName := s4uString{uint16(len(packageBytes) - 1), uint16(len(packageBytes)), &packageBytes[0]}
	var packageID uint32
	status, _, _ = s4uLookupPackage.Call(handle, uintptr(unsafe.Pointer(&packageName)), uintptr(unsafe.Pointer(&packageID)))
	runtime.KeepAlive(packageBytes)
	if status != 0 {
		return 0, fmt.Errorf("LsaLookupAuthenticationPackage: NTSTATUS 0x%08x", uint32(status))
	}

	buffer, length, err := s4uLogonBuffer(name)
	if err != nil {
		return 0, err
	}
	source := s4uTokenSource{}
	copy(source.Name[:], "BifS4U")
	if ok, _, callErr := s4uAllocateLUID.Call(uintptr(unsafe.Pointer(&source.ID))); ok == 0 {
		return 0, fmt.Errorf("AllocateLocallyUniqueId: %w", s4uCallError(callErr))
	}
	var profile uintptr
	var profileSize uint32
	var logonID windows.LUID
	var quota s4uQuotaLimits
	var substatus uint32
	status, _, _ = s4uLogon.Call(
		handle, uintptr(unsafe.Pointer(&origin)), 3, // Network
		uintptr(packageID), uintptr(unsafe.Pointer(&buffer[0])), uintptr(length), 0,
		uintptr(unsafe.Pointer(&source)), uintptr(unsafe.Pointer(&profile)),
		uintptr(unsafe.Pointer(&profileSize)), uintptr(unsafe.Pointer(&logonID)),
		uintptr(unsafe.Pointer(&result)), uintptr(unsafe.Pointer(&quota)), uintptr(unsafe.Pointer(&substatus)),
	)
	runtime.KeepAlive(originBytes)
	runtime.KeepAlive(buffer)
	if profile != 0 {
		if freeStatus, _, _ := s4uFreeBuffer.Call(profile); freeStatus != 0 {
			retErr = fmt.Errorf("LsaFreeReturnBuffer: NTSTATUS 0x%08x", uint32(freeStatus))
		}
	}
	if status != 0 {
		retErr = errors.Join(retErr, fmt.Errorf("LsaLogonUser: NTSTATUS 0x%08x (substatus 0x%08x)", uint32(status), substatus))
	} else if result == 0 {
		retErr = errors.Join(retErr, errors.New("LsaLogonUser returned no token"))
	}
	return result, retErr
}

func s4uCallError(err error) error {
	if err == nil || err == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return err
}
