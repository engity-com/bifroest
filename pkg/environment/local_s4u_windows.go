//go:build windows

package environment

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
	"unsafe"

	log "github.com/echocat/slf4g"
	"golang.org/x/sys/windows"
)

var (
	errLocalWindowsAccountNotFound = errors.New("local Windows account not found")

	localS4USecur32       = windows.NewLazySystemDLL("secur32.dll")
	localS4URegister      = localS4USecur32.NewProc("LsaRegisterLogonProcess")
	localS4ULookupPackage = localS4USecur32.NewProc("LsaLookupAuthenticationPackage")
	localS4ULogon         = localS4USecur32.NewProc("LsaLogonUser")
	localS4UDeregister    = localS4USecur32.NewProc("LsaDeregisterLogonProcess")
	localS4UFreeBuffer    = localS4USecur32.NewProc("LsaFreeReturnBuffer")
	localS4UAllocateLUID  = windows.NewLazySystemDLL("advapi32.dll").NewProc("AllocateLocallyUniqueId")
	localS4ULoadProfile   = windows.NewLazySystemDLL("userenv.dll").NewProc("LoadUserProfileW")
	localS4UUnloadProfile = windows.NewLazySystemDLL("userenv.dll").NewProc("UnloadUserProfile")
)

type windowsLocalAccount struct {
	Name string `json:"name"`
	SID  string `json:"sid"`
}

func lookupLocalWindowsAccount(name string) (windowsLocalAccount, error) {
	if !validLocalSAMName(name) {
		return windowsLocalAccount{}, fmt.Errorf("invalid local SAM account name %q", name)
	}
	host, err := os.Hostname()
	if err != nil {
		return windowsLocalAccount{}, fmt.Errorf("get local computer name: %w", err)
	}
	sid, domain, kind, err := windows.LookupSID("", host+`\`+name)
	if err != nil {
		if errors.Is(err, windows.ERROR_NONE_MAPPED) {
			return windowsLocalAccount{}, fmt.Errorf("%w: %q", errLocalWindowsAccountNotFound, name)
		}
		return windowsLocalAccount{}, fmt.Errorf("lookup local account %q: %w", name, err)
	}
	if kind != windows.SidTypeUser || !strings.EqualFold(domain, host) || sid == nil || !sid.IsValid() {
		return windowsLocalAccount{}, fmt.Errorf("%w: %q is not a local SAM user on %q", errLocalWindowsAccountNotFound, name, host)
	}
	canonical, resolvedDomain, resolvedKind, err := sid.LookupAccount("")
	if err != nil {
		return windowsLocalAccount{}, fmt.Errorf("resolve local account SID: %w", err)
	}
	if resolvedKind != windows.SidTypeUser || !strings.EqualFold(resolvedDomain, host) || !validLocalSAMName(canonical) {
		return windowsLocalAccount{}, fmt.Errorf("%w: SID for %q does not resolve to a local SAM user", errLocalWindowsAccountNotFound, name)
	}
	sidString := sid.String()
	if sidString == "" {
		return windowsLocalAccount{}, fmt.Errorf("cannot stringify local account SID")
	}
	return windowsLocalAccount{Name: canonical, SID: sidString}, nil
}

func validLocalSAMName(name string) bool {
	if name == "" || name == "." || name == ".." || name != strings.TrimSpace(name) || !utf8.ValidString(name) || strings.ContainsAny(name, `\/@"[]:;|=,+*?<>`) || strings.HasSuffix(name, ".") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// logon returns a primary token and a cleanup that unloads its profile and
// closes the token. Call cleanup exactly once, after every child process using
// the profile has exited. A failed profile load never returns a usable token.
func (account windowsLocalAccount) logon() (windows.Token, func(), error) {
	if !validLocalSAMName(account.Name) || account.SID == "" {
		return 0, nil, fmt.Errorf("invalid local Windows account")
	}
	expected, err := windows.StringToSid(account.SID)
	if err != nil || expected == nil || !expected.IsValid() {
		return 0, nil, fmt.Errorf("invalid local account SID %q: %v", account.SID, err)
	}
	current, err := lookupLocalWindowsAccount(account.Name)
	if err != nil {
		return 0, nil, err
	}
	if current.SID != expected.String() {
		return 0, nil, fmt.Errorf("local account %q changed SID since lookup", account.Name)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return 0, nil, fmt.Errorf("resolve LocalSystem SID: %w", err)
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || self == nil || self.User.Sid == nil || !self.User.Sid.Equals(system) {
		return 0, nil, fmt.Errorf("local S4U requires a LocalSystem process: %v", err)
	}

	impersonation, err := localS4UImpersonationToken(current.Name)
	if err != nil {
		return 0, nil, err
	}
	defer impersonation.Close()
	var primary windows.Token
	if err := windows.DuplicateTokenEx(impersonation, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return 0, nil, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	user, err := primary.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.Equals(expected) {
		primary.Close()
		return 0, nil, fmt.Errorf("S4U token SID differs from local account %q (lookup error: %v)", account.Name, err)
	}
	name, err := windows.UTF16PtrFromString(current.Name)
	if err != nil {
		primary.Close()
		return 0, nil, err
	}
	info := localS4UProfileInfo{Flags: 1, UserName: name} // PI_NOUI
	info.Size = uint32(unsafe.Sizeof(info))
	if ok, _, callErr := localS4ULoadProfile.Call(uintptr(primary), uintptr(unsafe.Pointer(&info))); ok == 0 {
		primary.Close()
		return 0, nil, fmt.Errorf("LoadUserProfileW for %q: %w", account.Name, localS4UCallError(callErr))
	}
	if info.Profile == 0 {
		primary.Close()
		return 0, nil, fmt.Errorf("LoadUserProfileW for %q returned no profile handle", account.Name)
	}
	return primary, func() {
		if ok, _, callErr := localS4UUnloadProfile.Call(uintptr(primary), uintptr(info.Profile)); ok == 0 {
			log.WithError(localS4UCallError(callErr)).With("user", account.Name).Warn("cannot unload local account profile")
		}
		if err := primary.Close(); err != nil {
			log.WithError(err).With("user", account.Name).Warn("cannot close local account token")
		}
	}, nil
}

type localS4UString struct {
	Length, MaximumLength uint16
	Buffer                *byte
}

type localS4UUnicodeString struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

type localS4UAuth struct {
	MessageType uint32
	Flags       uint32
	User        localS4UUnicodeString
	Domain      localS4UUnicodeString
}

type localS4UTokenSource struct {
	Name [8]byte
	ID   windows.LUID
}

type localS4UQuotaLimits struct {
	PagedPool, NonPagedPool, MinimumWorkingSet, MaximumWorkingSet, PageFile uintptr
	TimeLimit                                                               int64
}

type localS4UProfileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     windows.Handle
}

func localS4UImpersonationToken(name string) (result windows.Token, retErr error) {
	originBytes := []byte("BifS4U\x00")
	origin := localS4UString{uint16(len(originBytes) - 1), uint16(len(originBytes)), &originBytes[0]}
	var handle uintptr
	var mode uint64
	status, _, _ := localS4URegister.Call(uintptr(unsafe.Pointer(&origin)), uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(&mode)))
	runtime.KeepAlive(originBytes)
	if status != 0 {
		return 0, fmt.Errorf("LsaRegisterLogonProcess: NTSTATUS 0x%08x", uint32(status))
	}
	defer func() {
		if status, _, _ := localS4UDeregister.Call(handle); status != 0 {
			retErr = errors.Join(retErr, fmt.Errorf("LsaDeregisterLogonProcess: NTSTATUS 0x%08x", uint32(status)))
		}
		if retErr != nil && result != 0 {
			result.Close()
			result = 0
		}
	}()

	packageBytes := []byte("MICROSOFT_AUTHENTICATION_PACKAGE_V1_0\x00")
	packageName := localS4UString{uint16(len(packageBytes) - 1), uint16(len(packageBytes)), &packageBytes[0]}
	var packageID uint32
	status, _, _ = localS4ULookupPackage.Call(handle, uintptr(unsafe.Pointer(&packageName)), uintptr(unsafe.Pointer(&packageID)))
	runtime.KeepAlive(packageBytes)
	if status != 0 {
		return 0, fmt.Errorf("LsaLookupAuthenticationPackage: NTSTATUS 0x%08x", uint32(status))
	}

	user, err := windows.UTF16FromString(name)
	if err != nil {
		return 0, err
	}
	// UNICODE_STRING lengths, including the terminator, are 16-bit byte counts.
	if len(user)*2 > 65535 {
		return 0, fmt.Errorf("local account name exceeds S4U buffer limit")
	}
	domain := []uint16{'.', 0}
	base := int(unsafe.Sizeof(localS4UAuth{}))
	length := base + (len(user)+len(domain))*2
	buffer := make([]uint64, (length+7)/8)
	units := unsafe.Slice((*uint16)(unsafe.Pointer(&buffer[0])), len(buffer)*4)
	userUnits := units[base/2 : base/2+len(user)]
	domainUnits := units[base/2+len(user) : base/2+len(user)+len(domain)]
	copy(userUnits, user)
	copy(domainUnits, domain)
	auth := (*localS4UAuth)(unsafe.Pointer(&buffer[0]))
	auth.MessageType = 12 // MsV1_0S4ULogon
	auth.User = localS4UUnicodeString{uint16((len(user) - 1) * 2), uint16(len(user) * 2), &userUnits[0]}
	auth.Domain = localS4UUnicodeString{2, 4, &domainUnits[0]}

	source := localS4UTokenSource{}
	copy(source.Name[:], "BifS4U")
	if ok, _, callErr := localS4UAllocateLUID.Call(uintptr(unsafe.Pointer(&source.ID))); ok == 0 {
		return 0, fmt.Errorf("AllocateLocallyUniqueId: %w", localS4UCallError(callErr))
	}
	var profile uintptr
	var profileSize uint32
	var logonID windows.LUID
	var quota localS4UQuotaLimits
	var substatus uint32
	status, _, _ = localS4ULogon.Call(
		handle, uintptr(unsafe.Pointer(&origin)), 3, // Network
		uintptr(packageID), uintptr(unsafe.Pointer(&buffer[0])), uintptr(length), 0,
		uintptr(unsafe.Pointer(&source)), uintptr(unsafe.Pointer(&profile)),
		uintptr(unsafe.Pointer(&profileSize)), uintptr(unsafe.Pointer(&logonID)),
		uintptr(unsafe.Pointer(&result)), uintptr(unsafe.Pointer(&quota)), uintptr(unsafe.Pointer(&substatus)),
	)
	runtime.KeepAlive(originBytes)
	runtime.KeepAlive(buffer)
	if profile != 0 {
		if freeStatus, _, _ := localS4UFreeBuffer.Call(profile); freeStatus != 0 {
			retErr = fmt.Errorf("LsaFreeReturnBuffer: NTSTATUS 0x%08x", uint32(freeStatus))
		}
	}
	if status != 0 {
		retErr = errors.Join(retErr, fmt.Errorf("LsaLogonUser: NTSTATUS 0x%08x (substatus 0x%08x)", uint32(status), substatus))
	} else if result == 0 {
		retErr = errors.Join(retErr, fmt.Errorf("LsaLogonUser returned no token"))
	}
	return result, retErr
}

func localS4UCallError(err error) error {
	if err == nil || err == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return err
}
