//go:build windows

// Package windowslocal provides read-only access to local Windows SAM users.
package windowslocal

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ErrNotFound = errors.New("local SAM account not found")

// Account identifies a local SAM user. Callers must retain both fields when
// passing an account to Disabled or ValidatePassword.
type Account struct {
	Name string
	SID  string
}

type group struct {
	Name string
	SID  string
}

func (g group) GetField(name string) (any, bool, error) {
	switch name {
	case "name":
		return g.Name, true, nil
	case "gid":
		return g.SID, true, nil
	default:
		return nil, false, fmt.Errorf("unknown group field %q", name)
	}
}

// GetField implements the template context for a local account. Group data
// includes direct local and BUILTIN aliases, not domain or nested membership.
func (a Account) GetField(name string) (any, bool, error) {
	switch name {
	case "name":
		return a.Name, true, nil
	case "uid":
		return a.SID, true, nil
	case "managed":
		return nil, true, nil
	case "shell":
		if shell := os.Getenv("COMSPEC"); shell != "" {
			return shell, true, nil
		}
		return `C:\WINDOWS\system32\cmd.exe`, true, nil
	case "displayName", "groups", "gids", "homeDir":
		current, err := currentAccount(a)
		if err != nil {
			return nil, false, err
		}
		switch name {
		case "displayName":
			value, err := userDisplayName(current.Name)
			if err == nil {
				_, err = currentAccount(a)
			}
			return value, err == nil, err
		case "groups", "gids":
			groups, err := userGroups(current.Name)
			if err != nil {
				return nil, false, err
			}
			if _, err := currentAccount(a); err != nil {
				return nil, false, err
			}
			if name == "groups" {
				return groups, true, nil
			}
			gids := make([]string, len(groups))
			for i, g := range groups {
				gids[i] = g.SID
			}
			return gids, true, nil
		default:
			value, err := profileDirectory(current)
			return value, err == nil, err
		}
	default:
		return nil, false, fmt.Errorf("unknown user field %q", name)
	}
}

func validName(name string) bool {
	if name == "" || name == "." || name == ".." || name != strings.TrimSpace(name) || !utf8.ValidString(name) ||
		strings.ContainsAny(name, `\/@"[]:;|=,+*?<>`) || strings.HasSuffix(name, ".") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func hostName() (string, error) {
	// GetComputerName reports the SAM domain name, not a DNS FQDN.
	var buf [256]uint16
	n := uint32(len(buf))
	if err := windows.GetComputerName(&buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// Lookup resolves a bare name against this machine's SAM only.
func Lookup(name string) (Account, error) {
	if !validName(name) {
		return Account{}, fmt.Errorf("%w: invalid local SAM name %q", ErrNotFound, name)
	}
	host, err := hostName()
	if err != nil {
		return Account{}, err
	}
	sid, domain, kind, err := windows.LookupSID("", host+`\`+name)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return Account{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	if err != nil {
		return Account{}, fmt.Errorf("lookup local SAM user: %w", err)
	}
	if sid == nil || !sid.IsValid() || kind != windows.SidTypeUser || !strings.EqualFold(domain, host) {
		return Account{}, fmt.Errorf("%w: %q is not a local SAM user", ErrNotFound, name)
	}
	canonical, resolvedDomain, resolvedKind, err := sid.LookupAccount("")
	if err != nil {
		return Account{}, fmt.Errorf("reverse lookup local SAM user: %w", err)
	}
	if !validName(canonical) || resolvedKind != windows.SidTypeUser || !strings.EqualFold(resolvedDomain, host) || !strings.EqualFold(canonical, name) {
		return Account{}, fmt.Errorf("%w: local SAM name has no canonical user mapping", ErrNotFound)
	}
	return Account{Name: canonical, SID: sid.String()}, nil
}

// LookupBySID accepts only a SID that resolves back to the local SAM user.
func LookupBySID(value string) (Account, error) {
	sid, err := windows.StringToSid(value)
	if err != nil || sid == nil || !sid.IsValid() {
		return Account{}, fmt.Errorf("%w: invalid account SID", ErrNotFound)
	}
	name, domain, kind, err := sid.LookupAccount("")
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return Account{}, fmt.Errorf("%w: SID %s", ErrNotFound, sid)
	}
	if err != nil {
		return Account{}, err
	}
	host, err := hostName()
	if err != nil {
		return Account{}, err
	}
	if kind != windows.SidTypeUser || !strings.EqualFold(domain, host) || !validName(name) {
		return Account{}, fmt.Errorf("%w: SID is not a local SAM user", ErrNotFound)
	}
	account, err := Lookup(name)
	if err != nil {
		return Account{}, err
	}
	if !sameSID(account.SID, sid) {
		return Account{}, fmt.Errorf("%w: local SAM SID changed", ErrNotFound)
	}
	return account, nil
}

func sameSID(value string, expected *windows.SID) bool {
	if value == "" || expected == nil || !expected.IsValid() {
		return false
	}
	sid, err := windows.StringToSid(value)
	return err == nil && sid != nil && sid.IsValid() && sid.Equals(expected)
}

func currentAccount(a Account) (Account, error) {
	if !validName(a.Name) || a.SID == "" {
		return Account{}, fmt.Errorf("missing or invalid local SAM identity")
	}
	sid, err := windows.StringToSid(a.SID)
	if err != nil || sid == nil || !sid.IsValid() {
		return Account{}, fmt.Errorf("invalid local SAM SID")
	}
	current, err := Lookup(a.Name)
	if err != nil {
		return Account{}, err
	}
	if !sameSID(current.SID, sid) {
		return Account{}, fmt.Errorf("%w: local SAM user changed SID", ErrNotFound)
	}
	return current, nil
}

type userInfo1 struct {
	Name, Password    *uint16
	PasswordAge, Priv uint32
	HomeDir, Comment  *uint16
	Flags             uint32
	ScriptPath        *uint16
}

type userInfo2 struct {
	userInfo1
	AuthFlags                                       uint32
	FullName, UserComment, Parameters, Workstations *uint16
	LastLogon, LastLogoff, AccountExpires           uint32
	MaxStorage, UnitsPerWeek                        uint32
	LogonHours                                      *byte
	BadPasswordCount, LogonCount                    uint32
	LogonServer                                     *uint16
	CountryCode, CodePage                           uint32
}

type userInfo10 struct {
	Name, Comment, UserComment, FullName *uint16
}

type groupInfo0 struct{ Name *uint16 }

// Nano Server exports these functions from samcli/netutils rather than netapi32.
func netProc(name string) (*windows.LazyProc, error) {
	dlls := []string{"netapi32.dll", "samcli.dll"}
	if name == "NetApiBufferFree" {
		dlls = []string{"netapi32.dll", "netutils.dll"}
	}
	var errs []error
	for _, dll := range dlls {
		proc := windows.NewLazySystemDLL(dll).NewProc(name)
		if err := proc.Find(); err == nil {
			return proc, nil
		} else {
			errs = append(errs, fmt.Errorf("%s!%s: %w", dll, name, err))
		}
	}
	return nil, errors.Join(errs...)
}

func netCall(name string, args ...uintptr) error {
	proc, err := netProc(name)
	if err != nil {
		return err
	}
	if code, _, _ := proc.Call(args...); code != 0 {
		return fmt.Errorf("%s: %w", name, syscall.Errno(uint32(code)))
	}
	return nil
}

// Unavailable rejects disabled, locked, and expired local SAM accounts.
func Unavailable(a Account) (bool, error) {
	current, err := currentAccount(a)
	if err != nil {
		return false, err
	}
	name, _ := windows.UTF16PtrFromString(current.Name)
	var info *userInfo2
	err = netCall("NetUserGetInfo", 0, uintptr(unsafe.Pointer(name)), 2, uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(name)
	if info != nil {
		if err == nil {
			unavailable := accountUnavailable(info.Flags, info.AccountExpires, time.Now())
			err = netCall("NetApiBufferFree", uintptr(unsafe.Pointer(info)))
			if err != nil {
				return false, err
			}
			if _, err = currentAccount(a); err != nil {
				return false, err
			}
			return unavailable, nil
		}
		err = errors.Join(err, netCall("NetApiBufferFree", uintptr(unsafe.Pointer(info))))
	}
	if err == nil {
		err = errors.New("NetUserGetInfo returned no data")
	}
	return false, err
}

func accountUnavailable(flags, expires uint32, now time.Time) bool {
	const (
		accountDisabled = 0x2  // UF_ACCOUNTDISABLE
		accountLocked   = 0x10 // UF_LOCKOUT
	)
	return flags&(accountDisabled|accountLocked) != 0 || (expires != ^uint32(0) && int64(expires) <= now.Unix())
}

func userDisplayName(name string) (string, error) {
	username, _ := windows.UTF16PtrFromString(name)
	var info *userInfo10
	err := netCall("NetUserGetInfo", 0, uintptr(unsafe.Pointer(username)), 10, uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(username)
	var result string
	if info != nil {
		if err == nil && info.FullName != nil {
			result = windows.UTF16PtrToString(info.FullName)
		}
		err = errors.Join(err, netCall("NetApiBufferFree", uintptr(unsafe.Pointer(info))))
	} else if err == nil {
		err = errors.New("NetUserGetInfo returned no data")
	}
	return result, err
}

func userGroups(name string) ([]group, error) {
	username, _ := windows.UTF16PtrFromString(name)
	var info *groupInfo0
	var read, total uint32
	err := netCall("NetUserGetLocalGroups", 0, uintptr(unsafe.Pointer(username)), 0, 0, uintptr(unsafe.Pointer(&info)), 0xffffffff, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	runtime.KeepAlive(username)
	var names []string
	if err == nil && read > 0 && info == nil {
		err = errors.New("NetUserGetLocalGroups returned no data")
	}
	if err == nil {
		for _, g := range unsafe.Slice(info, read) {
			if g.Name == nil {
				err = errors.New("NetUserGetLocalGroups returned unnamed group")
				break
			}
			names = append(names, windows.UTF16PtrToString(g.Name))
		}
	}
	if info != nil {
		err = errors.Join(err, netCall("NetApiBufferFree", uintptr(unsafe.Pointer(info))))
	}
	if err != nil {
		return nil, err
	}
	host, err := hostName()
	if err != nil {
		return nil, err
	}
	groups := make([]group, 0, len(names))
	for _, name := range names {
		if !validName(name) {
			return nil, fmt.Errorf("invalid local group name %q", name)
		}
		var found *windows.SID
		var canonical string
		for _, domain := range []string{host, "BUILTIN"} {
			sid, resolvedDomain, kind, err := windows.LookupSID("", domain+`\`+name)
			if errors.Is(err, windows.ERROR_NONE_MAPPED) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if sid == nil || !sid.IsValid() || kind != windows.SidTypeAlias || !strings.EqualFold(resolvedDomain, domain) {
				return nil, fmt.Errorf("group %q is not a local alias", name)
			}
			reverseName, reverseDomain, reverseKind, err := sid.LookupAccount("")
			if err != nil || reverseKind != windows.SidTypeAlias || !strings.EqualFold(reverseDomain, domain) || !strings.EqualFold(reverseName, name) || !validName(reverseName) {
				return nil, fmt.Errorf("group %q has no canonical local alias: %v", name, err)
			}
			if found != nil && !found.Equals(sid) {
				return nil, fmt.Errorf("ambiguous local group %q", name)
			}
			found, canonical = sid, reverseName
		}
		if found == nil {
			return nil, fmt.Errorf("local group %q disappeared", name)
		}
		groups = append(groups, group{canonical, found.String()})
	}
	return groups, nil
}
