//go:build windows

package environment

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	localSAMGroupNotFound           = 2220 // NERR_GroupNotFound
	localSAMGroupExists             = 2223 // NERR_GroupExists
	localSAMMoreData                = 234  // ERROR_MORE_DATA
	localSAMUFAccountDisable uint32 = 0x2  // UF_ACCOUNTDISABLE
)

type localSAMUserInfo1 struct {
	Name, Password    *uint16
	PasswordAge, Priv uint32
	HomeDir, Comment  *uint16
	Flags             uint32
	ScriptPath        *uint16
}

type localSAMUserInfo10 struct {
	Name, Comment, UserComment, FullName *uint16
}

type localSAMUserInfo1008 struct{ Flags uint32 }
type localSAMUserInfo1011 struct{ FullName *uint16 }
type localSAMGroupInfo0 struct{ Name *uint16 }
type localSAMMemberInfo0 struct{ SID *windows.SID }

// localSAMProc only falls back when an export is unavailable, never after a
// failed API call. NewLazySystemDLL loads both DLLs from System32.
func localSAMProc(name string) (*windows.LazyProc, error) {
	var errs []error
	dlls := []string{"netapi32.dll", "samcli.dll"}
	if name == "NetApiBufferFree" {
		dlls = []string{"netapi32.dll", "netutils.dll"}
	}
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

func localSAMCall(name string, args ...uintptr) error {
	proc, err := localSAMProc(name)
	if err != nil {
		return err
	}
	status, _, _ := proc.Call(args...)
	if status != 0 {
		return fmt.Errorf("%s: %w", name, syscall.Errno(uint32(status)))
	}
	return nil
}

func localSAMProtectedName(name string) bool {
	switch strings.ToLower(name) {
	case "administrator", "guest", "defaultaccount", "wdagutilityaccount", "krbtgt",
		"system", "localsystem", "localservice", "networkservice", "containeradministrator", "containeruser":
		return true
	}
	return false
}

func localSAMProtectedAccount(account windowsLocalAccount) bool {
	if localSAMProtectedName(account.Name) {
		return true
	}
	switch account.SID {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-93-2-1", "S-1-5-93-2-2":
		return true
	}
	for _, rid := range []string{"-500", "-501", "-503", "-504"} {
		if strings.HasSuffix(account.SID, rid) {
			return true
		}
	}
	return false
}

func localSAMCurrent(name, sid string, allowSystemUsers ...bool) (windowsLocalAccount, error) {
	if !validLocalSAMName(name) || sid == "" {
		return windowsLocalAccount{}, fmt.Errorf("invalid local SAM identity")
	}
	expected, err := windows.StringToSid(sid)
	if err != nil || expected == nil || !expected.IsValid() {
		return windowsLocalAccount{}, fmt.Errorf("invalid local SAM SID: %v", err)
	}
	account, err := lookupLocalWindowsAccount(name)
	if err != nil {
		return windowsLocalAccount{}, err
	}
	if account.SID != expected.String() {
		return windowsLocalAccount{}, fmt.Errorf("local SAM account %q changed SID", name)
	}
	if localSAMProtectedAccount(account) && (len(allowSystemUsers) == 0 || !allowSystemUsers[0]) {
		return windowsLocalAccount{}, fmt.Errorf("protected local SAM account %q", name)
	}
	return account, nil
}

func localSAMGroupName(group string) error {
	if !validLocalSAMGroupName(group) || localSAMProtectedName(group) {
		return fmt.Errorf("invalid managed local group %q", group)
	}
	return nil
}

func validLocalSAMGroupName(name string) bool {
	if name == "" || name == "." || name == ".." || name != strings.TrimSpace(name) ||
		!utf8.ValidString(name) || strings.ContainsAny(name, `\/"[]:;|=,+*?<>`) || strings.HasSuffix(name, ".") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func localSAMGroupIdentity(group string) error {
	_, err := localSAMGroupSID(group)
	return err
}

func localSAMGroupSID(group string) (string, error) {
	if err := localSAMGroupName(group); err != nil {
		return "", err
	}
	host, err := os.Hostname()
	if err != nil {
		return "", err
	}
	sid, domain, kind, err := windows.LookupSID("", host+`\`+group)
	if err != nil {
		return "", fmt.Errorf("resolve managed group %q: %w", group, err)
	}
	if sid == nil || !sid.IsValid() || kind != windows.SidTypeAlias || !strings.EqualFold(domain, host) || strings.HasPrefix(sid.String(), "S-1-5-32-") {
		return "", fmt.Errorf("managed group %q is not a local non-BUILTIN alias", group)
	}
	return sid.String(), nil
}

func localSAMAccountDisabled(flags uint32) bool {
	return flags&localSAMUFAccountDisable != 0
}

func localSAMDisableFlags(account windowsLocalAccount, member bool, flags uint32) (uint32, error) {
	if localSAMProtectedAccount(account) {
		return 0, fmt.Errorf("protected local SAM account %q", account.Name)
	}
	if !member {
		return 0, fmt.Errorf("local SAM account %q is not a member of the managed group", account.Name)
	}
	return flags | localSAMUFAccountDisable, nil
}

func localSAMUserFlags(name string) (uint32, error) {
	username, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var buffer *localSAMUserInfo1
	err = localSAMCall("NetUserGetInfo", 0, uintptr(unsafe.Pointer(username)), 1, uintptr(unsafe.Pointer(&buffer)))
	runtime.KeepAlive(username)
	var flags uint32
	if buffer != nil {
		if err == nil {
			flags = buffer.Flags
		}
		err = errors.Join(err, localSAMCall("NetApiBufferFree", uintptr(unsafe.Pointer(buffer))))
	}
	if err != nil {
		return 0, err
	}
	if buffer == nil {
		return 0, fmt.Errorf("NetUserGetInfo returned no data")
	}
	return flags, nil
}

func localWindowsAccountDisabled(name, sid string) (bool, error) {
	account, err := localSAMCurrent(name, sid)
	if err != nil {
		return false, err
	}
	flags, err := localSAMUserFlags(account.Name)
	if err != nil {
		return false, err
	}
	if _, err := localSAMCurrent(name, sid); err != nil {
		return false, err
	}
	return localSAMAccountDisabled(flags), nil
}

// Only call this with a SID observed immediately after creating the account.
// Group setup might have failed, so disabling cannot require membership.
func setNewLocalWindowsAccountDisabled(name, sid, managedGroup string, disabled bool) error {
	account, err := localSAMCurrent(name, sid)
	if err != nil {
		return err
	}
	if !disabled {
		member, err := IsLocalWindowsAccountInGroup(account.Name, account.SID, managedGroup)
		if err != nil {
			return err
		}
		if !member {
			return fmt.Errorf("local SAM account %q is not in managed group %q", name, managedGroup)
		}
	}
	flags, err := localSAMUserFlags(account.Name)
	if err != nil {
		return err
	}
	account, err = localSAMCurrent(name, sid)
	if err != nil {
		return err
	}
	if disabled {
		flags, err = localSAMDisableFlags(account, true, flags)
		if err != nil {
			return err
		}
	} else {
		member, err := IsLocalWindowsAccountInGroup(account.Name, account.SID, managedGroup)
		if err != nil {
			return err
		}
		if !member {
			return fmt.Errorf("local SAM account %q is not in managed group %q", name, managedGroup)
		}
		flags &^= localSAMUFAccountDisable
	}
	username, err := windows.UTF16PtrFromString(account.Name)
	if err != nil {
		return err
	}
	info := localSAMUserInfo1008{Flags: flags}
	var invalid uint32
	err = localSAMCall("NetUserSetInfo", 0, uintptr(unsafe.Pointer(username)), 1008, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&invalid)))
	runtime.KeepAlive(username)
	if err != nil {
		return fmt.Errorf("set disabled state of local SAM user %q (parameter %d): %w", name, invalid, err)
	}
	return nil
}

func disableNewLocalWindowsAccount(name, sid string) error {
	return setNewLocalWindowsAccountDisabled(name, sid, "", true)
}

func localSAMDisplayName(name string) (string, error) {
	username, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var buffer *localSAMUserInfo10
	err = localSAMCall("NetUserGetInfo", 0, uintptr(unsafe.Pointer(username)), 10, uintptr(unsafe.Pointer(&buffer)))
	runtime.KeepAlive(username)
	if err != nil {
		return "", err
	}
	if buffer == nil {
		return "", fmt.Errorf("NetUserGetInfo returned no data")
	}
	var result string
	if name := buffer.FullName; name != nil {
		result = windows.UTF16PtrToString(name)
	}
	return result, localSAMCall("NetApiBufferFree", uintptr(unsafe.Pointer(buffer)))
}

// ensureLocalSAMGroup creates a missing local group, and rejects BUILTIN aliases
// such as Administrators even when their name is localized.
func ensureLocalSAMGroup(group string) error {
	if err := localSAMGroupName(group); err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(group)
	var info uintptr
	err := localSAMCall("NetLocalGroupGetInfo", 0, uintptr(unsafe.Pointer(name)), 1, uintptr(unsafe.Pointer(&info)))
	if info != 0 {
		freeErr := localSAMCall("NetApiBufferFree", info)
		if freeErr != nil {
			return freeErr
		}
	}
	if errors.Is(err, syscall.Errno(localSAMGroupNotFound)) {
		groupInfo := localSAMGroupInfo0{Name: name}
		var invalid uint32
		err = localSAMCall("NetLocalGroupAdd", 0, 0, uintptr(unsafe.Pointer(&groupInfo)), uintptr(unsafe.Pointer(&invalid)))
		if errors.Is(err, syscall.Errno(localSAMGroupExists)) {
			err = nil
		}
	}
	runtime.KeepAlive(name)
	if err != nil {
		return fmt.Errorf("ensure local group %q: %w", group, err)
	}
	return localSAMGroupIdentity(group)
}

// CreateLocalWindowsAccount creates a local user with a random, never returned
// password. It remains disabled until group and display-name setup succeed.
// Failures after observing the new SID return it for verified cleanup.
func CreateLocalWindowsAccount(name, displayName, managedGroup string) (string, error) {
	if !validLocalSAMName(name) || localSAMProtectedName(name) {
		return "", fmt.Errorf("invalid or protected local SAM account name %q", name)
	}
	if err := ensureLocalSAMGroup(managedGroup); err != nil {
		return "", err
	}
	if _, err := lookupLocalWindowsAccount(name); err == nil {
		return "", fmt.Errorf("local SAM account %q already exists", name)
	} else if !errors.Is(err, errLocalWindowsAccountNotFound) {
		return "", err
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", fmt.Errorf("generate local account password: %w", err)
	}
	encoded := make([]byte, hex.EncodedLen(len(secret)))
	hex.Encode(encoded, secret[:])
	password := make([]uint16, 0, 3+len(encoded)+3+1)
	for _, b := range []byte("Bf!") {
		password = append(password, uint16(b))
	}
	for _, b := range encoded {
		password = append(password, uint16(b))
	}
	for _, b := range []byte("aA1") {
		password = append(password, uint16(b))
	}
	password = append(password, 0)
	username, _ := windows.UTF16PtrFromString(name)
	// Never include the password or its buffer in diagnostics.
	info := localSAMUserInfo1{Name: username, Password: &password[0], Priv: 1, Flags: 0x201 | localSAMUFAccountDisable} // USER_PRIV_USER; UF_SCRIPT | UF_NORMAL_ACCOUNT
	var invalid uint32
	err := localSAMCall("NetUserAdd", 0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&invalid)))
	runtime.KeepAlive(username)
	runtime.KeepAlive(password)
	clear(password)
	clear(encoded)
	clear(secret[:])
	if err != nil {
		return "", fmt.Errorf("create local SAM user %q (parameter %d): %w", name, invalid, err)
	}
	account, err := lookupLocalWindowsAccount(name)
	if err != nil {
		return "", fmt.Errorf("resolve newly created local user %q: %w", name, err)
	}
	if localSAMProtectedAccount(account) {
		return "", fmt.Errorf("created user %q resolves to a protected SID", name)
	}
	if err := EnsureLocalWindowsAccountGroup(account.Name, account.SID, managedGroup); err != nil {
		return account.SID, err
	}
	if err := UpdateLocalWindowsAccountDisplayName(account.Name, account.SID, displayName, true); err != nil {
		return account.SID, err
	}
	if err := setNewLocalWindowsAccountDisabled(account.Name, account.SID, managedGroup, false); err != nil {
		return account.SID, err
	}
	return account.SID, nil
}

// UpdateLocalWindowsAccountDisplayName does nothing unless requested; an empty
// requested name is an intentional update.
func UpdateLocalWindowsAccountDisplayName(name, sid, displayName string, requested bool, allowSystemUsers ...bool) error {
	if _, err := localSAMCurrent(name, sid, allowSystemUsers...); err != nil {
		return err
	}
	if !requested {
		return nil
	}
	username, _ := windows.UTF16PtrFromString(name)
	var buffer *localSAMUserInfo10
	err := localSAMCall("NetUserGetInfo", 0, uintptr(unsafe.Pointer(username)), 10, uintptr(unsafe.Pointer(&buffer)))
	runtime.KeepAlive(username)
	if err != nil {
		return err
	}
	if buffer == nil {
		return fmt.Errorf("NetUserGetInfo returned no data")
	}
	var current string
	if fullName := buffer.FullName; fullName != nil {
		current = windows.UTF16PtrToString(fullName)
	}
	freeErr := localSAMCall("NetApiBufferFree", uintptr(unsafe.Pointer(buffer)))
	if freeErr != nil {
		return freeErr
	}
	if current == displayName {
		return nil
	}
	fullName, err := windows.UTF16PtrFromString(displayName)
	if err != nil {
		return err
	}
	if _, err := localSAMCurrent(name, sid, allowSystemUsers...); err != nil {
		return err
	}
	info := localSAMUserInfo1011{FullName: fullName}
	var invalid uint32
	err = localSAMCall("NetUserSetInfo", 0, uintptr(unsafe.Pointer(username)), 1011, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&invalid)))
	runtime.KeepAlive(username)
	runtime.KeepAlive(fullName)
	if err != nil {
		return fmt.Errorf("set display name (parameter %d): %w", invalid, err)
	}
	return nil
}

// IsLocalWindowsAccountInGroup checks direct membership by SID, not account name.
// It returns an error for an absent group rather than mistaking it for unmanaged.
func IsLocalWindowsAccountInGroup(name, sid, managedGroup string, allowSystemUsers ...bool) (bool, error) {
	if _, err := localSAMCurrent(name, sid, allowSystemUsers...); err != nil {
		return false, err
	}
	if err := localSAMGroupName(managedGroup); err != nil {
		return false, err
	}
	if err := localSAMGroupIdentity(managedGroup); err != nil {
		return false, err
	}
	group, _ := windows.UTF16PtrFromString(managedGroup)
	defer runtime.KeepAlive(group)
	var resume uintptr
	matched := false
	for {
		var buffer *localSAMMemberInfo0
		var read, total uint32
		err := localSAMCall("NetLocalGroupGetMembers", 0, uintptr(unsafe.Pointer(group)), 0, uintptr(unsafe.Pointer(&buffer)), 0xffffffff, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
		if buffer != nil {
			for _, member := range unsafe.Slice(buffer, read) {
				if member.SID != nil && member.SID.IsValid() && member.SID.String() == sid {
					matched = true
				}
			}
			freeErr := localSAMCall("NetApiBufferFree", uintptr(unsafe.Pointer(buffer)))
			if freeErr != nil {
				return false, freeErr
			}
		}
		if err != nil && !errors.Is(err, syscall.Errno(localSAMMoreData)) {
			return false, err
		}
		if err == nil {
			return matched, nil
		}
		if read == 0 {
			return false, fmt.Errorf("NetLocalGroupGetMembers made no progress")
		}
	}
}

// EnsureLocalWindowsAccountGroup creates the group if missing and adds the
// verified user's SID only when not already a direct member.
func EnsureLocalWindowsAccountGroup(name, sid, managedGroup string, allowSystemUsers ...bool) error {
	_, _, err := ensureLocalWindowsAccountGroup(name, sid, managedGroup, allowSystemUsers...)
	return err
}

func ensureLocalWindowsAccountGroup(name, sid, managedGroup string, allowSystemUsers ...bool) (bool, string, error) {
	if _, err := localSAMCurrent(name, sid, allowSystemUsers...); err != nil {
		return false, "", err
	}
	if err := ensureLocalSAMGroup(managedGroup); err != nil {
		return false, "", err
	}
	groupSID, err := localSAMGroupSID(managedGroup)
	if err != nil {
		return false, "", err
	}
	member, err := IsLocalWindowsAccountInGroup(name, sid, managedGroup, allowSystemUsers...)
	if err != nil || member {
		return false, "", err
	}
	if _, err := localSAMCurrent(name, sid, allowSystemUsers...); err != nil {
		return false, "", err
	}
	parsed, _ := windows.StringToSid(sid)
	group, _ := windows.UTF16PtrFromString(managedGroup)
	info := localSAMMemberInfo0{SID: parsed}
	err = localSAMCall("NetLocalGroupAddMembers", 0, uintptr(unsafe.Pointer(group)), 0, uintptr(unsafe.Pointer(&info)), 1)
	runtime.KeepAlive(group)
	runtime.KeepAlive(parsed)
	if err != nil {
		return false, "", err
	}
	return true, groupSID, nil
}

func removeLocalWindowsAccountGroup(name, sid, groupName, expectedGroupSID string, allowSystemUsers bool) error {
	if _, err := localSAMCurrent(name, sid, allowSystemUsers); err != nil {
		return err
	}
	groupSID, err := localSAMGroupSID(groupName)
	if err != nil {
		return err
	}
	if groupSID != expectedGroupSID {
		return fmt.Errorf("managed group %q changed SID", groupName)
	}
	if _, err := localSAMCurrent(name, sid, allowSystemUsers); err != nil {
		return err
	}
	parsed, _ := windows.StringToSid(sid)
	group, _ := windows.UTF16PtrFromString(groupName)
	info := localSAMMemberInfo0{SID: parsed}
	err = localSAMCall("NetLocalGroupDelMembers", 0, uintptr(unsafe.Pointer(group)), 0, uintptr(unsafe.Pointer(&info)), 1)
	runtime.KeepAlive(group)
	runtime.KeepAlive(parsed)
	return err
}

// DeleteLocalWindowsAccount verifies the account SID immediately before deletion.
// Profile removal is deliberately separate and is not performed here.
func DeleteLocalWindowsAccount(name, sid string, allowSystemUsers ...bool) error {
	account, err := localSAMCurrent(name, sid, allowSystemUsers...)
	if err != nil {
		return err
	}
	if _, err := localSAMCurrent(name, sid, allowSystemUsers...); err != nil {
		return err
	}
	username, _ := windows.UTF16PtrFromString(account.Name)
	err = localSAMCall("NetUserDel", 0, uintptr(unsafe.Pointer(username)))
	runtime.KeepAlive(username)
	return err
}
