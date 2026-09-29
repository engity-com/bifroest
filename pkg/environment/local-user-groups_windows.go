//go:build windows

package environment

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsLocalGroupRequirement struct {
	Name string
	SID  string
}

func (this windowsLocalGroupRequirement) GetField(name string) (any, bool, error) {
	switch name {
	case "name":
		return this.Name, true, nil
	case "gid":
		return this.SID, true, nil
	default:
		return nil, false, fmt.Errorf("unknown group field %q", name)
	}
}

const windowsBuiltinUsersSID = "S-1-5-32-545"

func validateWindowsLocalGroupRequirement(group windowsLocalGroupRequirement) (*windows.SID, error) {
	return validateWindowsLocalGroupIdentity(group, false)
}

func validateWindowsLocalGroupIdentity(group windowsLocalGroupRequirement, readOnly bool) (*windows.SID, error) {
	if group.Name == "" && group.SID == "" {
		return nil, fmt.Errorf("local group requires a name or SID")
	}
	if group.Name != "" {
		if !validLocalSAMGroupName(group.Name) || localSAMProtectedName(group.Name) {
			return nil, fmt.Errorf("invalid local group name %q", group.Name)
		}
		// Do not create a local namesake of a privileged BUILTIN alias when
		// the alias is not available by its English name on this host.
		if !readOnly {
			for _, reserved := range []string{"Administrators", "Power Users", "Account Operators", "Server Operators", "Print Operators", "Backup Operators", "Replicator"} {
				if strings.EqualFold(group.Name, reserved) {
					return nil, fmt.Errorf("privileged group name %q", group.Name)
				}
			}
		}
	}
	if group.SID == "" {
		return nil, nil
	}
	sid, err := windows.StringToSid(group.SID)
	if err != nil || sid == nil || !sid.IsValid() {
		return nil, fmt.Errorf("invalid local group SID %q: %v", group.SID, err)
	}
	if !readOnly && strings.HasPrefix(sid.String(), "S-1-5-32-") && sid.String() != windowsBuiltinUsersSID {
		return nil, fmt.Errorf("BUILTIN group %s cannot be required", sid)
	}
	return sid, nil
}

// lookupWindowsGroupIdentity validates the reverse and forward mappings, not
// just the spelling of a name supplied by configuration or NetAPI.
func lookupWindowsGroupIdentity(sid *windows.SID, host string) (windowsLocalGroupRequirement, error) {
	if sid == nil || !sid.IsValid() {
		return windowsLocalGroupRequirement{}, fmt.Errorf("invalid group SID")
	}
	name, domain, kind, err := sid.LookupAccount("")
	if err != nil {
		return windowsLocalGroupRequirement{}, err
	}
	if kind != windows.SidTypeAlias || !validLocalSAMGroupName(name) {
		return windowsLocalGroupRequirement{}, fmt.Errorf("SID %s is not a local group alias", sid)
	}
	if strings.HasPrefix(sid.String(), "S-1-5-32-") {
		if !strings.EqualFold(domain, "BUILTIN") {
			return windowsLocalGroupRequirement{}, fmt.Errorf("BUILTIN SID %s has unexpected domain %q", sid, domain)
		}
	} else if !strings.EqualFold(domain, host) {
		return windowsLocalGroupRequirement{}, fmt.Errorf("SID %s is not a local SAM group", sid)
	}
	forward, resolvedDomain, resolvedKind, err := windows.LookupSID("", domain+`\`+name)
	if err != nil {
		return windowsLocalGroupRequirement{}, err
	}
	if forward == nil || !forward.Equals(sid) || resolvedKind != windows.SidTypeAlias || !strings.EqualFold(resolvedDomain, domain) {
		return windowsLocalGroupRequirement{}, fmt.Errorf("group %q changed SID", name)
	}
	return windowsLocalGroupRequirement{Name: name, SID: sid.String()}, nil
}

func resolveWindowsLocalGroup(group windowsLocalGroupRequirement, host string, readOnly bool) (windowsLocalGroupRequirement, bool, error) {
	expected, err := validateWindowsLocalGroupIdentity(group, readOnly)
	if err != nil {
		return windowsLocalGroupRequirement{}, false, err
	}
	if group.Name == "" {
		resolved, err := lookupWindowsGroupIdentity(expected, host)
		if err != nil {
			return windowsLocalGroupRequirement{}, false, err
		}
		if _, err := validateWindowsLocalGroupIdentity(resolved, readOnly); err != nil {
			return windowsLocalGroupRequirement{}, false, err
		}
		// NetAPI takes an unqualified name when checking/adding membership.
		// A SID-only requirement must not bypass name ambiguity checks.
		byName, absent, err := resolveWindowsLocalGroup(resolved, host, readOnly)
		if err != nil || absent || byName.SID != resolved.SID {
			return windowsLocalGroupRequirement{}, false, fmt.Errorf("group SID %s has no unambiguous local name: %v", expected, err)
		}
		return byName, false, nil
	}
	var found *windows.SID
	for _, domain := range []string{host, "BUILTIN"} {
		sid, _, _, err := windows.LookupSID("", domain+`\`+group.Name)
		if errors.Is(err, windows.ERROR_NONE_MAPPED) {
			continue
		}
		if err != nil {
			return windowsLocalGroupRequirement{}, false, err
		}
		resolved, err := lookupWindowsGroupIdentity(sid, host)
		if err != nil {
			return windowsLocalGroupRequirement{}, false, err
		}
		if !strings.EqualFold(resolved.Name, group.Name) {
			return windowsLocalGroupRequirement{}, false, fmt.Errorf("group name %q resolves to %q", group.Name, resolved.Name)
		}
		if found != nil && !found.Equals(sid) {
			return windowsLocalGroupRequirement{}, false, fmt.Errorf("ambiguous local group name %q", group.Name)
		}
		found = sid
	}
	if found == nil {
		if expected != nil {
			return windowsLocalGroupRequirement{}, false, fmt.Errorf("group %q with SID %s not found", group.Name, expected)
		}
		return windowsLocalGroupRequirement{}, true, nil
	}
	if expected != nil && !expected.Equals(found) {
		return windowsLocalGroupRequirement{}, false, fmt.Errorf("group %q does not match SID %s", group.Name, expected)
	}
	resolved, err := lookupWindowsGroupIdentity(found, host)
	if err != nil {
		return windowsLocalGroupRequirement{}, false, err
	}
	if _, err := validateWindowsLocalGroupIdentity(resolved, readOnly); err != nil {
		return windowsLocalGroupRequirement{}, false, err
	}
	return resolved, false, nil
}

// ensureWindowsLocalUserGroups adds direct memberships only; it never changes
// the managed group used for account ownership and deletion.
func ensureWindowsLocalUserGroups(name, sid string, groups []windowsLocalGroupRequirement, allowSystemUsers bool) ([]windowsLocalGroupRequirement, error) {
	account, err := localSAMCurrent(name, sid, allowSystemUsers)
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	result := make([]windowsLocalGroupRequirement, len(groups))
	missing := make([]bool, len(groups))
	// Resolve all supplied identities before creating or changing any group.
	for i, group := range groups {
		result[i], missing[i], err = resolveWindowsLocalGroup(group, host, false)
		if err != nil {
			return nil, fmt.Errorf("resolve local group requirement %d: %w", i, err)
		}
	}
	for i, group := range groups {
		if missing[i] {
			if err := ensureLocalSAMGroup(group.Name); err != nil {
				return nil, err
			}
			result[i], missing[i], err = resolveWindowsLocalGroup(group, host, false)
			if err != nil || missing[i] {
				return nil, fmt.Errorf("resolve created local group %q: %v", group.Name, err)
			}
		}
		current, absent, err := resolveWindowsLocalGroup(result[i], host, false)
		if err != nil || absent || current.SID != result[i].SID {
			return nil, fmt.Errorf("local group %q changed identity: %v", result[i].Name, err)
		}
		member, err := windowsLocalGroupHasMember(current.Name, account.SID)
		if err != nil {
			return nil, err
		}
		if member {
			continue
		}
		if _, err := localSAMCurrent(name, sid, allowSystemUsers); err != nil {
			return nil, err
		}
		current, absent, err = resolveWindowsLocalGroup(result[i], host, false)
		if err != nil || absent || current.SID != result[i].SID {
			return nil, fmt.Errorf("local group %q changed identity: %v", result[i].Name, err)
		}
		parsed, _ := windows.StringToSid(account.SID)
		groupName, _ := windows.UTF16PtrFromString(current.Name)
		info := localSAMMemberInfo0{SID: parsed}
		err = localSAMCall("NetLocalGroupAddMembers", 0, uintptr(unsafe.Pointer(groupName)), 0, uintptr(unsafe.Pointer(&info)), 1)
		runtime.KeepAlive(groupName)
		runtime.KeepAlive(parsed)
		if err != nil {
			return nil, fmt.Errorf("add account to local group %q: %w", current.Name, err)
		}
	}
	return result, nil
}

func windowsLocalGroupHasMember(name, sid string) (bool, error) {
	group, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
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
			if freeErr := localSAMCall("NetApiBufferFree", uintptr(unsafe.Pointer(buffer))); freeErr != nil {
				return false, freeErr
			}
		}
		if err == nil {
			return matched, nil
		}
		if !errors.Is(err, syscall.Errno(localSAMMoreData)) || read == 0 {
			return false, err
		}
	}
}

// lookupWindowsLocalUserGroups returns direct local and BUILTIN aliases.
func lookupWindowsLocalUserGroups(name, sid string) ([]windowsLocalGroupRequirement, error) {
	account, err := localSAMCurrent(name, sid, true)
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	username, err := windows.UTF16PtrFromString(account.Name)
	if err != nil {
		return nil, err
	}
	var buffer *localSAMGroupInfo0
	var read, total uint32
	err = localSAMCall("NetUserGetLocalGroups", 0, uintptr(unsafe.Pointer(username)), 0, 0, uintptr(unsafe.Pointer(&buffer)), 0xffffffff, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	runtime.KeepAlive(username)
	var names []string
	if err == nil && read > 0 && buffer == nil {
		err = fmt.Errorf("NetUserGetLocalGroups returned no data")
	}
	if err == nil {
		for _, group := range unsafe.Slice(buffer, read) {
			if group.Name == nil {
				err = fmt.Errorf("NetUserGetLocalGroups returned an unnamed group")
				break
			}
			names = append(names, windows.UTF16PtrToString(group.Name))
		}
	}
	if buffer != nil {
		if freeErr := localSAMCall("NetApiBufferFree", uintptr(unsafe.Pointer(buffer))); freeErr != nil {
			return nil, freeErr
		}
	}
	if err != nil {
		return nil, err
	}
	result := make([]windowsLocalGroupRequirement, 0, len(names))
	for _, groupName := range names {
		resolved, absent, err := resolveWindowsLocalGroup(windowsLocalGroupRequirement{Name: groupName}, host, true)
		if err != nil || absent {
			return nil, fmt.Errorf("resolve direct local group: %v", err)
		}
		result = append(result, resolved)
	}
	return result, nil
}
