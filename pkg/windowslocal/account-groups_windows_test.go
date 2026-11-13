//go:build windows

package windowslocal

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLocalSAMFreshGroupMembership(t *testing.T) {
	requireSAMPolicyContainer(t)
	account, _ := newSAMPolicyAccount(t)
	before, err := inspectSAMGroups(t.Context(), account)
	require.NoError(t, err)
	groupName := "bifv" + strings.TrimPrefix(account.Name, "bifp")
	name, err := windows.UTF16PtrFromString(groupName)
	require.NoError(t, err)
	host, err := hostName()
	require.NoError(t, err)
	var groupSID string
	owned := func() error {
		requireSAMPolicyContainer(t)
		if groupSID == "" {
			return fmt.Errorf("owned alias created but SID binding unavailable; refuse name-only cleanup and retain for container teardown")
		}
		if _, err := currentAccount(account); err != nil {
			return err
		}
		current, _, _, err := windows.LookupSID("", host+`\`+groupName)
		if err != nil {
			return err
		}
		if !sameSID(groupSID, current) {
			return fmt.Errorf("owned fresh-group fixture changed SID")
		}
		return nil
	}
	info := struct{ Name *uint16 }{name}
	var parameter uint32
	require.NoError(t, netCall("NetLocalGroupAdd", 0, 0, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter))))
	// Establish cleanup responsibility immediately after successful creation,
	// before any identity lookup or assertion can stop this fixture.
	t.Cleanup(func() {
		if err := owned(); err != nil {
			t.Errorf("owned fresh-group cleanup identity: %v", err)
			return
		}
		err := netCall("NetLocalGroupDel", 0, uintptr(unsafe.Pointer(name)))
		runtime.KeepAlive(name)
		if err != nil {
			t.Errorf("remove owned fresh-group fixture: %v", err)
		}
	})
	runtime.KeepAlive(name)
	sid, domain, kind, err := windows.LookupSID("", host+`\`+groupName)
	require.NoError(t, err)
	require.NotNil(t, sid)
	require.EqualValues(t, windows.SidTypeAlias, kind)
	require.True(t, strings.EqualFold(domain, host))
	groupSID = sid.String()
	member, err := windows.StringToSid(account.SID)
	require.NoError(t, err)
	membership := struct{ SID *windows.SID }{member}
	require.NoError(t, owned())
	require.NoError(t, netCall("NetLocalGroupAddMembers", 0, uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&membership)), 1))
	runtime.KeepAlive(name)
	runtime.KeepAlive(member)
	added, err := inspectSAMGroups(t.Context(), account)
	require.NoError(t, err)
	require.False(t, sameSAMGroups(before, added))
	require.Len(t, added, len(before)+1)
	matched := false
	for _, value := range added {
		if value.SID == groupSID {
			require.True(t, strings.EqualFold(value.Name, groupName))
			matched = true
		}
	}
	require.True(t, matched, "fresh groups must include exactly the owned alias SID without a reference login")
	require.NoError(t, owned())
	require.NoError(t, netCall("NetLocalGroupDelMembers", 0, uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&membership)), 1))
	runtime.KeepAlive(name)
	runtime.KeepAlive(member)
	removed, err := inspectSAMGroups(t.Context(), account)
	require.NoError(t, err)
	require.True(t, sameSAMGroups(before, removed), "second fresh read must reject reuse of earlier group membership")
	t.Log("FRESH_SAM_GROUPS same account SID, own alias add/remove observed before any reference login; request-local comparison only, no resume eligibility")
}
