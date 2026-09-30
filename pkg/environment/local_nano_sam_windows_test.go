//go:build windows && nanoserver_integration

package environment

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLocalNanoServerSAMLifecycle(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_NANO_SAM_IN_CONTAINER") != "1" {
		t.Skip("only run inside the pinned Nano Server container")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve container process SID: %v", err)
	}
	if got := user.User.Sid.String(); got != "S-1-5-93-2-1" {
		t.Fatalf("local SAM lifecycle requires ContainerAdministrator (S-1-5-93-2-1), got %s", got)
	}

	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("generate isolated SAM names: %v", err)
	}
	suffix := hex.EncodeToString(nonce[:])
	name, group := "bsu"+suffix, "bsg"+suffix
	extraGroup := "bng" + suffix
	const initialDisplay = "Nano SAM lifecycle initial"
	const updatedDisplay = "Nano SAM lifecycle updated"
	sid, err := CreateLocalWindowsAccount(name, initialDisplay, group)
	if err != nil {
		t.Fatalf("create Nano Server local account: %v", err)
	}
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			if err := DeleteLocalWindowsAccount(name, sid); err != nil {
				t.Logf("best-effort cleanup of Nano Server local account %q: %v", name, err)
			}
		}
	})
	if sid == "" {
		t.Fatal("new local account has no SID")
	}
	disabled, err := localWindowsAccountDisabled(name, sid)
	if err != nil || disabled {
		t.Fatalf("newly created account must be enabled: disabled=%t, err=%v", disabled, err)
	}
	account, err := lookupLocalWindowsAccount(name)
	if err != nil {
		t.Fatalf("look up created local account: %v", err)
	}
	if account.Name != name || account.SID != sid {
		t.Fatalf("created local account identity mismatch: got %+v, want name %q SID %q", account, name, sid)
	}
	member, err := IsLocalWindowsAccountInGroup(name, sid, group)
	if err != nil || !member {
		t.Fatalf("created account lacks direct managed-group membership: member=%t, err=%v", member, err)
	}
	if _, _, err := ensureWindowsLocalUserGroups(name, sid, []windowsLocalGroupRequirement{{Name: extraGroup}}, false); err != nil {
		t.Fatalf("enroll in additional local group: %v", err)
	}
	extraSID, err := localSAMGroupSID(extraGroup)
	if err != nil {
		t.Fatalf("resolve additional group SID: %v", err)
	}
	if _, _, err := ensureWindowsLocalUserGroups(name, sid, []windowsLocalGroupRequirement{{SID: extraSID}}, false); err != nil {
		t.Fatalf("resolve and confirm additional group by SID: %v", err)
	}
	listed, err := lookupWindowsLocalUserGroups(name, sid)
	if err != nil {
		t.Fatalf("enumerate account's local groups: %v", err)
	}
	found := false
	for _, candidate := range listed {
		found = found || candidate.SID == extraSID
	}
	if !found {
		t.Fatalf("additional local group %s not present in candidate groups: %v", extraSID, listed)
	}
	display, err := localSAMDisplayName(name)
	if err != nil || display != initialDisplay {
		t.Fatalf("initial display name: got %q, want %q, err=%v", display, initialDisplay, err)
	}
	if err := UpdateLocalWindowsAccountDisplayName(name, sid, updatedDisplay, true); err != nil {
		t.Fatalf("update local account display name: %v", err)
	}
	display, err = localSAMDisplayName(name)
	if err != nil || display != updatedDisplay {
		t.Fatalf("updated display name: got %q, want %q, err=%v", display, updatedDisplay, err)
	}
	if err := DeleteLocalWindowsAccount(name, sid); err != nil {
		t.Fatalf("delete local account: %v", err)
	}
	deleted = true
	if _, err := lookupLocalWindowsAccount(name); !errors.Is(err, errLocalWindowsAccountNotFound) {
		t.Fatalf("deleted local account is still resolvable or lookup failed: %v", err)
	}
}
