//go:build windows

package environment

import "testing"

func TestLocalSAMProtectedNames(t *testing.T) {
	for _, name := range []string{"Administrator", "aDmInIsTrAtOr", "Guest", "DefaultAccount", "WDAGUtilityAccount", "krbtgt", "LocalSystem", "SYSTEM", "LocalService", "NetworkService", "ContainerAdministrator", "ContainerUser"} {
		if !localSAMProtectedName(name) {
			t.Errorf("accepted protected name %q", name)
		}
	}
	if localSAMProtectedName("ordinary") {
		t.Fatal("rejected ordinary name")
	}
}

func TestLocalSAMProtectedSIDs(t *testing.T) {
	for _, sid := range []string{"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-93-2-1", "S-1-5-93-2-2"} {
		if !localSAMProtectedAccount(windowsLocalAccount{Name: "renamed", SID: sid}) {
			t.Errorf("accepted protected SID %s", sid)
		}
	}
	for _, rid := range []string{"500", "501", "503", "504"} {
		if !localSAMProtectedAccount(windowsLocalAccount{Name: "renamed", SID: "S-1-5-21-1-2-3-" + rid}) {
			t.Errorf("accepted protected RID %s", rid)
		}
	}
	if localSAMProtectedAccount(windowsLocalAccount{Name: "ordinary", SID: "S-1-5-21-1-2-3-1500"}) {
		t.Fatal("rejected ordinary RID")
	}
}

func TestLocalSAMGroupNameValidation(t *testing.T) {
	for _, name := range []string{"", `domain\group`, "bad/name", "guest", "a\x00b"} {
		if err := localSAMGroupName(name); err == nil {
			t.Errorf("accepted unsafe group %q", name)
		}
	}
	if err := localSAMGroupName("bifroest-managed"); err != nil {
		t.Fatal(err)
	}
	if err := localSAMGroupName("ops@corp"); err != nil {
		t.Fatalf("rejected valid Windows local group: %v", err)
	}
}

func TestLocalSAMAccountDisabled(t *testing.T) {
	for _, tc := range []struct {
		flags    uint32
		disabled bool
	}{
		{0, false},
		{0x201, false},
		{localSAMUFAccountDisable, true},
		{0x201 | localSAMUFAccountDisable, true},
	} {
		if got := localSAMAccountDisabled(tc.flags); got != tc.disabled {
			t.Errorf("flags %#x: disabled = %t, want %t", tc.flags, got, tc.disabled)
		}
	}
}

func TestLocalSAMDisableFlags(t *testing.T) {
	ordinary := windowsLocalAccount{Name: "ordinary", SID: "S-1-5-21-1-2-3-1500"}
	for _, flags := range []uint32{0, 0x201, 0x201 | localSAMUFAccountDisable, 0xffffffff} {
		got, err := localSAMDisableFlags(ordinary, true, flags)
		if err != nil {
			t.Fatalf("flags %#x: %v", flags, err)
		}
		if want := flags | localSAMUFAccountDisable; got != want {
			t.Errorf("flags %#x: got %#x, want %#x", flags, got, want)
		}
	}
	for _, tc := range []struct {
		name    string
		account windowsLocalAccount
		member  bool
	}{
		{"not managed", ordinary, false},
		{"protected name", windowsLocalAccount{Name: "Guest", SID: ordinary.SID}, true},
		{"protected SID", windowsLocalAccount{Name: "renamed", SID: "S-1-5-21-1-2-3-500"}, true},
		{"protected and not managed", windowsLocalAccount{Name: "Guest", SID: ordinary.SID}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := localSAMDisableFlags(tc.account, tc.member, 0x201); err == nil {
				t.Errorf("accepted unsafe account with flags %#x", got)
			}
		})
	}
}
