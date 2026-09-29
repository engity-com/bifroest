//go:build windows

package environment

import "testing"

func TestValidateWindowsLocalGroupRequirement(t *testing.T) {
	tests := []struct {
		name  string
		group windowsLocalGroupRequirement
		want  string
	}{
		{"name only", windowsLocalGroupRequirement{Name: "developers"}, ""},
		{"SID only", windowsLocalGroupRequirement{SID: "S-1-5-21-1-2-3-1001"}, "S-1-5-21-1-2-3-1001"},
		{"name and SID", windowsLocalGroupRequirement{Name: "developers", SID: windowsBuiltinUsersSID}, windowsBuiltinUsersSID},
		{"BUILTIN Users", windowsLocalGroupRequirement{Name: "Users", SID: windowsBuiltinUsersSID}, windowsBuiltinUsersSID},
		{"empty", windowsLocalGroupRequirement{}, "invalid"},
		{"domain name", windowsLocalGroupRequirement{Name: `domain\developers`}, "invalid"},
		{"qualified BUILTIN name", windowsLocalGroupRequirement{Name: `BUILTIN\Users`}, "invalid"},
		{"NUL name", windowsLocalGroupRequirement{Name: "a\x00b"}, "invalid"},
		{"invalid SID", windowsLocalGroupRequirement{SID: "not-a-SID"}, "invalid"},
		{"Administrators SID", windowsLocalGroupRequirement{SID: "S-1-5-32-544"}, "invalid"},
		{"other BUILTIN alias", windowsLocalGroupRequirement{SID: "S-1-5-32-551"}, "invalid"},
		{"Administrators name", windowsLocalGroupRequirement{Name: "aDmInIsTrAtOrS"}, "invalid"},
		{"Backup Operators name", windowsLocalGroupRequirement{Name: "Backup Operators"}, "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid, err := validateWindowsLocalGroupRequirement(tt.group)
			if tt.want == "invalid" {
				if err == nil {
					t.Fatalf("accepted unsafe group %+v", tt.group)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" && sid != nil || tt.want != "" && (sid == nil || sid.String() != tt.want) {
				t.Fatalf("SID = %v; want %q", sid, tt.want)
			}
		})
	}
}

func TestWindowsLocalGroupReadOnlyAllowsPrivilegedAliases(t *testing.T) {
	if _, err := validateWindowsLocalGroupIdentity(windowsLocalGroupRequirement{Name: "Administrators", SID: "S-1-5-32-544"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := validateWindowsLocalGroupIdentity(windowsLocalGroupRequirement{Name: `domain\Administrators`}, true); err == nil {
		t.Fatal("accepted domain-qualified alias")
	}
}
