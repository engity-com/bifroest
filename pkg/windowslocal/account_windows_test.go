//go:build windows

package windowslocal

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestSIDMatching(t *testing.T) {
	sid, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{sid.String(), true},
		{"S-1-5-21-1-2-3-1002", false},
		{"", false},
		{"not-a-sid", false},
	} {
		if got := sameSID(tc.value, sid); got != tc.want {
			t.Errorf("sameSID(%q) = %t, want %t", tc.value, got, tc.want)
		}
	}
	if sameSID(sid.String(), nil) {
		t.Fatal("nil expected SID matched")
	}
}

func TestMissingIdentity(t *testing.T) {
	for _, a := range []Account{{}, {Name: "alice"}, {SID: "S-1-5-21-1-2-3-1001"}, {Name: `DOMAIN\alice`, SID: "S-1-5-21-1-2-3-1001"}, {Name: "alice", SID: "bad"}} {
		if _, err := currentAccount(a); err == nil {
			t.Errorf("currentAccount(%+v) accepted incomplete identity", a)
		}
		if _, err := Unavailable(a); err == nil {
			t.Errorf("Unavailable(%+v) accepted incomplete identity", a)
		}
		if _, err := ValidatePassword(a, "test"); err == nil {
			t.Errorf("ValidatePassword(%+v) accepted incomplete identity", a)
		}
		if _, ok, err := a.GetField("homeDir"); ok || err == nil {
			t.Errorf("homeDir for %+v = ok %t, err %v", a, ok, err)
		}
	}
}

func TestNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", " user", "user ", "user.", `machine\user`, "user@domain", "user\x00suffix", "user\n", "bad\xff"} {
		if validName(name) {
			t.Errorf("accepted invalid name %q", name)
		}
	}
	for _, name := range []string{"alice", "Alice Smith", "\u00e4lice"} {
		if !validName(name) {
			t.Errorf("rejected valid name %q", name)
		}
	}
}

func TestFieldsWithoutConfiguration(t *testing.T) {
	a := Account{Name: "alice", SID: "S-1-5-21-1-2-3-1001"}
	for name, want := range map[string]any{"name": a.Name, "uid": a.SID, "managed": nil} {
		got, ok, err := a.GetField(name)
		if err != nil || !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("GetField(%q) = %v, %t, %v; want %v", name, got, ok, err, want)
		}
	}
	if value, ok, err := a.GetField("shell"); err != nil || !ok || value == "" {
		t.Errorf("shell = %v, %t, %v", value, ok, err)
	}
	if _, ok, err := a.GetField("unknown"); ok || err == nil {
		t.Errorf("unknown field returned ok=%t, err=%v", ok, err)
	}
	g := group{"Users", "S-1-5-32-545"}
	for name, want := range map[string]string{"name": g.Name, "gid": g.SID} {
		got, ok, err := g.GetField(name)
		if err != nil || !ok || got != want {
			t.Errorf("group.%s = %v, %t, %v", name, got, ok, err)
		}
	}
	if _, ok, err := g.GetField("unknown"); ok || err == nil {
		t.Errorf("unknown group field returned ok=%t, err=%v", ok, err)
	}
}

func TestInvalidCredentials(t *testing.T) {
	for _, code := range []syscall.Errno{86, 1326, 1327, 1328, 1329, 1330, 1331, 1907, 1909} {
		if !invalidCredentials(code) {
			t.Errorf("code %d should be a rejection", code)
		}
	}
	for _, err := range []error{nil, syscall.Errno(5), errors.New("system error")} {
		if invalidCredentials(err) {
			t.Errorf("unexpected credential rejection for %v", err)
		}
	}
}

func TestAccountUnavailable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		name           string
		flags, expires uint32
		want           bool
	}{
		{"active", 0, ^uint32(0), false},
		{"disabled", 0x2, ^uint32(0), true},
		{"locked", 0x10, ^uint32(0), true},
		{"expires later", 0, uint32(now.Unix() + 1), false},
		{"expired now", 0, uint32(now.Unix()), true},
		{"expired earlier", 0, uint32(now.Unix() - 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := accountUnavailable(tc.flags, tc.expires, now); got != tc.want {
				t.Errorf("accountUnavailable(%#x, %d) = %t, want %t", tc.flags, tc.expires, got, tc.want)
			}
		})
	}
}

func TestS4ULogonBuffer(t *testing.T) {
	buffer, length, err := s4uLogonBuffer("localuser")
	if err != nil {
		t.Fatal(err)
	}
	if length != int(unsafe.Sizeof(s4uAuth{}))+(len("localuser")+1+2)*2 {
		t.Fatalf("unexpected authentication buffer length %d", length)
	}
	auth := (*s4uAuth)(unsafe.Pointer(&buffer[0]))
	if auth.MessageType != 12 || auth.User.Length != uint16(len("localuser")*2) || auth.User.MaximumLength != auth.User.Length+2 {
		t.Fatalf("invalid S4U authentication header: %+v", *auth)
	}
	if got := windows.UTF16ToString(unsafe.Slice(auth.User.Buffer, int(auth.User.MaximumLength)/2)); got != "localuser" {
		t.Errorf("S4U username = %q", got)
	}
	if auth.Domain.Length != 2 || auth.Domain.MaximumLength != 4 || windows.UTF16ToString(unsafe.Slice(auth.Domain.Buffer, 2)) != "." {
		t.Error("S4U domain is not local")
	}
	if _, _, err := s4uLogonBuffer("bad\x00user"); err == nil {
		t.Error("accepted embedded NUL")
	}
	if _, _, err := s4uLogonBuffer(strings.Repeat("x", 32768)); err == nil {
		t.Error("accepted oversized S4U username")
	}
}

func TestLocalSAMIntegration(t *testing.T) {
	name := os.Getenv("BIFROEST_WINDOWSLOCAL_TEST_USER")
	if name == "" {
		t.Skip("set BIFROEST_WINDOWSLOCAL_TEST_USER to an existing local SAM account")
	}
	a, err := Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(a.Name, name) || a.SID == "" {
		t.Fatalf("unexpected local identity: %+v", a)
	}
	bySID, err := LookupBySID(a.SID)
	if err != nil || bySID != a {
		t.Fatalf("LookupBySID = %+v, %v; want %+v", bySID, err, a)
	}
	if _, err := Unavailable(a); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"displayName", "groups", "gids"} {
		if _, ok, err := a.GetField(field); err != nil || !ok {
			t.Errorf("GetField(%q) = ok %t, err %v", field, ok, err)
		}
	}
	if _, err := ValidatePassword(a, ""); err != nil {
		t.Errorf("empty password validation: %v", err)
	}
	// Run as LocalSystem; the account may have no ProfileList entry yet.
	if os.Getenv("BIFROEST_WINDOWSLOCAL_TEST_S4U") == "1" {
		value, ok, err := a.GetField("homeDir")
		if err != nil || !ok || value == "" {
			t.Errorf("S4U homeDir = %v, %t, %v", value, ok, err)
		}
	}
}
