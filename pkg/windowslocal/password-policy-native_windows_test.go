//go:build windows

package windowslocal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestS4UPolicyProbeFlagsDoNotPermitIdentificationOrBypass(t *testing.T) {
	for _, flags := range []uint32{0, 2} {
		buffer, _, err := s4uLogonBufferWithFlags("owned-user", flags)
		require.NoError(t, err)
		auth := (*s4uAuth)(unsafe.Pointer(&buffer[0]))
		require.EqualValues(t, 12, auth.MessageType)
		require.Equal(t, flags, auth.Flags)
	}
	for _, flags := range []uint32{1, 4, 8, 0xffffffff} {
		_, _, err := s4uLogonBufferWithFlags("owned-user", flags)
		require.Error(t, err)
	}
}

func requireSAMPolicyContainer(t *testing.T) {
	t.Helper()
	if os.Getenv("BIFROEST_TEST_SAM_POLICY_IN_CONTAINER") != "1" {
		t.Skip("requires the owned Server Core LocalSystem policy harness")
	}
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	require.Equal(t, "S-1-5-18", self.User.Sid.String())
	marker, err := os.ReadFile(`C:\smoke\servercore-container.marker`)
	require.NoError(t, err)
	require.Equal(t, "bifroest-servercore-integration", strings.TrimSpace(string(marker)))
	containerAdmin, _, _, err := windows.LookupSID("", "ContainerAdministrator")
	require.NoError(t, err)
	require.Equal(t, "S-1-5-93-2-1", containerAdmin.String(), "never mutate a host SAM or host LSA policy")
}

func newSAMPolicyAccount(t *testing.T) (Account, string) {
	return newSAMPolicyAccountWithPassword(t, true)
}

func newSAMPolicyAccountWithPassword(t *testing.T, withPassword bool) (Account, string) {
	t.Helper()
	requireSAMPolicyContainer(t)
	var nonce [8]byte
	_, err := rand.Read(nonce[:])
	require.NoError(t, err)
	name := "bifp" + hex.EncodeToString(nonce[:])
	var secret [24]byte
	_, err = rand.Read(secret[:])
	require.NoError(t, err)
	password := "T3st!" + hex.EncodeToString(secret[:]) + "Z"
	username, err := windows.UTF16PtrFromString(name)
	require.NoError(t, err)
	units, err := windows.UTF16FromString(password)
	require.NoError(t, err)
	defer clear(units)
	info := userInfo1{Name: username, Password: &units[0], Priv: 1, Flags: 0x201}
	if !withPassword {
		// Native creation without an initial password is distinct from resetting
		// a strong password to empty, which the image's complexity filter rejects.
		// This is only a new owned account; never weaken password complexity.
		info.Password = nil
		info.Flags |= 0x22 // UF_PASSWD_NOTREQD | UF_ACCOUNTDISABLE until owned setup is complete.
		password = ""
	}
	var parameter uint32
	err = netCall("NetUserAdd", 0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(username)
	runtime.KeepAlive(units)
	require.NoError(t, err, "create only the owned random policy account, parameter %d", parameter)
	account, err := Lookup(name)
	require.NoError(t, err)
	t.Cleanup(func() {
		if _, err := currentAccount(account); err != nil {
			t.Errorf("owned policy account identity changed before cleanup: %v", err)
			return
		}
		err := netCall("NetUserDel", 0, uintptr(unsafe.Pointer(username)))
		runtime.KeepAlive(username)
		if err != nil {
			t.Errorf("remove owned policy account: %v", err)
		}
	})
	if !withPassword {
		flags := uint32(0x221)
		setSAMPolicyInfo(t, account, 1008, unsafe.Pointer(&flags))
		setSAMPolicyPasswordExpired(t, account, false)
		state, err := inspectPreliminaryPasswordAccount(t.Context(), account)
		require.NoError(t, err)
		require.False(t, state.PasswordExpired, "the blank-password reference must not be poisoned by initial password expiry")
		require.Zero(t, state.Flags&0x800000)
	}
	return account, password
}

func setSAMPolicyInfo(t *testing.T, account Account, level uint32, value unsafe.Pointer) {
	t.Helper()
	requireSAMPolicyContainer(t)
	_, err := currentAccount(account)
	require.NoError(t, err)
	name, err := windows.UTF16PtrFromString(account.Name)
	require.NoError(t, err)
	var parameter uint32
	err = netCall("NetUserSetInfo", 0, uintptr(unsafe.Pointer(name)), uintptr(level), uintptr(value), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(name)
	runtime.KeepAlive(value)
	require.NoError(t, err, "set owned account level %d parameter %d", level, parameter)
}

func setSAMPolicyPasswordExpired(t *testing.T, account Account, expired bool) {
	t.Helper()
	requireSAMPolicyContainer(t)
	_, err := currentAccount(account)
	require.NoError(t, err)
	name, err := windows.UTF16PtrFromString(account.Name)
	require.NoError(t, err)
	var value *userInfo3
	err = netCall("NetUserGetInfo", 0, uintptr(unsafe.Pointer(name)), 3, uintptr(unsafe.Pointer(&value)))
	runtime.KeepAlive(name)
	if value != nil {
		defer func() { require.NoError(t, netCall("NetApiBufferFree", uintptr(unsafe.Pointer(value)))) }()
	}
	require.NoError(t, err)
	require.NotNil(t, value)
	value.PasswordExpired = 0
	value.Flags &^= 0x800000
	if expired {
		value.PasswordExpired = 1
	}
	setSAMPolicyInfo(t, account, 3, unsafe.Pointer(value))
}

func denySAMPolicyNetworkLogon(t *testing.T, account Account, throughGroup bool) {
	t.Helper()
	requireSAMPolicyContainer(t)
	_, err := currentAccount(account)
	require.NoError(t, err)
	subject, err := windows.StringToSid(account.SID)
	require.NoError(t, err)
	if throughGroup {
		groupName := "bifg" + strings.TrimPrefix(account.Name, "bifp")
		name, err := windows.UTF16PtrFromString(groupName)
		require.NoError(t, err)
		info := struct{ Name *uint16 }{name}
		var parameter uint32
		require.NoError(t, netCall("NetLocalGroupAdd", 0, 0, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter))))
		runtime.KeepAlive(name)
		var kind uint32
		var domain string
		subject, domain, kind, err = windows.LookupSID("", groupName)
		require.NoError(t, err)
		host, err := hostName()
		require.NoError(t, err)
		require.True(t, strings.EqualFold(domain, host))
		require.EqualValues(t, windows.SidTypeAlias, kind)
		groupSID := subject.String()
		t.Cleanup(func() {
			current, _, _, err := windows.LookupSID("", groupName)
			if err != nil || current.String() != groupSID {
				t.Errorf("owned policy group identity changed: %v", err)
				return
			}
			err = netCall("NetLocalGroupDel", 0, uintptr(unsafe.Pointer(name)))
			runtime.KeepAlive(name)
			if err != nil {
				t.Errorf("remove owned policy group: %v", err)
			}
		})
		member, err := windows.UTF16PtrFromString(host + `\` + account.Name)
		require.NoError(t, err)
		members := struct{ Name *uint16 }{member}
		require.NoError(t, netCall("NetLocalGroupAddMembers", 0, uintptr(unsafe.Pointer(name)), 3, uintptr(unsafe.Pointer(&members)), 1))
		runtime.KeepAlive(name)
		runtime.KeepAlive(member)
	}
	advapi := windows.NewLazySystemDLL("advapi32.dll")
	open, add, remove, closePolicy := advapi.NewProc("LsaOpenPolicy"), advapi.NewProc("LsaAddAccountRights"), advapi.NewProc("LsaRemoveAccountRights"), advapi.NewProc("LsaClose")
	type objectAttributes struct {
		Length                          uint32
		Root                            windows.Handle
		Name                            uintptr
		Attributes                      uint32
		SecurityDescriptor, SecurityQoS uintptr
	}
	attributes := objectAttributes{}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var policy windows.Handle
	status, _, _ := open.Call(0, uintptr(unsafe.Pointer(&attributes)), 0x811, uintptr(unsafe.Pointer(&policy))) // VIEW_LOCAL_INFORMATION | CREATE_ACCOUNT | LOOKUP_NAMES
	require.Zerof(t, uint32(status), "LsaOpenPolicy NTSTATUS 0x%08x", uint32(status))
	t.Cleanup(func() {
		status, _, _ := closePolicy.Call(uintptr(policy))
		if status != 0 {
			t.Errorf("LsaClose: 0x%08x", uint32(status))
		}
	})
	units, err := windows.UTF16FromString("SeDenyNetworkLogonRight")
	require.NoError(t, err)
	right := s4uUnicodeString{Length: uint16((len(units) - 1) * 2), MaximumLength: uint16(len(units) * 2), Buffer: &units[0]}
	status, _, _ = add.Call(uintptr(policy), uintptr(unsafe.Pointer(subject)), uintptr(unsafe.Pointer(&right)), 1)
	runtime.KeepAlive(subject)
	runtime.KeepAlive(units)
	require.Zerof(t, uint32(status), "LsaAddAccountRights owned SID: 0x%08x", uint32(status))
	t.Cleanup(func() {
		status, _, _ := remove.Call(uintptr(policy), uintptr(unsafe.Pointer(subject)), 0, uintptr(unsafe.Pointer(&right)), 1)
		runtime.KeepAlive(subject)
		runtime.KeepAlive(units)
		if status != 0 {
			t.Errorf("remove own network-deny right: 0x%08x", uint32(status))
		}
	})
}

func nativeSAMPolicyDecision(t *testing.T, account Account, password string, deny bool) uint32 {
	t.Helper()
	state, stateErr := inspectPreliminaryPasswordAccount(t.Context(), account)
	require.NoError(t, stateErr)
	reason := state.denialReason(time.Now())
	if strings.HasSuffix(t.Name(), "/password-must-change") {
		require.Equal(t, "password-must-change", reason, "fresh SAM must close the observed S4U must-change gap")
	}
	if !deny {
		require.Empty(t, reason)
	}
	var nativeStatus syscall.Errno
	primary, primaryErr := validatePasswordObserved(account, password, func(accepted bool, nativeErr error) {
		if !accepted {
			_ = errors.As(nativeErr, &nativeStatus)
		}
	})
	if primaryErr != nil {
		// Account expiry and denied network logon are policy denials too, even
		// though the primary API currently returns them as errors rather than false.
		require.True(t, errors.Is(primaryErr, syscall.Errno(1385)) || errors.Is(primaryErr, syscall.Errno(1793)), "unexpected primary policy failure: %v", primaryErr)
	}
	t.Logf("NATIVE_LOGON_REFERENCE accepted=%t nativeStatus=%d reason=%q", primary && primaryErr == nil, uint32(nativeStatus), reason)
	require.Equal(t, !deny, primary && primaryErr == nil, "regular Network LogonUser is the native policy reference, native status=%d", uint32(nativeStatus))
	type decision struct {
		Kind               string `json:"kind"`
		Accepted           bool   `json:"accepted"`
		Error              string `json:"error,omitempty"`
		NativeStatus       uint32 `json:"nativeStatus,omitempty"`
		LogonDataSize      uint32 `json:"logonDataSize,omitempty"`
		PasswordLastSet    string `json:"passwordLastSet,omitempty"`
		PasswordMustChange string `json:"passwordMustChange,omitempty"`
	}
	results := []decision{{Kind: "LogonUserNetwork", Accepted: primary && primaryErr == nil, NativeStatus: uint32(nativeStatus)}}
	t.Logf("FRESH_SAM_RESTRICTION reason=%q passwordExpired=%t age=%d maxAge=%d (preliminary, no eligibility)", reason, state.PasswordExpired, state.PasswordAge, state.MaximumPasswordAge)
	for _, flags := range []uint32{0, 2} {
		token, err := s4uImpersonationTokenWithFlagsContext(t.Context(), account.Name, flags)
		accepted := err == nil && token != 0
		result := decision{Kind: fmt.Sprintf("S4UNetworkFlags%d", flags), Accepted: accepted}
		if token != 0 {
			func() {
				defer func() { require.NoError(t, token.Close()) }()
				if accepted {
					user, lookupErr := token.GetTokenUser()
					require.NoError(t, lookupErr)
					require.Equal(t, account.SID, user.User.Sid.String())
					size, last, must := observeSAMPolicyLogonMetadata(t, token, account)
					result.LogonDataSize = size
					result.PasswordLastSet = fmt.Sprintf("%016x", uint64(last))
					result.PasswordMustChange = fmt.Sprintf("%016x", uint64(must))
				}
			}()
		}
		if !deny {
			require.NoError(t, err)
			require.True(t, accepted)
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}
	raw, err := json.Marshal(results)
	require.NoError(t, err)
	// A successful observation is not a resume eligibility pass. In particular,
	// S4U success in a denied primary case is recorded as a policy gap, not hidden.
	t.Logf("NATIVE_SAM_POLICY_OBSERVATION %s", raw)
	return uint32(nativeStatus)
}

func TestLocalSAMPasswordPolicyNativeMatrix(t *testing.T) {
	requireSAMPolicyContainer(t)
	tests := []struct {
		name      string
		deny      bool
		configure func(*testing.T, Account)
	}{
		{name: "ordinary", deny: false},
		{name: "disabled", deny: true, configure: func(t *testing.T, a Account) {
			flags := uint32(0x203)
			setSAMPolicyInfo(t, a, 1008, unsafe.Pointer(&flags))
		}},
		{name: "account-expired", deny: true, configure: func(t *testing.T, a Account) {
			expires := uint32(time.Now().Add(-time.Hour).Unix())
			setSAMPolicyInfo(t, a, 1017, unsafe.Pointer(&expires))
		}},
		{name: "outside-logon-hours", deny: true, configure: func(t *testing.T, a Account) {
			hours := [21]byte{}
			info := struct {
				UnitsPerWeek uint32
				LogonHours   *byte
			}{168, &hours[0]}
			setSAMPolicyInfo(t, a, 1020, unsafe.Pointer(&info))
			runtime.KeepAlive(hours)
		}},
		{name: "wrong-workstation", deny: true, configure: func(t *testing.T, a Account) {
			name, err := windows.UTF16PtrFromString("BFST-OTHER")
			require.NoError(t, err)
			setSAMPolicyInfo(t, a, 1014, unsafe.Pointer(&name))
			runtime.KeepAlive(name)
		}},
		{name: "password-must-change", deny: true, configure: func(t *testing.T, a Account) {
			setSAMPolicyPasswordExpired(t, a, true)
		}},
		{name: "network-logon-denied-direct", deny: true, configure: func(t *testing.T, a Account) { denySAMPolicyNetworkLogon(t, a, false) }},
		{name: "network-logon-denied-via-group", deny: true, configure: func(t *testing.T, a Account) { denySAMPolicyNetworkLogon(t, a, true) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account, password := newSAMPolicyAccount(t)
			if test.configure != nil {
				test.configure(t, account)
			}
			nativeSAMPolicyDecision(t, account, password, test.deny)
		})
	}
	// Windows containers may default this to zero. Tighten only this owned
	// disposable container's registry view; never assume the host's default and
	// never connect to a remote registry. Restore and verify the exact old value.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE|registry.SET_VALUE)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := key.Close(); err != nil {
			t.Errorf("close owned container policy key: %v", err)
		}
	})
	limit, kind, err := key.GetIntegerValue("LimitBlankPasswordUse")
	require.NoError(t, err)
	require.EqualValues(t, registry.DWORD, kind)
	t.Cleanup(func() {
		if err := key.SetDWordValue("LimitBlankPasswordUse", uint32(limit)); err != nil {
			t.Errorf("restore owned container blank-password policy: %v", err)
		} else {
			actual, _, err := key.GetIntegerValue("LimitBlankPasswordUse")
			if err != nil || actual != limit {
				t.Errorf("container blank-password policy restore mismatch: %d: %v", actual, err)
			}
		}
	})
	t.Logf("owned container blank-password policy: original=%d (both reference values verified; restored during cleanup)", limit)
	for _, passwordRequired := range []bool{false, true} {
		name := "blank-password-not-required"
		if passwordRequired {
			name = "blank-password-required-flag"
		}
		t.Run(name, func(t *testing.T) {
			account, password := newSAMPolicyAccountWithPassword(t, false)
			if passwordRequired {
				flags := uint32(0x201)
				setSAMPolicyInfo(t, account, 1008, unsafe.Pointer(&flags))
			}
			for _, restricted := range []bool{false, true} {
				value := uint32(0)
				phase := "restriction-disabled"
				if restricted {
					value = 1
					phase = "restriction-enabled"
				}
				t.Run(phase, func(t *testing.T) {
					require.NoError(t, key.SetDWordValue("LimitBlankPasswordUse", value))
					actual, _, err := key.GetIntegerValue("LimitBlankPasswordUse")
					require.NoError(t, err)
					require.EqualValues(t, value, actual)
					freshRestricted, err := inspectSAMBlankNetworkPolicy(t.Context())
					require.NoError(t, err)
					require.Equal(t, restricted, freshRestricted, "fresh read-only policy getter must observe this owned container's actual DWORD")
					// Both outcomes are required for this same account/password:
					// an unrelated account or password-change denial cannot pass.
					nativeSAMPolicyDecision(t, account, password, restricted)
				})
			}
		})
	}
	t.Run("actual-password-age-expiry", testNativeSAMPasswordAgeExpiry)
	t.Run("actual-account-lockout", testNativeSAMActualLockout)
}
