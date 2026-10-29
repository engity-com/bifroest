//go:build windows

package windowslocal

import (
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func requireOwnedSAMPolicyDomain(t *testing.T, account Account) {
	t.Helper()
	requireSAMPolicyContainer(t)
	_, err := currentAccount(account)
	require.NoError(t, err)
	var domain *struct {
		Name *uint16
		SID  *windows.SID
	}
	err = netCall("NetUserModalsGet", 0, 2, uintptr(unsafe.Pointer(&domain)))
	if domain != nil {
		defer func() { require.NoError(t, netCall("NetApiBufferFree", uintptr(unsafe.Pointer(domain)))) }()
	}
	require.NoError(t, err)
	require.NotNil(t, domain)
	require.NotNil(t, domain.SID)
	separator := strings.LastIndexByte(account.SID, '-')
	require.Positive(t, separator)
	require.True(t, sameSID(account.SID[:separator], domain.SID), "refuse to write a policy belonging to any other SAM domain")
	host, err := hostName()
	require.NoError(t, err)
	require.True(t, strings.EqualFold(host, windows.UTF16PtrToString(domain.Name)))
}

func setOwnedSAMPolicy(t *testing.T, account Account, level uint32, value unsafe.Pointer) {
	t.Helper()
	requireOwnedSAMPolicyDomain(t, account)
	var parameter uint32
	err := netCall("NetUserModalsSet", 0, uintptr(level), uintptr(value), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(value)
	require.NoError(t, err, "set only the owned disposable container SAM policy level%d parameter%d", level, parameter)
}

func readOwnedSAMPolicy[T any](t *testing.T, account Account, level uint32) T {
	t.Helper()
	requireOwnedSAMPolicyDomain(t, account)
	var value *T
	err := netCall("NetUserModalsGet", 0, uintptr(level), uintptr(unsafe.Pointer(&value)))
	if value != nil {
		defer func() { require.NoError(t, netCall("NetApiBufferFree", uintptr(unsafe.Pointer(value)))) }()
	}
	require.NoError(t, err)
	require.NotNil(t, value)
	return *value
}

func testNativeSAMPasswordAgeExpiry(t *testing.T) {
	account, password := newSAMPolicyAccount(t)
	original := readOwnedSAMPolicy[userModalsInfo0](t, account, 0)
	require.Less(t, original.MinimumPasswordAge, uint32(2), "do not lower the minimum change age to make the fixture work")
	policy := original
	policy.MaximumPasswordAge = 2
	t.Cleanup(func() {
		setOwnedSAMPolicy(t, account, 0, unsafe.Pointer(&original))
		require.Equal(t, original, readOwnedSAMPolicy[userModalsInfo0](t, account, 0))
	})
	setOwnedSAMPolicy(t, account, 0, unsafe.Pointer(&policy))
	require.Equal(t, policy, readOwnedSAMPolicy[userModalsInfo0](t, account, 0), "length/history/minimum age remain byte-for-byte unchanged")
	nativeSAMPolicyDecision(t, account, password, false)
	deadline := time.Now().Add(5 * time.Second)
	for {
		state, err := inspectPreliminaryPasswordAccount(t.Context(), account)
		require.NoError(t, err)
		if state.PasswordAge >= 2 {
			require.Equal(t, "password-expired", state.denialReason(time.Now()))
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned account did not reach actual native password age2")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-t.Context().Done():
			timer.Stop()
			t.Fatal(t.Context().Err())
		case <-timer.C:
		}
	}
	nativeSAMPolicyDecision(t, account, password, true)
}

func testNativeSAMActualLockout(t *testing.T) {
	account, password := newSAMPolicyAccount(t)
	type lockoutPolicy struct{ Duration, ObservationWindow, Threshold uint32 }
	original := readOwnedSAMPolicy[lockoutPolicy](t, account, 3)
	policy := original
	policy.Threshold = 1
	if policy.ObservationWindow == 0 {
		policy.ObservationWindow = 30
	}
	if policy.Duration != 0 && policy.Duration < policy.ObservationWindow {
		policy.Duration = policy.ObservationWindow
	}
	t.Cleanup(func() {
		setOwnedSAMPolicy(t, account, 3, unsafe.Pointer(&original))
		require.Equal(t, original, readOwnedSAMPolicy[lockoutPolicy](t, account, 3))
	})
	setOwnedSAMPolicy(t, account, 3, unsafe.Pointer(&policy))
	require.Equal(t, policy, readOwnedSAMPolicy[lockoutPolicy](t, account, 3))
	nativeSAMPolicyDecision(t, account, password, false)
	accepted, err := ValidatePassword(account, "known wrong fixture password")
	require.NoError(t, err)
	require.False(t, accepted)
	state, err := inspectPreliminaryPasswordAccount(t.Context(), account)
	require.NoError(t, err)
	require.Equal(t, "account-locked", state.denialReason(time.Now()), "one actual failed logon must trigger native lockout, not a forged flag")
	nativeSAMPolicyDecision(t, account, password, true)
}
