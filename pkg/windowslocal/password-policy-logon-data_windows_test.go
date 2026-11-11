//go:build windows

package windowslocal

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

type policyTokenStatistics struct {
	TokenID, AuthenticationID                                    windows.LUID
	ExpirationTime                                               int64
	TokenType, ImpersonationLevel                                uint32
	DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount uint32
	ModifiedID                                                   windows.LUID
}

type policyLogonSessionData struct {
	Size                                         uint32
	LogonID                                      windows.LUID
	UserName, LogonDomain, AuthenticationPackage s4uUnicodeString
	LogonType, Session                           uint32
	SID                                          *windows.SID
	LogonTime                                    int64
	LogonServer, DNSDomainName, UPN              s4uUnicodeString
	UserFlags                                    uint32
	LastLogonInfo                                struct {
		Successful, Failed int64
		FailedAttemptCount uint32
	}
	LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive                     s4uUnicodeString
	LogoffTime, KickOffTime, PasswordLastSet, PasswordCanChange, PasswordMustChange int64
}

func TestSAMPolicyNativeLogonMetadataLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("this read-only metadata observation targets 64-bit Windows")
	}
	require.Equal(t, uintptr(56), unsafe.Sizeof(policyTokenStatistics{}))
	require.Equal(t, uintptr(8), unsafe.Offsetof(policyTokenStatistics{}.AuthenticationID))
	require.Equal(t, uintptr(272), unsafe.Sizeof(policyLogonSessionData{}))
	require.Equal(t, uintptr(248), unsafe.Offsetof(policyLogonSessionData{}.PasswordLastSet))
}

// Read only nonsecret account/password timestamps from this fresh token's own
// LUID. The authentication package may leave PasswordLastSet zero; record that
// fact instead of treating an absent generation as an eligibility capability.
func observeSAMPolicyLogonMetadata(t *testing.T, token windows.Token, account Account) (size uint32, last, must int64) {
	t.Helper()
	require.Equal(t, uintptr(8), unsafe.Sizeof(uintptr(0)), "never read a 32-bit native structure through the 64-bit observation layout")
	var statistics policyTokenStatistics
	var returned uint32
	require.NoError(t, windows.GetTokenInformation(token, windows.TokenStatistics, (*byte)(unsafe.Pointer(&statistics)), uint32(unsafe.Sizeof(statistics)), &returned))
	require.EqualValues(t, unsafe.Sizeof(statistics), returned)
	var data *policyLogonSessionData
	query := s4uSecur32.NewProc("LsaGetLogonSessionData")
	require.NoError(t, query.Find())
	status, _, _ := query.Call(uintptr(unsafe.Pointer(&statistics.AuthenticationID)), uintptr(unsafe.Pointer(&data)))
	if data != nil {
		defer func() {
			status, _, _ := s4uFreeBuffer.Call(uintptr(unsafe.Pointer(data)))
			require.Zerof(t, uint32(status), "free native logon data: 0x%08x", uint32(status))
		}()
	}
	require.Zerof(t, uint32(status), "LsaGetLogonSessionData: 0x%08x", uint32(status))
	require.NotNil(t, data)
	require.GreaterOrEqual(t, data.Size, uint32(unsafe.Sizeof(policyLogonSessionData{})), "never read beyond the native versioned structure")
	require.Equal(t, statistics.AuthenticationID, data.LogonID)
	require.EqualValues(t, 3, data.LogonType)
	require.NotNil(t, data.SID)
	require.True(t, sameSID(account.SID, data.SID))
	return data.Size, data.PasswordLastSet, data.PasswordMustChange
}
