//go:build windows

package windowslocal

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestS4USystemContextRejectsOrdinaryProcess(t *testing.T) {
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	if self.User.Sid.String() == "S-1-5-18" {
		t.Skip("ordinary process control requires a non-LocalSystem unit runner")
	}
	called := false
	err = withS4USystemContext(t.Context(), func() error { called = true; return nil })
	require.ErrorIs(t, err, errS4USystemContext)
	require.False(t, called)
}

func ownedSystemContextImpersonation(t *testing.T) windows.Token {
	t.Helper()
	requireSAMPolicyContainer(t)
	var processToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
	if processToken != 0 {
		defer func() { require.NoError(t, processToken.Close()) }()
	}
	require.NoError(t, err)
	require.NotZero(t, processToken)
	var token windows.Token
	err = windows.DuplicateTokenEx(processToken, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &token)
	if token != 0 {
		t.Cleanup(func() { require.NoError(t, token.Close()) })
	}
	require.NoError(t, err)
	require.NotZero(t, token)
	return token
}

func systemContextThreadStatistics(t *testing.T) policyTokenStatistics {
	t.Helper()
	var token windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)
	if token != 0 {
		defer func() { require.NoError(t, token.Close()) }()
	}
	require.NoError(t, err)
	require.NotZero(t, token)
	var statistics policyTokenStatistics
	var returned uint32
	require.NoError(t, windows.GetTokenInformation(token, windows.TokenStatistics, (*byte)(unsafe.Pointer(&statistics)), uint32(unsafe.Sizeof(statistics)), &returned))
	require.EqualValues(t, unsafe.Sizeof(statistics), returned)
	return statistics
}

func TestLocalSAMSystemContextIsolation(t *testing.T) {
	requireSAMPolicyContainer(t)
	t.Run("worker-and-thread-retirement", func(t *testing.T) {
		account, _ := newSAMPolicyAccount(t)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		caller := windows.GetCurrentThreadId()
		var workerID uint32
		var worker windows.Handle
		err := withS4USystemContext(t.Context(), func() (resultErr error) {
			workerID = windows.GetCurrentThreadId()
			if workerID == s4uStartupThreadID {
				return fmt.Errorf("native work selected the startup thread")
			}
			if workerID == caller {
				return fmt.Errorf("native policy did not enter an isolated thread")
			}
			var err error
			worker, err = windows.OpenThread(windows.SYNCHRONIZE, false, workerID)
			if err != nil {
				return err
			}
			token, err := s4uImpersonationTokenWithFlagsContext(t.Context(), account.Name, s4uLogonFlagCheckLogonHours)
			if token != 0 {
				defer func() { resultErr = errors.Join(resultErr, token.Close()) }()
			}
			if err != nil {
				return err
			}
			user, err := token.GetTokenUser()
			if err != nil {
				return err
			}
			if user == nil || user.User.Sid == nil || user.User.Sid.String() != account.SID {
				return fmt.Errorf("isolated native token SID mismatch")
			}
			runtime.Gosched()
			if windows.GetCurrentThreadId() != workerID {
				return fmt.Errorf("native worker changed its OS thread")
			}
			return nil
		})
		if worker != 0 {
			defer func() { require.NoError(t, windows.CloseHandle(worker)) }()
		}
		require.NoError(t, err)
		require.NotZero(t, worker)
		require.Equal(t, caller, windows.GetCurrentThreadId(), "caller thread ownership must remain unchanged")
		status, err := windows.WaitForSingleObject(worker, 3000)
		require.NoError(t, err)
		require.EqualValues(t, windows.WAIT_OBJECT_0, status, "isolated OS thread must terminate, not return to the Go pool")
		t.Log("S4U_SYSTEM_CONTEXT native isolated LocalSystem worker/target SID/thread retirement confirmed; no eligibility")
	})
	t.Run("caller-impersonation-is-denied-not-reverted", func(t *testing.T) {
		runtime.LockOSThread()
		defer func() {
			if err := windows.RevertToSelf(); err != nil {
				t.Errorf("restore only the owned fixture thread: %v", err)
				return
			}
			runtime.UnlockOSThread()
		}()
		impersonation := ownedSystemContextImpersonation(t)
		require.NoError(t, windows.SetThreadToken(nil, impersonation))
		before := systemContextThreadStatistics(t)
		called := false
		err := withS4USystemContext(t.Context(), func() error { called = true; return nil })
		require.ErrorIs(t, err, errS4USystemContext)
		require.False(t, called)
		var retained windows.Token
		err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &retained)
		if retained != 0 {
			defer func() { require.NoError(t, retained.Close()) }()
		}
		require.NoError(t, err)
		require.NotZero(t, retained, "denial must not silently RevertToSelf on the caller")
		after := systemContextThreadStatistics(t)
		require.Equal(t, before.TokenID, after.TokenID, "guard must not replace the caller's thread token")
		require.Equal(t, before.AuthenticationID, after.AuthenticationID)
		require.Equal(t, before.ModifiedID, after.ModifiedID, "guard must not mutate the caller's token contents")
		require.Equal(t, before.TokenType, after.TokenType)
		require.Equal(t, before.ImpersonationLevel, after.ImpersonationLevel)
		t.Log("S4U_SYSTEM_CONTEXT native caller token identity/modification statistics unchanged; fixture alone restores it")
	})
	t.Run("worker-impersonation-denied-and-thread-retired", func(t *testing.T) {
		impersonation := ownedSystemContextImpersonation(t)
		var worker windows.Handle
		err := withS4USystemContext(t.Context(), func() error {
			if windows.GetCurrentThreadId() == s4uStartupThreadID {
				return fmt.Errorf("native identity fixture selected startup thread")
			}
			var err error
			worker, err = windows.OpenThread(windows.SYNCHRONIZE, false, windows.GetCurrentThreadId())
			if err != nil {
				return err
			}
			// Deliberately leave this *owned fixture worker* impersonating. The
			// production guard must deny and retire it, never call RevertToSelf.
			return windows.SetThreadToken(nil, impersonation)
		})
		if worker != 0 {
			defer func() { require.NoError(t, windows.CloseHandle(worker)) }()
		}
		require.ErrorIs(t, err, errS4USystemContext)
		require.NotZero(t, worker)
		status, err := windows.WaitForSingleObject(worker, 3000)
		require.NoError(t, err)
		require.EqualValues(t, windows.WAIT_OBJECT_0, status)
		require.NoError(t, inspectS4USystemContext(t.Context()), "worker identity must not leak into the caller")
		t.Log("S4U_SYSTEM_CONTEXT native worker impersonation denied and isolated OS thread retired without revert")
	})
}
