//go:build windows

package environment

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLocalWindowsProcessMatches(t *testing.T) {
	const target = "S-1-5-21-1-2-3-1001"
	for _, test := range []struct {
		name       string
		pid, self  uint32
		targetSID  string
		processSID string
		want       bool
	}{
		{"matching user", 42, 7, target, target, true},
		{"different user", 42, 7, target, "S-1-5-21-1-2-3-1002", false},
		{"LocalSystem process", 42, 7, target, "S-1-5-18", false},
		{"LocalSystem target", 42, 7, "S-1-5-18", "S-1-5-18", false},
		{"current process", 7, 7, target, target, false},
		{"zero PID", 0, 7, target, target, false},
		{"empty target", 42, 7, "", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, localWindowsProcessMatches(test.pid, test.self, test.targetSID, test.processSID))
		})
	}
}

func TestLocalWindowsUnverifiedProcessFailsClosed(t *testing.T) {
	const targetSID = "S-1-5-21-1-2-3-1001"
	lookupFailure := errors.New("cannot enumerate process SID")
	for _, test := range []struct {
		name       string
		processErr error
		foreign    bool
		lookupErr  error
		skipped    bool
		lookedUp   bool
	}{
		{"foreign protected process", windows.ERROR_ACCESS_DENIED, true, nil, true, true},
		{"protected target", windows.ERROR_ACCESS_DENIED, false, nil, false, true},
		{"unknown SID", windows.ERROR_ACCESS_DENIED, false, lookupFailure, false, true},
		{"unrelated process error", windows.ERROR_INVALID_HANDLE, true, nil, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			lookedUp := false
			err := localWindowsUnverifiedProcessError(42, targetSID, test.processErr, func(pid uint32, sid string) (bool, error) {
				lookedUp = true
				require.Equal(t, uint32(42), pid)
				require.Equal(t, targetSID, sid)
				return test.foreign, test.lookupErr
			})
			require.Equal(t, test.lookedUp, lookedUp)
			if test.skipped {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.processErr)
			}
			if test.lookupErr != nil {
				require.ErrorIs(t, err, test.lookupErr)
			}
		})
	}
}

func TestLocalWindowsProcessIdentityEnumerationIsReadOnly(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		t.Skip("enumerating processes across users requires administrator privileges")
	}
	user, err := token.GetTokenUser()
	require.NoError(t, err)
	foreign, err := localWindowsForeignProcess(uint32(os.Getpid()), user.User.Sid.String())
	require.NoError(t, err)
	require.False(t, foreign)
}

func TestLocalWindowsKillFlagRestoration(t *testing.T) {
	repository := &LocalRepository{}
	account := windowsLocalAccount{Name: "alice", SID: "S-1-5-21-1-2-3-1001"}
	protected := windowsLocalAccount{Name: "admin", SID: "S-1-5-21-1-2-3-500"}
	for _, test := range []struct {
		name    string
		account windowsLocalAccount
		token   localToken
		want    bool
	}{
		{"enabled", account, localToken{Version: 2, Managed: true, DeleteOnDispose: true, KillProcessesOnDispose: true}, true},
		{"legacy", account, localToken{Managed: true, DeleteOnDispose: true, KillProcessesOnDispose: true}, false},
		{"no deletion", account, localToken{Version: 2, Managed: true, KillProcessesOnDispose: true}, true},
		{"unmanaged", account, localToken{Version: 2, KillProcessesOnDispose: true}, true},
		{"protected", protected, localToken{Version: 2, Managed: true, DeleteOnDispose: true, KillProcessesOnDispose: true}, false},
		{"protected explicit", protected, localToken{Version: 2, Managed: true, AllowSystemUsers: true, DeleteOnDispose: true, KillProcessesOnDispose: true}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, repository.new(test.account, nil, false, &test.token).killProcessesOnDispose)
		})
	}
}

func TestLocalWindowsKillMarkerSurvivesTokenRestore(t *testing.T) {
	account := windowsLocalAccount{Name: "alice", SID: "S-1-5-21-1-2-3-1001"}
	token := localToken{Version: 2, User: account, KillProcessesOnDispose: true, ProcessesKilledOnDispose: true}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	var restored localToken
	require.NoError(t, json.Unmarshal(encoded, &restored))
	env := (&LocalRepository{}).new(account, nil, false, &restored)
	require.True(t, env.killProcessesOnDispose)
	require.True(t, env.token.ProcessesKilledOnDispose)
	require.False(t, env.deleteOnDispose)
}
