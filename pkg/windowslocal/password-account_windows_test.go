//go:build windows

package windowslocal

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestLocalSAMPasswordAccountView(t *testing.T) {
	requireSAMPolicyContainer(t)
	account, password := newSAMPolicyAccount(t)
	valid, err := ValidatePassword(account, password)
	require.NoError(t, err)
	require.True(t, valid, "controlled nonblank account must have a real native positive reference")
	before, err := CheckPasswordAccount(t.Context(), account, PasswordAccountPolicy{AllowEmpty: false})
	require.NoError(t, err)
	require.NotNil(t, before)
	require.Equal(t, account, before.Account())
	for _, field := range []string{"name", "uid", "displayName", "homeDir", "shell", "groups", "gids"} {
		_, found, err := before.GetField(field)
		require.NoError(t, err)
		require.True(t, found)
	}
	after, err := CheckPasswordAccount(t.Context(), account, PasswordAccountPolicy{AllowEmpty: true})
	require.NoError(t, err)
	require.True(t, before.IsEqualTo(after))
	state, err := inspectPreliminaryPasswordAccount(t.Context(), account)
	require.NoError(t, err)
	original := state.Flags
	t.Cleanup(func() { setSAMPolicyInfo(t, account, 1008, unsafe.Pointer(&original)) })
	disabled := original | 0x2
	setSAMPolicyInfo(t, account, 1008, unsafe.Pointer(&disabled))
	denied, err := CheckPasswordAccount(t.Context(), account, PasswordAccountPolicy{AllowEmpty: true})
	require.Nil(t, denied)
	require.ErrorIs(t, err, ErrPasswordAccountPolicyDenied)
	t.Log("CURRENT_SAM_PASSWORD_VIEW same bound SID/current fields/profile/groups, both operator values and fresh disabled denial; no primary credential replay")
}
