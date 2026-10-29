//go:build windows

package windowslocal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLocalSAMLogonUIBlankPasswordObservation(t *testing.T) {
	requireSAMPolicyContainer(t)
	for _, test := range []struct {
		name                                           string
		blank, disabled, requiredFlag, notRequiredFlag bool
	}{
		{name: "nonblank"},
		{name: "nonblank-not-required-flag", notRequiredFlag: true},
		{name: "blank", blank: true},
		{name: "blank-required-flag", blank: true, requiredFlag: true},
		{name: "disabled-nonblank", disabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			account, password := newSAMPolicyAccountWithPassword(t, !test.blank)
			if test.disabled || test.requiredFlag || test.notRequiredFlag {
				flags := uint32(0x201)
				if test.disabled {
					flags |= 0x2
				}
				if test.notRequiredFlag {
					flags |= 0x20
				}
				setSAMPolicyInfo(t, account, 1008, unsafe.Pointer(&flags))
			}
			state, err := inspectPreliminaryPasswordAccount(t.Context(), account)
			require.NoError(t, err)
			require.Equal(t, test.disabled, state.Flags&0x2 != 0)
			if test.requiredFlag {
				require.Zero(t, state.Flags&0x20, "real blank fixture must remain blank even without PASSWORD_NOT_REQUIRED")
			}
			if test.notRequiredFlag {
				require.NotZero(t, state.Flags&0x20, "a strong password remains nonblank despite PASSWORD_NOT_REQUIRED")
			}
			observed, err := observeSAMLocalLogonUI(t.Context(), account)
			if err != nil {
				t.Logf("SAM_LOGON_UI_OBSERVATION unavailable=%q; research only, no eligibility", err)
				return
			}
			require.NotNil(t, observed)
			raw, err := json.Marshal(observed)
			require.NoError(t, err)
			t.Logf("SAM_LOGON_UI_OBSERVATION %s; research only, no eligibility", raw)
			require.Equal(t, test.blank, observed.PasswordIsBlank, "read-only local bit must distinguish the actual controlled blank/nonblank passwords")
			require.Equal(t, test.disabled, observed.AccountDisabled, "independent native flag control must agree")
			if test.blank {
				require.True(t, password == "", "blank fixture creation must not introduce a password")
			} else {
				require.True(t, len(password) > 0, "nonblank fixture creation must assign a password")
			}
		})
	}
	t.Run("blank-to-strong-same-account", func(t *testing.T) {
		account, _ := newSAMPolicyAccountWithPassword(t, false)
		before, err := observeSAMLocalLogonUI(t.Context(), account)
		if err != nil {
			t.Logf("SAM_LOGON_UI_TRANSITION unavailable-before=%q; research only, no eligibility", err)
			return
		}
		require.NotNil(t, before)
		require.True(t, before.PasswordIsBlank)
		require.False(t, before.AccountDisabled)
		var random [24]byte
		_, err = rand.Read(random[:])
		require.NoError(t, err)
		password := "N3w!" + hex.EncodeToString(random[:]) + "Z"
		clear(random[:])
		units, err := windows.UTF16FromString(password)
		require.NoError(t, err)
		defer clear(units)
		pointer := &units[0]
		setSAMPolicyInfo(t, account, 1003, unsafe.Pointer(&pointer))
		// Keep the flag set on this same owned account: the observed blank bit
		// must follow the password, not a password-required flag heuristic.
		flags := uint32(0x221)
		setSAMPolicyInfo(t, account, 1008, unsafe.Pointer(&flags))
		state, err := inspectPreliminaryPasswordAccount(t.Context(), account)
		require.NoError(t, err)
		require.NotZero(t, state.Flags&0x20)
		beforeReference, err := observeSAMLocalLogonUI(t.Context(), account)
		if err != nil {
			t.Logf("SAM_LOGON_UI_TRANSITION unavailable-before-reference=%q; research only, no eligibility", err)
			return
		}
		require.NotNil(t, beforeReference)
		require.False(t, beforeReference.PasswordIsBlank, "the completed reset must be visible before any password login can update a cache")
		require.False(t, beforeReference.AccountDisabled)
		accepted, err := ValidatePassword(account, password)
		require.NoError(t, err)
		require.True(t, accepted, "the owned strong reset must actually authenticate")
		for index := range 2 {
			after, err := observeSAMLocalLogonUI(t.Context(), account)
			if err != nil {
				t.Logf("SAM_LOGON_UI_TRANSITION unavailable-after=%q; research only, no eligibility", err)
				return
			}
			require.NotNil(t, after)
			require.False(t, after.PasswordIsBlank, "fresh handle%d must observe the same account's completed strong reset", index+1)
			require.False(t, after.AccountDisabled)
		}
		t.Log("SAM_LOGON_UI_TRANSITION blank=true->false with PASSWORD_NOT_REQUIRED still set; same SID, fresh query before reference logon and two after actual strong-password logon; research only, no eligibility")
	})
}
