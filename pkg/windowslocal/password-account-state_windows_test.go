//go:build windows

package windowslocal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPreliminarySAMPasswordRestrictionsAreNotS4UAvailability(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := preliminaryPasswordAccountState{AccountExpires: ^uint32(0), MaximumPasswordAge: 3600, PasswordAge: 3599}
	for _, test := range []struct {
		name, reason string
		update       func(*preliminaryPasswordAccountState)
	}{
		{"ordinary", "", func(*preliminaryPasswordAccountState) {}},
		{"disabled", "account-disabled", func(s *preliminaryPasswordAccountState) { s.Flags |= 2 }},
		{"locked", "account-locked", func(s *preliminaryPasswordAccountState) { s.Flags |= 0x10 }},
		{"expiry-boundary", "account-expired", func(s *preliminaryPasswordAccountState) { s.AccountExpires = uint32(now.Unix()) }},
		{"must-change-field", "password-must-change", func(s *preliminaryPasswordAccountState) { s.PasswordExpired = true }},
		{"must-change-flag", "password-must-change", func(s *preliminaryPasswordAccountState) { s.Flags |= 0x800000 }},
		{"password-age-boundary", "password-expired", func(s *preliminaryPasswordAccountState) { s.PasswordAge = 3600 }},
		{"never-expire-policy", "", func(s *preliminaryPasswordAccountState) {
			s.MaximumPasswordAge = ^uint32(0)
			s.PasswordAge = ^uint32(0)
		}},
		{"never-expire-account", "", func(s *preliminaryPasswordAccountState) { s.Flags |= 0x10000; s.PasswordAge = 3601 }},
		{"must-change-overrides-never-expire", "password-must-change", func(s *preliminaryPasswordAccountState) { s.Flags |= 0x10000; s.PasswordExpired = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := base
			test.update(&state)
			require.Equal(t, test.reason, state.denialReason(now))
		})
	}
}

func TestPreliminarySAMPasswordStateRejectsCancellationBeforeNativeLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	state, err := inspectPreliminaryPasswordAccount(ctx, Account{Name: "must-not-be-looked-up"})
	require.Nil(t, state)
	require.ErrorIs(t, err, context.Canceled)
}
