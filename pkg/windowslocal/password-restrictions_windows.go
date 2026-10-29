//go:build windows

package windowslocal

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// Private, prospective restriction kernel. A nil result is not a complete
// password-resume authorization. No token, password, group/environment snapshot
// or historical policy is retained, and no resume adapter calls this yet.
func checkSAMPasswordRestrictions(ctx context.Context, account Account, allowEmpty bool) error {
	return withS4USystemContext(ctx, func() error {
		return checkSAMPasswordRestrictionsFlow(ctx, allowEmpty, samPasswordRestrictionOperations{
			system:   func() error { return inspectS4USystemContext(ctx) },
			identity: func() error { _, err := currentAccount(account); return err },
			accountState: func() error {
				state, err := inspectPreliminaryPasswordAccount(ctx, account)
				if err != nil {
					return err
				}
				if state == nil || !strings.EqualFold(state.Account.Name, account.Name) || state.Account.SID != account.SID {
					return fmt.Errorf("native SAM restriction identity changed")
				}
				if reason := state.denialReason(time.Now()); reason != "" {
					return fmt.Errorf("%w: %s", errSAMPasswordRestriction, reason)
				}
				return nil
			},
			blankPassword: func() (bool, error) {
				state, err := observeSAMLocalLogonUI(ctx, account)
				if err != nil {
					return false, err
				}
				if state == nil {
					return false, fmt.Errorf("native SAM returned no blank-password observation")
				}
				if state.AccountDisabled {
					return false, errSAMPasswordRestriction
				}
				return state.PasswordIsBlank, nil
			},
			blankNetwork: func() (bool, error) { return inspectSAMBlankNetworkPolicy(ctx) },
			s4u: func() (uintptr, error) {
				token, err := s4uImpersonationTokenWithFlagsContext(ctx, account.Name, s4uLogonFlagCheckLogonHours)
				return uintptr(token), err
			},
			tokenIdentity: func(value uintptr) error {
				user, err := windows.Token(value).GetTokenUser()
				if err != nil {
					return err
				}
				if user == nil || !sameSID(account.SID, user.User.Sid) {
					return fmt.Errorf("native S4U restriction token SID changed")
				}
				return nil
			},
			closeToken: func(value uintptr) error { return windows.Token(value).Close() },
		})
	})
}
