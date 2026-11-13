//go:build windows

package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// CheckPasswordAccount checks current native restrictions and returns only a
// current request-local template view. Independent possession/session/target/
// method validation must surround this check; it is not primary authentication.
func CheckPasswordAccount(ctx context.Context, account Account, policy PasswordAccountPolicy) (result *PasswordAccount, resultErr error) {
	resultErr = withS4USystemContext(ctx, func() error {
		var err error
		result, err = readSAMPasswordAccount(ctx, account, samPasswordAccountOperations{
			restrictions: func() error {
				return checkSAMPasswordRestrictionsFlow(ctx, policy.AllowEmpty, nativeSAMPasswordRestrictionOperations(ctx, account))
			},
			identity:    func() (Account, error) { return currentAccount(account) },
			displayName: func() (string, error) { return userDisplayName(account.Name) },
			homeDir:     func() (string, error) { return profileDirectoryContext(ctx, account) },
			shell: func() (string, error) {
				if shell := os.Getenv("COMSPEC"); shell != "" {
					return shell, nil
				}
				return `C:\WINDOWS\system32\cmd.exe`, nil
			},
			groups: func() ([]group, error) { return userGroupsContext(ctx, account.Name) },
		})
		return err
	})
	if resultErr == nil && result == nil {
		resultErr = ErrPasswordAccountPolicyUnavailable
	}
	if resultErr != nil {
		result = nil
		if errors.Is(resultErr, errSAMPasswordRestriction) || errors.Is(resultErr, ErrNotFound) || errors.Is(resultErr, ErrPasswordAccountPolicyDenied) {
			resultErr = fmt.Errorf("%w: %w", ErrPasswordAccountPolicyDenied, resultErr)
		} else {
			resultErr = fmt.Errorf("%w: %w", ErrPasswordAccountPolicyUnavailable, resultErr)
		}
	}
	return result, resultErr
}
