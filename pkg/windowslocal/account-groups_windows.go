//go:build windows

package windowslocal

import "context"

// Private prospective policy input; no resume or grant capability. Each call
// rereads the same native direct aliases and binds the account before/after.
func inspectSAMGroups(ctx context.Context, account Account) (result []group, resultErr error) {
	resultErr = withS4USystemContext(ctx, func() error {
		var err error
		result, err = inspectSAMGroupsFlow(ctx, func() error { _, err := currentAccount(account); return err }, func() ([]group, error) { return userGroupsContext(ctx, account.Name) })
		return err
	})
	if resultErr != nil {
		result = nil
	}
	return result, resultErr
}
