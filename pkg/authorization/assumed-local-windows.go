//go:build unix || windows

package authorization

import (
	"context"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

// BindAssumedLocalWindowsAuthentication binds an assumed post-authentication
// local account to supplied Windows facts, including on non-Windows test hosts.
// It performs no native account, credential, policy, token or profile operation.
// Canonical SID syntax/scope are the fixture layer's responsibility, as for the
// MemoryLookup; a supplied snapshot is never native password-policy evidence.
func BindAssumedLocalWindowsAuthentication(ctx context.Context, flow *configuration.Flow, accountName string, accounts *windowslocal.MemoryLookup) (*AssumedLocalAuthentication, error) {
	if err := validateAssumedLocalFlow(flow); err != nil {
		return nil, err
	}
	if !windowslocal.ValidSAMName(accountName) {
		return nil, ErrInvalidLocalAuthenticationAssumption
	}
	account, err := accounts.LookupByName(ctx, accountName)
	if err != nil {
		return nil, err
	}
	name, sid := account.Identity()
	if !windowslocal.ValidSAMName(name) {
		return nil, ErrInvalidLocalAuthenticationAssumption
	}
	return bindAssumedLocalAuthentication(flow, account, name, sid)
}
