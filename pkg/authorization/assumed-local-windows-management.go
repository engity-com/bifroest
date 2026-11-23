//go:build unix || windows

package authorization

import (
	"context"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

// WindowsAccountWithManagement overlays the current flow's managed-group
// observation using direct member SIDs, never native lookups or inferred account
// name membership. No local environment means present managed=nil; an applicable
// but unmodeled group is an error, not managed=false.
func (this *AssumedLocalAuthentication) WindowsAccountWithManagement(ctx context.Context, flow *configuration.Flow, groups *windowslocal.MemoryGroupLookup) (LocalAccountView, error) {
	if err := this.validateManagementFlow(flow); err != nil {
		return nil, err
	}
	account, ok := this.account.source.(*windowslocal.AccountSnapshot)
	if !ok {
		return nil, ErrInvalidLocalAuthenticationAssumption
	}
	if ctx == nil {
		return nil, errors.System.Newf("local account management context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.System.Newf("%w", err)
	}
	group, available := (configuration.Flows{*flow}).LocalManagedGroupFor(this.flow)
	if !available {
		return localAccountWithManagement{account: this.account}, nil
	}
	_, sid := account.Identity()
	managed, err := groups.IsMember(ctx, group, sid)
	if err != nil {
		return nil, err
	}
	return localAccountWithManagement{account: this.account, managed: &managed}, nil
}
