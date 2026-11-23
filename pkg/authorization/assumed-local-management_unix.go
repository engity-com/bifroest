//go:build unix

package authorization

import (
	"context"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/user"
)

// UnixAccountWithManagement resolves the same local managed-group selector and
// name-based membership decision as the production service, using only the bound
// account facts. It returns a new immutable view; the authentication binding is
// not modified. No native context resolver or target-account inventory is used.
// A missing/non-local management configuration yields the production nil field;
// missing facts needed by an applicable selector remain errors.
func (this *AssumedLocalAuthentication) UnixAccountWithManagement(ctx context.Context, flow *configuration.Flow) (LocalAccountView, error) {
	if err := this.validateManagementFlow(flow); err != nil {
		return nil, err
	}
	account, ok := this.account.source.(*user.Snapshot)
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
	managed, err := user.IsInGroupByName(account, group)
	if canceled := ctx.Err(); canceled != nil {
		return nil, errors.System.Newf("%w", canceled)
	}
	if err != nil {
		return nil, err
	}
	return localAccountWithManagement{account: this.account, managed: &managed}, nil
}
