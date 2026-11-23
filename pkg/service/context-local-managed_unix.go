//go:build unix

package service

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/user"
)

func (this *environmentContext) ResolveLocalUserManaged(name configuration.FlowName, account *user.User) (bool, bool, error) {
	if this.service == nil || this.service.Service == nil || this.authorization == nil ||
		this.authorization.Flow() != name || account == nil {
		return false, false, nil
	}
	group, available := this.service.Configuration.Flows.LocalManagedGroupFor(name)
	if !available {
		return false, false, nil
	}
	managed, err := user.IsInGroupByName(account, group)
	return managed, true, err
}
