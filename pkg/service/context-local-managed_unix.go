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
	for _, flow := range this.service.Configuration.Flows {
		if flow.Name != name {
			continue
		}
		local, ok := flow.Environment.V.(*configuration.EnvironmentLocal)
		if !ok || local.ManagedGroup == "" {
			return false, false, nil
		}
		if account.Group.Name == local.ManagedGroup {
			return true, true, nil
		}
		for _, group := range account.Groups {
			if group.Name == local.ManagedGroup {
				return true, true, nil
			}
		}
		return false, true, nil
	}
	return false, false, nil
}
