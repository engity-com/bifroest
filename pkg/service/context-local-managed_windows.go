//go:build windows

package service

import (
	"errors"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func (this *environmentContext) ResolveLocalWindowsUserManaged(name configuration.FlowName, account windowslocal.Account) (bool, bool, error) {
	if this.service == nil || this.service.Service == nil || this.authorization == nil ||
		this.authorization.Flow() != name || account.Name == "" || account.SID == "" {
		return false, false, nil
	}
	group, available := this.service.Configuration.Flows.LocalManagedGroupFor(name)
	if !available {
		return false, false, nil
	}
	managed, err := environment.IsLocalWindowsAccountInGroup(account.Name, account.SID, group, true)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return false, true, nil
	}
	return managed, true, err
}
