//go:build windows

package environment

type localToken struct {
	Version                  uint8               `json:"version,omitempty"`
	User                     windowsLocalAccount `json:"user"`
	PortForwardingAllowed    bool                `json:"portForwardingAllowed"`
	Managed                  bool                `json:"managed,omitempty"`
	ManagedGroup             string              `json:"managedGroup,omitempty"`
	ManagedGroupSID          string              `json:"managedGroupSid,omitempty"`
	AllowSystemUsers         bool                `json:"allowSystemUsers,omitempty"`
	DeleteOnDispose          bool                `json:"deleteOnDispose,omitempty"`
	DeleteProfileOnDispose   bool                `json:"deleteProfileOnDispose,omitempty"`
	KillProcessesOnDispose   bool                `json:"killProcessesOnDispose,omitempty"`
	ProcessesKilledOnDispose bool                `json:"processesKilledOnDispose,omitempty"`
}

func localWindowsCleanupAllowed(account windowsLocalAccount, allowSystemUsers, requested bool) bool {
	return requested && (!localSAMProtectedAccount(account) || allowSystemUsers)
}

func (this *LocalRepository) newLocalToken(req Request, account windowsLocalAccount, managed, allowSystemUsers bool) (*localToken, error) {
	fail := func(err error) (*localToken, error) {
		return nil, err
	}

	portForwardingAllowed, err := this.conf.PortForwardingAllowed.Render(req)
	if err != nil {
		return fail(err)
	}
	ctx := localTemplateContext{Request: req, user: account, managed: managed}
	deleteOnDispose, err := this.conf.DeleteOnDispose.Render(ctx)
	if err != nil {
		return fail(err)
	}
	var groupSID string
	if managed {
		groupSID, err = localSAMGroupSID(this.conf.ManagedGroup)
		if err != nil {
			return fail(err)
		}
	}
	delete := localWindowsCleanupAllowed(account, allowSystemUsers, deleteOnDispose)
	deleteProfile := false
	if delete {
		if deleteProfile, err = this.conf.DeleteHomeTogetherWithUser.Render(ctx); err != nil {
			return fail(err)
		}
	}
	killProcesses, err := this.conf.KillProcessesOnDispose.Render(ctx)
	if err != nil {
		return fail(err)
	}

	return &localToken{
		Version:                2,
		User:                   account,
		PortForwardingAllowed:  portForwardingAllowed,
		Managed:                managed,
		ManagedGroup:           this.conf.ManagedGroup,
		ManagedGroupSID:        groupSID,
		AllowSystemUsers:       allowSystemUsers,
		DeleteOnDispose:        delete,
		DeleteProfileOnDispose: deleteProfile,
		KillProcessesOnDispose: localWindowsCleanupAllowed(account, allowSystemUsers, killProcesses),
	}, nil
}
