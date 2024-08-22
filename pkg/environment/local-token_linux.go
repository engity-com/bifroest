//go:build linux

package environment

import "github.com/engity-com/bifroest/pkg/user"

type localTokenUser struct {
	Name                   string   `json:"name,omitempty"`
	Uid                    *user.Id `json:"uid,omitempty"`
	Managed                bool     `json:"managed,omitempty"`
	DeleteOnDispose        bool     `json:"deleteOnDispose,omitempty"`
	DeleteHomeDirOnDispose bool     `json:"deleteHomeDirOnDispose,omitempty"`
	KillProcessesOnDispose bool     `json:"killProcessesOnDispose,omitempty"`
}

func (this *LocalRepository) newLocalToken(u *user.User, req Request, userIsManaged bool) (*localToken, error) {
	fail := func(err error) (*localToken, error) {
		return nil, err
	}

	portForwardingAllowed, err := this.conf.PortForwardingAllowed.Render(req)
	if err != nil {
		return fail(err)
	}

	deleteOnDispose, err := this.conf.Dispose.DeleteManagedUser.Render(req)
	if err != nil {
		return fail(err)
	}
	deleteHomeDirOnDispose, err := this.conf.Dispose.DeleteManagedUserHomeDir.Render(req)
	if err != nil {
		return fail(err)
	}
	killProcessesOnDispose, err := this.conf.Dispose.KillManagedUserProcesses.Render(req)
	if err != nil {
		return fail(err)
	}

	return &localToken{
		localTokenUser{
			u.Name,
			common.P(u.Uid),
			userIsManaged,
			deleteOnDispose && userIsManaged,
			deleteHomeDirOnDispose && deleteOnDispose && userIsManaged,
			killProcessesOnDispose && userIsManaged,
		},
		portForwardingAllowed,
	}, nil
}
