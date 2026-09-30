//go:build unix

package environment

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/user"
)

type localToken struct {
	Version               uint8          `json:"version,omitempty"`
	User                  localTokenUser `json:"user"`
	PortForwardingAllowed bool           `json:"portForwardingAllowed"`
}

type localTokenUser struct {
	Name                       string   `json:"name,omitempty"`
	Uid                        *user.Id `json:"uid,omitempty"`
	HomeDir                    string   `json:"homeDir,omitempty"`
	Managed                    bool     `json:"managed,omitempty"`
	AllowSystemUsers           bool     `json:"allowSystemUsers,omitempty"`
	DeleteOnDispose            bool     `json:"deleteOnDispose,omitempty"`
	DeleteHomeTogetherWithUser bool     `json:"deleteHomeTogetherWithUser,omitempty"`
	KillProcessesOnDispose     bool     `json:"killProcessesOnDispose,omitempty"`
	ProcessesKilledOnDispose   bool     `json:"processesKilledOnDispose,omitempty"`
}

func (this *LocalRepository) newLocalToken(u *user.User, req Request, managed, allowSystemUsers bool) (*localToken, error) {
	fail := func(err error) (*localToken, error) {
		return nil, err
	}

	portForwardingAllowed, err := this.conf.PortForwardingAllowed.Render(req)
	if err != nil {
		return fail(err)
	}
	ctx := localTemplateContext{Request: req, user: u, managed: managed}

	deleteOnDispose, err := this.conf.DeleteOnDispose.Render(ctx)
	if err != nil {
		return fail(err)
	}
	killProcessesOnDispose, err := this.conf.KillProcessesOnDispose.Render(ctx)
	if err != nil {
		return fail(err)
	}
	allowed := u.Uid != 0 || allowSystemUsers
	deleteHomeTogetherWithUser := false
	if deleteOnDispose && allowed {
		if deleteHomeTogetherWithUser, err = this.conf.DeleteHomeTogetherWithUser.Render(ctx); err != nil {
			return fail(err)
		}
	}

	return &localToken{
		Version: 2,
		User: localTokenUser{
			Name:                       u.Name,
			Uid:                        common.P(u.Uid),
			HomeDir:                    u.HomeDir,
			Managed:                    managed,
			AllowSystemUsers:           allowSystemUsers,
			DeleteOnDispose:            deleteOnDispose && allowed,
			DeleteHomeTogetherWithUser: deleteHomeTogetherWithUser,
			KillProcessesOnDispose:     killProcessesOnDispose && allowed,
		},
		PortForwardingAllowed: portForwardingAllowed,
	}, nil
}
