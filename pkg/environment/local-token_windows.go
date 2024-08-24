//go:build windows

package environment

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/user"
)

type localTokenUser struct {
	Name  string   `json:"name,omitempty"`
	Uid   *user.Id `json:"uid,omitempty"`
	Shell string   `json:"shell,omitempty"`
}

func (this *LocalRepository) newLocalToken(u *user.User, req Request, _ bool) (*localToken, error) {
	fail := func(err error) (*localToken, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*localToken, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	portForwardingAllowed, err := this.conf.PortForwardingAllowed.Render(req)
	if err != nil {
		return fail(err)
	}

	shell, err := this.conf.User.Shell.Render(req)
	if err != nil {
		return failf("cannot render user's shell: %w", err)
	}

	return &localToken{
		localTokenUser{
			u.Name,
			common.P(u.Uid),
			shell,
		},
		portForwardingAllowed,
	}, nil
}
