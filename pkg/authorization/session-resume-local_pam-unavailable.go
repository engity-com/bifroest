//go:build unix && (!linux || !cgo || without_pam)

package authorization

import (
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

func (*LocalAuthorizer) checkPamPasswordAccount(SessionResumeRequest, string, user.Id, user.PasswordAccountPolicy) (*user.User, sys.EnvVars, error) {
	return nil, nil, ErrSessionResumeUnavailable
}
