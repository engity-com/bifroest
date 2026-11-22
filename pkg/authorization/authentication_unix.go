//go:build unix

package authorization

import (
	"github.com/engity-com/bifroest/pkg/authentication"
)

func (this *local) Authentication() (authentication.Identity, error) {
	if this.user == nil {
		return authentication.Identity{}, ErrAuthenticationUnavailable
	}
	return localAuthenticationIdentity(this.user.Name, this.user.Uid.String()), nil
}
