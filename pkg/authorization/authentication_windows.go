//go:build windows

package authorization

import "github.com/engity-com/bifroest/pkg/authentication"

func (this *local) Authentication() (authentication.Identity, error) {
	return localAuthenticationIdentity(this.user.Name, this.user.SID), nil
}
