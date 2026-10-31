//go:build windows

package authorization

import "github.com/engity-com/bifroest/pkg/authentication"

func (this *local) Authentication() (authentication.Identity, error) {
	return authentication.Identity{Principal: this.user.Name, Issuer: "local", Subject: this.user.SID}, nil
}
