//go:build unix

package authorization

import (
	"strconv"

	"github.com/engity-com/bifroest/pkg/authentication"
)

func (this *local) Authentication() (authentication.Identity, error) {
	if this.user == nil {
		return authentication.Identity{}, ErrAuthenticationUnavailable
	}
	return authentication.Identity{
		Principal: this.user.Name, Issuer: "local", Subject: strconv.FormatUint(uint64(this.user.Uid), 10),
	}, nil
}
