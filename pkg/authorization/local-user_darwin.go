//go:build darwin

package authorization

import "github.com/engity-com/bifroest/pkg/user"

type localUserAware interface {
	LocalUser() *user.User
}

func (this *local) LocalUser() *user.User { return this.user }

func LocalUserOf(auth Authorization) *user.User {
	if value, ok := auth.(localUserAware); ok {
		return value.LocalUser()
	}
	return nil
}
