//go:build unix && !darwin

package environment

import "github.com/engity-com/bifroest/pkg/user"

func (*LocalRepository) isTargetAccountAccepted(*user.User) (bool, error) {
	return true, nil
}

func (*LocalRepository) isStoredTargetAccountAccepted(*user.User, *localToken) (bool, error) {
	return true, nil
}
