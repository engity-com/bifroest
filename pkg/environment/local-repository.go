package environment

import (
	"fmt"
)

var (
	_ = RegisterRepository(NewLocalRepository)
)

func (this *LocalRepository) WillBeAccepted(req Request) (ok bool, err error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	if ok, err = this.conf.LoginAllowed.Render(req); err != nil {
		return fail(fmt.Errorf("cannot evaluate if user is allowed to login or not: %w", err))
	}

	return ok, nil
}
