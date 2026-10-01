//go:build darwin

package environment

import (
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/user"
)

func (this *LocalRepository) lookupTargetAccount(ctx Context) (*user.User, error) {
	target, err := this.lookupUserBy(ctx)
	if !errors.Is(err, user.ErrNoSuchUser) {
		return target, err
	}
	create, renderErr := this.conf.CreateIfAbsent.Render(ctx)
	if renderErr != nil {
		return nil, renderErr
	}
	if create {
		return nil, nil
	}
	return nil, err
}

func acceptLegacyEnvironmentTokenWithoutAuthorizationKind() bool {
	return false
}
