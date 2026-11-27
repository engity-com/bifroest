package service

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
)

// Reusing a session never transfers its resources to a newer provider. In
// particular an unprovisioned/recreated container must use its original image,
// not silently acquire today's image under yesterday's immutable association.
// Return the lease separately so optional Environment interfaces remain intact.
func (this *service) ensureEnvironment(req environment.Request) (environment.Environment, func(), error) {
	release := func() {}
	if this.resources == nil || this.Watch != configuration.WatchModeReuse || req.Authorization().FindSession() == nil {
		env, err := this.environments.Ensure(req)
		return env, release, err
	}
	if !this.loginSessionCompatible(req.Authorization().FindSession()) {
		return nil, nil, errors.Permission.Newf("session is not compatible with the admitted configuration")
	}
	owner, release, err := this.retainSessionOwner(req.Authorization().FindSession())
	if err != nil {
		return nil, nil, err
	}
	if owner != this {
		accepted, err := this.environments.WillBeAccepted(req)
		if err != nil || !accepted {
			release()
			if err == nil {
				err = environment.ErrNotAcceptable
			}
			return nil, nil, err
		}
	}
	env, err := owner.environments.Ensure(req)
	if err != nil {
		release()
		return nil, nil, err
	}
	return env, release, nil
}
