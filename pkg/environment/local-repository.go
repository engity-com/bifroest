package environment

import (
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	_ = RegisterRepository(NewLocalRepository)
)

func (this *LocalRepository) WillBeAccepted(ctx Context) (ok bool, err error) {
	return LocalLoginAllowed(ctx, this.conf)
}

// LocalLoginAllowed shares the production pre-target admission decision without
// constructing a repository, session, native account or provisioning capability.
// A true result is this gate only, not successful native login or full access.
func LocalLoginAllowed(ctx Context, conf *configuration.EnvironmentLocal) (bool, error) {
	if conf == nil || nilLocalTargetDependency(ctx) || ctx.Context() == nil {
		return false, errors.System.Newf("local login policy context/configuration is unavailable")
	}
	ok, err := conf.LoginAllowed.Render(ctx)
	if err != nil {
		return false, fmt.Errorf("cannot evaluate if user is allowed to login or not: %w", err)
	}
	return ok, nil
}

func (this *LocalRepository) Cleanup(context.Context, *CleanupOpts) error {
	return nil
}
