//go:build unix && !darwin

package environment

import (
	"context"

	"github.com/engity-com/bifroest/pkg/user"
)

func (this *LocalRepository) willBeAcceptedAtAdmission(ctx Context) (bool, error) {
	_, accepted, err := this.willBeAccepted(ctx)
	return accepted, err
}

func (this *LocalRepository) resolveTargetAccount(ctx Context) (any, bool, error) {
	return nil, true, nil
}

func (*LocalRepository) localTokenAuthorizationKind(Request) string { return "" }

func (*LocalRepository) isCurrentTargetAccount(any, *user.User) bool { return true }

func (*LocalRepository) acceptedTargetAccount(any, *user.User) (*user.User, bool, error) {
	return nil, true, nil
}

func (*LocalRepository) validateCurrentTargetAccount(Context, *user.User) (any, bool, error) {
	return nil, true, nil
}

func (*LocalRepository) withValidatedTargetAccountRequest(request Request, _ *user.User) Request {
	return request
}

func (*LocalRepository) validateProvisionedTargetAccount(Request, *user.User) error { return nil }

func (*LocalRepository) isStoredTargetAccountAccepted(context.Context, *user.User, *localToken) (bool, error) {
	return true, nil
}

func (*LocalRepository) isTargetAccountAccepted(*user.User) (bool, error) { return true, nil }

func (*local) revalidateTargetAccount(context.Context) error { return nil }
