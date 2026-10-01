//go:build !unix

package environment

import "context"

func (this *LocalRepository) willBeAcceptedAtAdmission(ctx Context) (bool, error) {
	_, accepted, err := this.willBeAccepted(ctx)
	return accepted, err
}

func (*LocalRepository) resolveTargetAccount(Context) (any, bool, error) {
	return nil, true, nil
}

func (*local) revalidateTargetAccount(context.Context) error {
	return nil
}
