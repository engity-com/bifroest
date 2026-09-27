//go:build !darwin

package environment

import "context"

func (*LocalRepository) willTargetAccountBeAccepted(Context) (bool, error) {
	return true, nil
}

func (*local) revalidateTargetAccount(context.Context) error {
	return nil
}
