//go:build !unix

package environment

import "context"

func (*LocalRepository) resolveTargetAccount(Context) (any, bool, error) {
	return nil, true, nil
}

func (*local) revalidateTargetAccount(context.Context) error {
	return nil
}
