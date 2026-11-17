//go:build unix

package user

import (
	"context"
	"errors"
)

var (
	ErrPasswordAccountPolicyUnavailable = errors.New("native password account policy is unavailable")
	ErrPasswordAccountPolicyDenied      = errors.New("native password account policy denied")
)

// PasswordAccountPolicy contains current operator policy, never a password or a
// historical authorization snapshot. This is eligibility after an independent
// possession proof, not primary password authentication.
type PasswordAccountPolicy struct {
	AllowEmpty bool
}

// PasswordAccountPolicyChecker must inspect fresh native state and retain both
// name and UID. A repository's ordinary lookup is deliberately not sufficient.
type PasswordAccountPolicyChecker interface {
	CheckPasswordAccount(context.Context, string, Id, PasswordAccountPolicy) (*User, error)
}

func CheckPasswordAccount(ctx context.Context, repository Repository, name string, id Id, policy PasswordAccountPolicy) (*User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	checker, ok := repository.(PasswordAccountPolicyChecker)
	if !ok {
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	current, err := checker.CheckPasswordAccount(ctx, name, id, policy)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if current == nil || current.Name != name || current.Uid != id {
		return nil, ErrPasswordAccountPolicyDenied
	}
	return current, nil
}

// Forward the optional capability explicitly rather than losing it through the
// embedded Repository interface. Unsupported custom repositories stay closed.
func (this *sharedRepository[T]) CheckPasswordAccount(ctx context.Context, name string, id Id, policy PasswordAccountPolicy) (*User, error) {
	return CheckPasswordAccount(ctx, this.Repository, name, id, policy)
}
