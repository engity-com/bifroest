//go:build unix

package authorization

import (
	"context"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/user"
)

func (this *LocalAuthorizer) isRequestedAccountBound(ctx context.Context, requestedName string, requested, authenticated *user.User) (bool, error) {
	if requested == nil {
		var err error
		requested, err = this.userRepository.LookupByName(ctx, requestedName)
		if errors.Is(err, user.ErrNoSuchUser) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	return requested != nil && authenticated != nil && requested.Uid == authenticated.Uid, nil
}

func (this *LocalAuthorizer) isRestoredAccountBound(ctx context.Context, token *localTokenUser, byName *user.User) (bool, error) {
	if token == nil || token.Name == "" || token.Uid == nil || byName == nil ||
		byName.Name != token.Name || byName.Uid != *token.Uid {
		return false, nil
	}
	byUid, err := this.userRepository.LookupById(ctx, *token.Uid)
	if errors.Is(err, user.ErrNoSuchUser) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return byUid != nil && byUid.Name == token.Name && byUid.Uid == *token.Uid, nil
}
