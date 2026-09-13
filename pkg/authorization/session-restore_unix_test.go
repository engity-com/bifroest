//go:build unix

package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalRestoreClassifiesRemovedUserAsUnusable(t *testing.T) {
	authorizer := &LocalAuthorizer{flow: "flow", userRepository: &authorizationRestoreTestUserRepository{}}
	sess := &authorizationRestoreTestSession{flow: "flow", token: []byte(`{"user":{"name":"removed"}}`)}

	_, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{})

	require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
	require.Zero(t, sess.setTokenCalls)
}

func TestLocalRestoreAutoCleanupRemovesTokenOfRemovedUser(t *testing.T) {
	authorizer := &LocalAuthorizer{flow: "flow", userRepository: &authorizationRestoreTestUserRepository{}}
	sess := &authorizationRestoreTestSession{flow: "flow", token: []byte(`{"user":{"name":"removed"}}`)}
	autoCleanup := true

	_, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{AutoCleanUpAllowed: &autoCleanup})

	require.ErrorIs(t, err, ErrNoSuchAuthorization)
	require.Equal(t, 1, sess.setTokenCalls)
	require.Empty(t, sess.token)
}

type authorizationRestoreTestUserRepository struct {
	user.CloseableRepository
}

func (*authorizationRestoreTestUserRepository) LookupByName(context.Context, string) (*user.User, error) {
	return nil, user.ErrNoSuchUser
}
