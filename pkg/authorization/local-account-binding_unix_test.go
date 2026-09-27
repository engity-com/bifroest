//go:build unix

package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/user"
)

func TestUnixRequestedLocalAccountBindingUsesUid(t *testing.T) {
	requested := &user.User{Name: "alice", Uid: 501}
	authorizer := &LocalAuthorizer{userRepository: &unixLocalAccountTestRepository{
		lookupByName: func(context.Context, string) (*user.User, error) { return requested, nil },
	}}

	bound, err := authorizer.isRequestedAccountBound(context.Background(), "alias", nil, &user.User{Name: "canonical", Uid: 501})
	require.NoError(t, err)
	require.True(t, bound)

	bound, err = authorizer.isRequestedAccountBound(context.Background(), "alias", nil, &user.User{Name: "mallory", Uid: 502})
	require.NoError(t, err)
	require.False(t, bound)
}

func TestUnixLocalRestoreRejectsChangedOrIncompleteIdentity(t *testing.T) {
	tests := map[string]struct {
		token        string
		lookupByName func(context.Context, string) (*user.User, error)
		lookupById   func(context.Context, user.Id) (*user.User, error)
	}{
		"missing name": {
			token: `{"user":{"uid":501}}`,
			lookupById: func(context.Context, user.Id) (*user.User, error) {
				return &user.User{Name: "alice", Uid: 501}, nil
			},
		},
		"missing UID": {
			token: `{"user":{"name":"alice"}}`,
			lookupByName: func(context.Context, string) (*user.User, error) {
				return &user.User{Name: "alice", Uid: 501}, nil
			},
		},
		"name reused": {
			token: `{"user":{"name":"alice","uid":501}}`,
			lookupByName: func(context.Context, string) (*user.User, error) {
				return &user.User{Name: "alice", Uid: 502}, nil
			},
		},
		"UID remapped": {
			token: `{"user":{"name":"alice","uid":501}}`,
			lookupByName: func(context.Context, string) (*user.User, error) {
				return &user.User{Name: "alice", Uid: 501}, nil
			},
			lookupById: func(context.Context, user.Id) (*user.User, error) {
				return &user.User{Name: "bob", Uid: 501}, nil
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			authorizer := &LocalAuthorizer{
				flow: "flow",
				userRepository: &unixLocalAccountTestRepository{
					lookupByName: test.lookupByName,
					lookupById:   test.lookupById,
				},
			}
			sess := &authorizationRestoreTestSession{flow: "flow", token: []byte(test.token)}

			actual, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{})
			require.Nil(t, actual)
			require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
		})
	}
}

type unixLocalAccountTestRepository struct {
	user.CloseableRepository
	lookupByName func(context.Context, string) (*user.User, error)
	lookupById   func(context.Context, user.Id) (*user.User, error)
}

func (this *unixLocalAccountTestRepository) LookupByName(ctx context.Context, name string) (*user.User, error) {
	if this.lookupByName == nil {
		return nil, user.ErrNoSuchUser
	}
	return this.lookupByName(ctx, name)
}

func (this *unixLocalAccountTestRepository) LookupById(ctx context.Context, id user.Id) (*user.User, error) {
	if this.lookupById == nil {
		return nil, user.ErrNoSuchUser
	}
	return this.lookupById(ctx, id)
}
