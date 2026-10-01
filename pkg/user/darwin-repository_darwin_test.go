//go:build darwin

package user

import (
	"context"
	"errors"
	osuser "os/user"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestDarwinRepositoryLookupUser(t *testing.T) {
	tests := map[string]struct {
		lookup func(context.Context, *DarwinRepository) (*User, error)
	}{
		"by canonicalized name": {
			lookup: func(ctx context.Context, repository *DarwinRepository) (*User, error) {
				return repository.LookupByName(ctx, "alice.alias")
			},
		},
		"by id": {
			lookup: func(ctx context.Context, repository *DarwinRepository) (*User, error) {
				return repository.LookupById(ctx, 501)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			nativeUser := &osuser.User{
				Uid:      "501",
				Gid:      "20",
				Username: "alice",
				Name:     "Alice Example",
				HomeDir:  "/Users/alice",
			}
			groups := map[string]*osuser.Group{
				"20": {Gid: "20", Name: "staff"},
				"12": {Gid: "12", Name: "everyone"},
				"80": {Gid: "80", Name: "admin"},
			}
			repository := &DarwinRepository{
				lookupUserByName: func(name string) (*osuser.User, error) {
					require.Equal(t, "alice.alias", name)
					return nativeUser, nil
				},
				lookupUserById: func(id string) (*osuser.User, error) {
					require.Equal(t, "501", id)
					return nativeUser, nil
				},
				lookupGroupById: func(id string) (*osuser.Group, error) {
					group, found := groups[id]
					require.True(t, found)
					return group, nil
				},
				lookupGroupIds: func(user *osuser.User) ([]string, error) {
					require.Same(t, nativeUser, user)
					return []string{"20", "12", "80", "12"}, nil
				},
				lookupLoginShell: func(name string) (string, error) {
					require.Equal(t, "alice", name)
					return "/bin/zsh", nil
				},
			}

			actual, err := test.lookup(context.Background(), repository)
			require.NoError(t, err)
			require.Equal(t, &User{
				Name:        "alice",
				DisplayName: "Alice Example",
				Uid:         501,
				Group:       Group{Gid: 20, Name: "staff"},
				Groups: Groups{
					{Gid: 12, Name: "everyone"},
					{Gid: 80, Name: "admin"},
				},
				Shell:   "/bin/zsh",
				HomeDir: "/Users/alice",
			}, actual)
		})
	}
}

func TestDarwinRepositoryResolvesCurrentDirectoryServicesIdentity(t *testing.T) {
	current, err := osuser.Current()
	require.NoError(t, err)
	uid, err := strconv.ParseUint(current.Uid, 10, 32)
	require.NoError(t, err)

	repository := &DarwinRepository{}
	byName, err := repository.LookupByName(t.Context(), current.Username)
	require.NoError(t, err)
	byID, err := repository.LookupById(t.Context(), Id(uid))
	require.NoError(t, err)
	require.Equal(t, byName, byID)
	require.Equal(t, current.Username, byName.Name)
	require.Equal(t, current.HomeDir, byName.HomeDir)
	require.NotEmpty(t, byName.Shell)

	expectedGroupIDs, err := current.GroupIds()
	require.NoError(t, err)
	expected := make(map[GroupId]struct{}, len(expectedGroupIDs))
	for _, raw := range expectedGroupIDs {
		value, err := strconv.ParseUint(raw, 10, 32)
		require.NoError(t, err)
		expected[GroupId(value)] = struct{}{}
	}
	actual := map[GroupId]struct{}{byName.Group.Gid: {}}
	for _, group := range byName.Groups {
		actual[group.Gid] = struct{}{}
	}
	require.Equal(t, expected, actual)
}

func TestDarwinRepositoryLookupGroup(t *testing.T) {
	repository := &DarwinRepository{
		lookupGroupByName: func(name string) (*osuser.Group, error) {
			require.Equal(t, "staff", name)
			return &osuser.Group{Gid: "20", Name: "staff"}, nil
		},
		lookupGroupById: func(id string) (*osuser.Group, error) {
			require.Equal(t, "20", id)
			return &osuser.Group{Gid: "20", Name: "staff"}, nil
		},
	}

	byName, err := repository.LookupGroupByName(context.Background(), "staff")
	require.NoError(t, err)
	require.Equal(t, &Group{Gid: 20, Name: "staff"}, byName)

	byId, err := repository.LookupGroupById(context.Background(), 20)
	require.NoError(t, err)
	require.Equal(t, &Group{Gid: 20, Name: "staff"}, byId)
}

func TestDarwinRepositoryMapsMissingAccounts(t *testing.T) {
	repository := &DarwinRepository{
		lookupUserByName: func(string) (*osuser.User, error) {
			return nil, osuser.UnknownUserError("missing")
		},
		lookupGroupByName: func(string) (*osuser.Group, error) {
			return nil, osuser.UnknownGroupError("missing")
		},
	}

	actualUser, err := repository.LookupByName(context.Background(), "missing")
	require.Nil(t, actualUser)
	require.ErrorIs(t, err, ErrNoSuchUser)

	actualGroup, err := repository.LookupGroupByName(context.Background(), "missing")
	require.Nil(t, actualGroup)
	require.ErrorIs(t, err, ErrNoSuchGroup)
}

func TestDarwinRepositoryReportsLookupFailures(t *testing.T) {
	expected := errors.New("directory service unavailable")
	repository := &DarwinRepository{
		lookupUserByName: func(string) (*osuser.User, error) {
			return nil, expected
		},
	}

	actual, err := repository.LookupByName(context.Background(), "alice")
	require.Nil(t, actual)
	require.ErrorIs(t, err, expected)
	require.True(t, berrors.System.IsErr(err))
}

func TestDarwinRepositoryInitAndCloseAreSideEffectFree(t *testing.T) {
	repository := &DarwinRepository{
		lookupUserByName: func(string) (*osuser.User, error) {
			panic("lookup must not be called")
		},
		lookupGroupByName: func(string) (*osuser.Group, error) {
			panic("lookup must not be called")
		},
		lookupLoginShell: func(string) (string, error) {
			panic("lookup must not be called")
		},
	}

	require.NoError(t, repository.Init(context.Background()))
	require.NoError(t, repository.Close())
	require.NoError(t, repository.Close())
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, repository.Init(canceled), context.Canceled)
}

func TestDarwinDefaultRepositoryProvider(t *testing.T) {
	_, ok := DefaultRepositoryProvider.(*SharedRepositoryProvider[*DarwinRepository])
	require.True(t, ok)

	repository, err := DefaultRepositoryProvider.Create(context.Background())
	require.NoError(t, err)
	require.Implements(t, (*identityCleanupRepository)(nil), repository)
	require.Implements(t, (*absentIdentityHomeCleanupRepository)(nil), repository)
	require.NoError(t, repository.Close())
}

func TestDarwinRepositoryPasswordValidationUnsupported(t *testing.T) {
	repository := &DarwinRepository{}
	ctx := context.Background()

	valid, err := repository.ValidatePasswordById(ctx, 501, "secret")
	require.False(t, valid)
	require.ErrorIs(t, err, ErrDarwinPasswordValidationUnsupported)

	valid, err = repository.ValidatePasswordByName(ctx, "alice", "secret")
	require.False(t, valid)
	require.ErrorIs(t, err, ErrDarwinPasswordValidationUnsupported)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	valid, err = repository.ValidatePasswordByName(canceled, "alice", "secret")
	require.False(t, valid)
	require.ErrorIs(t, err, context.Canceled)
}
