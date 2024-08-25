//go:build windows

package user

import (
	"context"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestWindowsRepository_Lifecycle(t *testing.T) {
	instance := &WindowsRepository{}

	actualErr := instance.Init(context.Background())
	require.NoError(t, actualErr)

	actualErr = instance.Close()
	require.NoError(t, actualErr)
}

func TestWindowsRepository_DeleteById(t *testing.T) {
	instance := newWindowsRepository(t)
	id := sidOf(t, "S-1-1-21-1")

	actualErr := instance.DeleteById(context.Background(), id, nil)
	assert.ErrorContains(t, actualErr, "delete not supported on windows systems")
}

func TestWindowsRepository_DeleteByName(t *testing.T) {
	instance := newWindowsRepository(t)

	actualErr := instance.DeleteByName(context.Background(), "test", nil)
	assert.ErrorContains(t, actualErr, "delete not supported on windows systems")
}

func TestWindowsRepository_DeleteGroupById(t *testing.T) {
	instance := newWindowsRepository(t)

	actualErr := instance.DeleteGroupById(context.Background(), "test", nil)
	assert.ErrorContains(t, actualErr, "delete not supported on windows systems")
}

func TestWindowsRepository_DeleteGroupByName(t *testing.T) {
	instance := newWindowsRepository(t)

	actualErr := instance.DeleteGroupByName(context.Background(), "test", nil)
	assert.ErrorContains(t, actualErr, "delete not supported on windows systems")
}

func TestWindowsRepository_Ensure(t *testing.T) {
	instance := newWindowsRepository(t)
	current := currentUser(t)
	currentAsUser := User{
		Name:        current.Username,
		DisplayName: current.Name,
		Uid:         uidOfUser(t, current),
		HomeDir:     current.HomeDir,
	}

	cases := []struct {
		name        string
		requirement Requirement
		expected    *User
		expectedRes EnsureResult
		expectedErr string
	}{{
		name: "by-name-exists",
		requirement: Requirement{
			Name: current.Username,
		},
		expected:    &currentAsUser,
		expectedRes: EnsureResultUnchanged,
	}, {
		name: "by-id-exists",
		requirement: Requirement{
			Uid: common.P(uidOfUser(t, current)),
		},
		expected:    &currentAsUser,
		expectedRes: EnsureResultUnchanged,
	}, {
		name: "by-both-exists",
		requirement: Requirement{
			Name: current.Username,
			Uid:  common.P(uidOfUser(t, current)),
		},
		expected:    &currentAsUser,
		expectedRes: EnsureResultUnchanged,
	}, {
		name: "by-both-but-different",
		requirement: Requirement{
			Name: current.Username,
			Uid:  common.P(sidOf(t, "S-1-1-21-1")),
		},
		expectedRes: EnsureResultError,
		expectedErr: ErrUserDoesNotFulfilRequirement.Error(),
	}, {
		name: "by-name-absent",
		requirement: Requirement{
			Name: "does not exist",
		},
		expectedRes: EnsureResultError,
		expectedErr: ErrNoSuchUser.Error(),
	}, {
		name: "by-id-absent",
		requirement: Requirement{
			Uid: common.P(sidOf(t, "S-1-1-21-1")),
		},
		expectedRes: EnsureResultError,
		expectedErr: ErrNoSuchUser.Error(),
	}, {
		name:        "by-nothing",
		requirement: Requirement{},
		expectedRes: EnsureResultError,
		expectedErr: "required does neither define name nor UID",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, actualRes, actualErr := instance.Ensure(context.Background(), &c.requirement, nil)
			if c.expectedErr != "" {
				require.EqualError(t, actualErr, c.expectedErr)
			} else {
				require.NoError(t, actualErr)
			}
			assert.Equal(t, c.expectedRes, actualRes)
			assert.Equal(t, c.expected, actual)
		})
	}
}

func TestWindowsRepository_EnsureGroup(t *testing.T) {
	instance := newWindowsRepository(t)

	actual, actualRes, actualErr := instance.EnsureGroup(context.Background(), &GroupRequirement{}, nil)
	assert.ErrorIs(t, actualErr, ErrGroupDoesNotFulfilRequirement)
	assert.Equal(t, EnsureResultError, actualRes)
	assert.Nil(t, actual)
}

func TestWindowsRepository_LookupByName(t *testing.T) {
	instance := newWindowsRepository(t)

	current := currentUser(t)
	actual, actualErr := instance.LookupByName(context.Background(), current.Username)
	require.NoError(t, actualErr)

	assert.NotNil(t, actual)
	assert.Equal(t, current.Username, actual.Name)
	assert.Equal(t, current.Uid, actual.Uid.String())
	assert.Equal(t, current.HomeDir, actual.HomeDir)
}

func TestWindowsRepository_LookupById(t *testing.T) {
	instance := newWindowsRepository(t)

	current := currentUser(t)
	actual, actualErr := instance.LookupById(context.Background(), uidOfUser(t, current))
	require.NoError(t, actualErr)

	assert.NotNil(t, actual)
	assert.Equal(t, current.Username, actual.Name)
	assert.Equal(t, current.Uid, actual.Uid.String())
	assert.Equal(t, current.HomeDir, actual.HomeDir)
}

func TestWindowsRepository_LookupGroupById(t *testing.T) {
	instance := newWindowsRepository(t)

	actual, actualErr := instance.LookupGroupById(context.Background(), "123")
	assert.ErrorIs(t, actualErr, ErrNoSuchGroup)
	assert.Nil(t, actual)
}

func TestWindowsRepository_LookupGroupByName(t *testing.T) {
	instance := newWindowsRepository(t)

	actual, actualErr := instance.LookupGroupByName(context.Background(), "123")
	assert.ErrorIs(t, actualErr, ErrNoSuchGroup)
	assert.Nil(t, actual)
}

func TestWindowsRepository_ValidatePasswordById(t *testing.T) {
	instance := newWindowsRepository(t)
	uid := currentUid(t)

	actual, actualErr := instance.ValidatePasswordById(context.Background(), uid, "test")
	assert.ErrorContains(t, actualErr, "validate password not supported on windows systems")
	assert.False(t, actual)
}

func TestWindowsRepository_ValidatePasswordByName(t *testing.T) {
	instance := newWindowsRepository(t)

	actual, actualErr := instance.ValidatePasswordByName(context.Background(), "demo132", "A2efh#fA$k^9o")
	assert.ErrorContains(t, actualErr, "validate password not supported on windows systems")
	assert.False(t, actual)

}

func currentUid(t *testing.T) Id {
	current := currentUser(t)

	return uidOfUser(t, current)
}

func uidOfUser(t *testing.T, v *user.User) Id {
	return sidOf(t, v.Uid)
}

func sidOf(t *testing.T, plain string) Id {
	var sid Id
	require.NoError(t, sid.Set(plain))
	return sid
}

func newWindowsRepository(t *testing.T) *WindowsRepository {
	instance := &WindowsRepository{}
	assert.NoError(t, instance.Init(context.Background()))
	t.Cleanup(func() {
		_ = instance.Close()
	})
	return instance
}

func currentUser(t *testing.T) *user.User {
	current, err := user.Current()
	require.NoError(t, err)
	return current
}
