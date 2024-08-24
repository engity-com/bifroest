//go:build windows

package user

import (
	"context"
	"fmt"
	"os/user"

	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/errors"
)

func init() {
	DefaultRepositoryProvider = &SharedRepositoryProvider[*WindowsRepository]{V: &WindowsRepository{}}
}

type WindowsRepository struct {
}

func (this *WindowsRepository) Init(_ context.Context) error {
	return nil
}

func (this *WindowsRepository) Close() error {
	return nil
}

func (this *WindowsRepository) Ensure(ctx context.Context, req *Requirement, _ *EnsureOpts) (u *User, res EnsureResult, err error) {
	name := req.Name
	uid := req.Uid

	if name != "" {
		u, err = this.LookupByName(ctx, name)
		if err != nil {
			return nil, EnsureResultError, err
		}
		if uid != nil && !uid.isEqualTo(&u.Uid) {
			return nil, EnsureResultError, ErrUserDoesNotFulfilRequirement
		}
		return u, EnsureResultUnchanged, nil
	}

	if uid != nil {
		u, err = this.LookupById(ctx, *uid)
		if err != nil {
			return nil, EnsureResultError, err
		}
		return u, EnsureResultUnchanged, nil

	}

	return nil, EnsureResultError, fmt.Errorf("required does neither define name nor UID")
}

func (this *WindowsRepository) EnsureGroup(context.Context, *GroupRequirement, *EnsureOpts) (*Group, EnsureResult, error) {
	return nil, EnsureResultError, ErrGroupDoesNotFulfilRequirement
}

func (this *WindowsRepository) LookupByName(_ context.Context, name string) (*User, error) {
	u, err := user.Lookup(name)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) || errors.Is(err, (*user.UnknownUserIdError)(nil)) {
		return nil, ErrNoSuchUser
	}
	if err != nil {
		return nil, err
	}
	var id Id
	if err := id.UnmarshalText([]byte(u.Uid)); err != nil {
		return nil, err
	}

	return &User{
		Name:        u.Username,
		DisplayName: u.Name,
		Uid:         id,
		HomeDir:     u.HomeDir,
	}, nil
}

func (this *WindowsRepository) LookupById(_ context.Context, id Id) (*User, error) {
	strId, err := id.MarshalText()
	if err != nil {
		return nil, err
	}
	u, err := user.LookupId(string(strId))
	if errors.Is(err, windows.ERROR_NONE_MAPPED) || errors.Is(err, (*user.UnknownUserIdError)(nil)) {
		return nil, ErrNoSuchUser
	}
	if err != nil {
		return nil, err
	}

	return &User{
		Name:        u.Username,
		DisplayName: u.Name,
		Uid:         id,
		HomeDir:     u.HomeDir,
	}, nil
}

func (this *WindowsRepository) LookupGroupByName(context.Context, string) (*Group, error) {
	return nil, ErrNoSuchGroup
}

func (this *WindowsRepository) LookupGroupById(context.Context, GroupId) (*Group, error) {
	return nil, ErrNoSuchGroup
}

func (this *WindowsRepository) DeleteById(context.Context, Id, *DeleteOpts) error {
	return fmt.Errorf("delete not supported on windows systems")
}

func (this *WindowsRepository) DeleteByName(context.Context, string, *DeleteOpts) error {
	return fmt.Errorf("delete not supported on windows systems")
}

func (this *WindowsRepository) ValidatePasswordById(context.Context, Id, string) (bool, error) {
	return false, fmt.Errorf("validate password not supported on windows systems")
}

func (this *WindowsRepository) ValidatePasswordByName(context.Context, string, string) (bool, error) {
	return false, fmt.Errorf("validate password not supported on windows systems")
}

func (this *WindowsRepository) DeleteGroupById(context.Context, GroupId, *DeleteOpts) error {
	return fmt.Errorf("delete not supported on windows systems")
}

func (this *WindowsRepository) DeleteGroupByName(context.Context, string, *DeleteOpts) error {
	return fmt.Errorf("delete not supported on windows systems")
}
