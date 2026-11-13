package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrPasswordAccountPolicyDenied      = errors.New("native Windows password account policy denied")
	ErrPasswordAccountPolicyUnavailable = errors.New("native Windows password account policy unavailable")
)

type PasswordAccountPolicy struct{ AllowEmpty bool }

type PasswordAccountView interface {
	Account() Account
	GetField(string) (any, bool, error)
	IsEqualTo(PasswordAccountView) bool
}

// PasswordAccount is a current request-local template view, never a persisted
// authorization/environment snapshot. Only its immutable selector is stored in
// a session. Fresh policy and an equal new view are required after validation.
type PasswordAccount struct {
	account                     Account
	displayName, homeDir, shell string
	groups                      []group
}

func (v *PasswordAccount) Account() Account {
	if v == nil {
		return Account{}
	}
	return v.account
}
func (v *PasswordAccount) IsEqualTo(other PasswordAccountView) bool {
	value, ok := other.(*PasswordAccount)
	return ok && v != nil && value != nil && v.account == value.account && v.displayName == value.displayName && v.homeDir == value.homeDir && v.shell == value.shell && sameSAMGroups(v.groups, value.groups)
}
func (v *PasswordAccount) GetField(name string) (any, bool, error) {
	if v == nil {
		return nil, false, ErrPasswordAccountPolicyUnavailable
	}
	switch name {
	case "name":
		return v.account.Name, true, nil
	case "uid":
		return v.account.SID, true, nil
	case "displayName":
		return v.displayName, true, nil
	case "homeDir":
		return v.homeDir, true, nil
	case "shell":
		return v.shell, true, nil
	case "managed":
		return nil, true, nil
	case "groups":
		return slices.Clone(v.groups), true, nil
	case "gids":
		ids := make([]string, len(v.groups))
		for i, g := range v.groups {
			ids[i] = g.SID
		}
		return ids, true, nil
	default:
		return nil, false, fmt.Errorf("unknown user field %q", name)
	}
}

type samPasswordAccountOperations struct {
	restrictions func() error
	identity     func() (Account, error)
	displayName  func() (string, error)
	homeDir      func() (string, error)
	shell        func() (string, error)
	groups       func() ([]group, error)
}

func readSAMPasswordAccount(ctx context.Context, selected Account, api samPasswordAccountOperations) (result *PasswordAccount, resultErr error) {
	if ctx == nil {
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	defer func() {
		resultErr = errors.Join(resultErr, ctx.Err())
		if resultErr != nil {
			result = nil
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if selected.Name == "" || selected.SID == "" {
		return nil, ErrPasswordAccountPolicyDenied
	}
	if api.restrictions == nil || api.identity == nil || api.displayName == nil || api.homeDir == nil || api.shell == nil || api.groups == nil {
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	identity := func() (Account, error) {
		if err := ctx.Err(); err != nil {
			return Account{}, err
		}
		current, err := api.identity()
		if err != nil {
			return Account{}, err
		}
		if current.SID != selected.SID || !strings.EqualFold(current.Name, selected.Name) {
			return Account{}, ErrPasswordAccountPolicyDenied
		}
		return current, ctx.Err()
	}
	restrict := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.Join(api.restrictions(), ctx.Err())
	}
	read := func(operation func() (string, error)) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		value, err := operation()
		return value, errors.Join(err, ctx.Err())
	}
	if err := restrict(); err != nil {
		return nil, err
	}
	current, err := identity()
	if err != nil {
		return nil, err
	}
	value := &PasswordAccount{account: current}
	if value.displayName, err = read(api.displayName); err != nil {
		return nil, err
	}
	if value.homeDir, err = read(api.homeDir); err != nil {
		return nil, err
	}
	if value.homeDir == "" {
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	if value.shell, err = read(api.shell); err != nil {
		return nil, err
	}
	if value.shell == "" {
		return nil, ErrPasswordAccountPolicyUnavailable
	}
	var nativeOrder []group
	_, err = inspectSAMGroupsFlow(ctx, func() error {
		observed, err := identity()
		if err == nil && observed != current {
			return ErrPasswordAccountPolicyDenied
		}
		return err
	}, func() ([]group, error) {
		groups, err := api.groups()
		if err == nil {
			nativeOrder = slices.Clone(groups)
		}
		return groups, err
	})
	if err != nil {
		return nil, err
	}
	// Preserve the primary-login reader's order for index-sensitive templates.
	// The shared group flow validates/canonicalizes its own comparison copy;
	// that ordering must not silently become this template view's ordering.
	value.groups = nativeOrder
	if err := restrict(); err != nil {
		return nil, err
	}
	after, err := identity()
	if err != nil {
		return nil, err
	}
	if after != current {
		return nil, ErrPasswordAccountPolicyDenied
	}
	return value, nil
}
