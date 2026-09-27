//go:build darwin

package user

import (
	"context"
	stderrors "errors"
	"fmt"
	osuser "os/user"
	"strconv"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

// ErrReadOnlyRepository indicates an operation that cannot be performed by the
// native read-only Darwin account repository.
var ErrReadOnlyRepository = stderrors.New("darwin user repository is read-only: operation unsupported")

// DarwinRepository resolves native macOS users and groups without modifying them.
type DarwinRepository struct {
	lookupUserByName  func(string) (*osuser.User, error)
	lookupUserById    func(string) (*osuser.User, error)
	lookupGroupByName func(string) (*osuser.Group, error)
	lookupGroupById   func(string) (*osuser.Group, error)
	lookupGroupIds    func(*osuser.User) ([]string, error)
	lookupLoginShell  func(string) (string, error)
}

func init() {
	DefaultRepositoryProvider = &SharedRepositoryProvider[*DarwinRepository]{V: &DarwinRepository{}}
}

var _ CloseableRepository = (*DarwinRepository)(nil)

// Init is side-effect free because Darwin account information is queried on demand.
func (this *DarwinRepository) Init(context.Context) error {
	return nil
}

// Close is side-effect free because DarwinRepository owns no resources.
func (this *DarwinRepository) Close() error {
	return nil
}

func (this *DarwinRepository) LookupByName(ctx context.Context, name string) (*User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	native, err := this.userByName(name)
	if err != nil {
		if isUnknownDarwinUser(err) {
			return nil, ErrNoSuchUser
		}
		return nil, berrors.Newf(berrors.System, "cannot look up Darwin user %q: %w", name, err)
	}
	return this.toUser(ctx, native)
}

func (this *DarwinRepository) LookupById(ctx context.Context, id Id) (*User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	native, err := this.userById(id.String())
	if err != nil {
		if isUnknownDarwinUser(err) {
			return nil, ErrNoSuchUser
		}
		return nil, berrors.Newf(berrors.System, "cannot look up Darwin user %d: %w", id, err)
	}
	return this.toUser(ctx, native)
}

func (this *DarwinRepository) LookupGroupByName(ctx context.Context, name string) (*Group, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	native, err := this.groupByName(name)
	if err != nil {
		if isUnknownDarwinGroup(err) {
			return nil, ErrNoSuchGroup
		}
		return nil, berrors.Newf(berrors.System, "cannot look up Darwin group %q: %w", name, err)
	}
	return darwinGroupToGroup(native)
}

func (this *DarwinRepository) LookupGroupById(ctx context.Context, id GroupId) (*Group, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	native, err := this.groupById(id.String())
	if err != nil {
		if isUnknownDarwinGroup(err) {
			return nil, ErrNoSuchGroup
		}
		return nil, berrors.Newf(berrors.System, "cannot look up Darwin group %d: %w", id, err)
	}
	return darwinGroupToGroup(native)
}

func (this *DarwinRepository) Ensure(context.Context, *Requirement, *EnsureOpts) (*User, EnsureResult, error) {
	return nil, EnsureResultError, ErrReadOnlyRepository
}

func (this *DarwinRepository) EnsureGroup(context.Context, *GroupRequirement, *EnsureOpts) (*Group, EnsureResult, error) {
	return nil, EnsureResultError, ErrReadOnlyRepository
}

func (this *DarwinRepository) DeleteById(context.Context, Id, *DeleteOpts) error {
	return ErrReadOnlyRepository
}

func (this *DarwinRepository) DeleteByName(context.Context, string, *DeleteOpts) error {
	return ErrReadOnlyRepository
}

func (this *DarwinRepository) DeleteGroupById(context.Context, GroupId, *DeleteOpts) error {
	return ErrReadOnlyRepository
}

func (this *DarwinRepository) DeleteGroupByName(context.Context, string, *DeleteOpts) error {
	return ErrReadOnlyRepository
}

func (this *DarwinRepository) ValidatePasswordById(context.Context, Id, string) (bool, error) {
	return false, ErrReadOnlyRepository
}

func (this *DarwinRepository) ValidatePasswordByName(context.Context, string, string) (bool, error) {
	return false, ErrReadOnlyRepository
}

func (this *DarwinRepository) toUser(ctx context.Context, native *osuser.User) (*User, error) {
	uid, err := parseDarwinId(native.Uid, "user")
	if err != nil {
		return nil, err
	}
	primaryGid, err := parseDarwinId(native.Gid, "primary group")
	if err != nil {
		return nil, err
	}

	primaryGroup, err := this.LookupGroupById(ctx, GroupId(primaryGid))
	if err != nil {
		return nil, fmt.Errorf("cannot resolve primary group %s of Darwin user %q: %w", native.Gid, native.Username, err)
	}

	groupIds, err := this.groupIds(native)
	if err != nil {
		return nil, berrors.Newf(berrors.System, "cannot look up groups of Darwin user %q: %w", native.Username, err)
	}
	groups := make(Groups, 0, len(groupIds))
	seen := make(map[GroupId]struct{}, len(groupIds))
	for _, rawGroupId := range groupIds {
		groupId, err := parseDarwinId(rawGroupId, "supplementary group")
		if err != nil {
			return nil, err
		}
		id := GroupId(groupId)
		if id == primaryGroup.Gid {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		group, err := this.LookupGroupById(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve supplementary group %s of Darwin user %q: %w", rawGroupId, native.Username, err)
		}
		seen[id] = struct{}{}
		groups = append(groups, *group)
	}

	shell, err := this.loginShell(native.Username)
	if err != nil {
		return nil, berrors.Newf(berrors.System, "cannot look up login shell of Darwin user %q: %w", native.Username, err)
	}

	return &User{
		Name:        native.Username,
		DisplayName: native.Name,
		Uid:         Id(uid),
		Group:       *primaryGroup,
		Groups:      groups,
		Shell:       shell,
		HomeDir:     native.HomeDir,
	}, nil
}

func (this *DarwinRepository) userByName(name string) (*osuser.User, error) {
	if this.lookupUserByName != nil {
		return this.lookupUserByName(name)
	}
	return osuser.Lookup(name)
}

func (this *DarwinRepository) userById(id string) (*osuser.User, error) {
	if this.lookupUserById != nil {
		return this.lookupUserById(id)
	}
	return osuser.LookupId(id)
}

func (this *DarwinRepository) groupByName(name string) (*osuser.Group, error) {
	if this.lookupGroupByName != nil {
		return this.lookupGroupByName(name)
	}
	return osuser.LookupGroup(name)
}

func (this *DarwinRepository) groupById(id string) (*osuser.Group, error) {
	if this.lookupGroupById != nil {
		return this.lookupGroupById(id)
	}
	return osuser.LookupGroupId(id)
}

func (this *DarwinRepository) groupIds(native *osuser.User) ([]string, error) {
	if this.lookupGroupIds != nil {
		return this.lookupGroupIds(native)
	}
	return native.GroupIds()
}

func (this *DarwinRepository) loginShell(name string) (string, error) {
	if this.lookupLoginShell != nil {
		return this.lookupLoginShell(name)
	}
	return lookupDarwinLoginShell(name)
}

func darwinGroupToGroup(native *osuser.Group) (*Group, error) {
	gid, err := parseDarwinId(native.Gid, "group")
	if err != nil {
		return nil, err
	}
	return &Group{Gid: GroupId(gid), Name: native.Name}, nil
}

func parseDarwinId(value, kind string) (uint32, error) {
	id, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, berrors.Newf(berrors.System, "invalid Darwin %s id %q: %w", kind, value, err)
	}
	return uint32(id), nil
}

func isUnknownDarwinUser(err error) bool {
	var byName osuser.UnknownUserError
	var byId osuser.UnknownUserIdError
	return stderrors.As(err, &byName) || stderrors.As(err, &byId)
}

func isUnknownDarwinGroup(err error) bool {
	var byName osuser.UnknownGroupError
	var byId osuser.UnknownGroupIdError
	return stderrors.As(err, &byName) || stderrors.As(err, &byId)
}
