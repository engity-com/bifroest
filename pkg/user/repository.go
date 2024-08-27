//go:build unix

package user

import (
	"context"
	"io"
	"sync"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	// ErrNoSuchUser indicates that a User which was requested
	// does not exist.
	ErrNoSuchUser = errors.Newf(errors.Unknown, "no such user")

	// ErrNoSuchGroup indicates that a Group which was requested
	// does not exist.
	ErrNoSuchGroup = errors.Newf(errors.Unknown, "no such group")

	// DefaultRepositoryProvider holds the default instance of RepositoryProvider.
	DefaultRepositoryProvider RepositoryProvider = &failingRepositoryProvider{}
)

// Repository gives access to User and Group objects.
type Repository interface {
	Ensurer

	// LookupByName is used to look up a user by its name. If the
	// user does not exist ErrNoSuchUser is returned.
	LookupByName(context.Context, string) (*User, error)

	// LookupById is used to look up a user by its Id. If the
	// user does not exist ErrNoSuchUser is returned.
	LookupById(context.Context, Id) (*User, error)

	// LookupGroupByName is used to look up a group by its name. If
	// the group does not exist ErrNoSuchGroup is returned.
	LookupGroupByName(context.Context, string) (*Group, error)

	// LookupGroupById is used to look up a group by its GroupId.
	// If the group does not exist ErrNoSuchGroup is returned.
	LookupGroupById(context.Context, GroupId) (*Group, error)

	// DeleteById will delete the user by the given Id. If the
	// user does not exist ErrNoSuchUser is returned.
	DeleteById(context.Context, Id, *DeleteOpts) error

	// DeleteByName will delete the user by the given name. If the
	// user does not exist ErrNoSuchUser is returned.
	DeleteByName(context.Context, string, *DeleteOpts) error

	// ValidatePasswordById will validate the given password
	// the given user by its Id. It returns true if the given
	// password is valid. It will return ErrNoSuchUser if the
	// given user does not exist.
	ValidatePasswordById(ctx context.Context, id Id, pass string) (bool, error)

	// ValidatePasswordByName will validate the given password
	// the given user by its name. It returns true if the given
	// password is valid. It will return ErrNoSuchUser if the
	// given user does not exist.
	ValidatePasswordByName(ctx context.Context, name string, pass string) (bool, error)

	// DeleteGroupById will delete the group by the given GroupId.
	// If the group does not exist ErrNoSuchGroup is returned.
	DeleteGroupById(context.Context, GroupId, *DeleteOpts) error

	// DeleteGroupByName will delete the group by the given name.
	// If the group does not exist ErrNoSuchGroup is returned.
	DeleteGroupByName(context.Context, string, *DeleteOpts) error
}

// CloseableRepository represents a Repository which needs to be closed
// after final usage (via Close).
type CloseableRepository interface {
	Repository
	io.Closer
}

// RepositoryProvider provides a working instance of Repository.
type RepositoryProvider interface {
	// Create provides a working instance of Repository.
	//
	// It is important to call CloseableRepository.Close after usage.
	Create(context.Context) (CloseableRepository, error)
}

type SharedRepositoryProvider[T interface {
	CloseableRepository
	Init(context.Context) error
}] struct {
	V      T
	usages int16
	mutex  sync.Mutex
}

func (this *SharedRepositoryProvider[T]) Create(ctx context.Context) (CloseableRepository, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if this.usages == 0 {
		if err := this.V.Init(ctx); err != nil {
			return nil, err
		}
	}
	this.usages++
	return &sharedRepository[T]{this, this.V, false}, nil
}

type sharedRepository[T interface {
	CloseableRepository
	Init(context.Context) error
}] struct {
	provider *SharedRepositoryProvider[T]
	Repository
	closed bool
}

func (this *sharedRepository[T]) Close() error {
	this.provider.mutex.Lock()
	defer this.provider.mutex.Unlock()

	if this.closed {
		return nil
	}

	defer func() {
		this.closed = true
	}()

	this.provider.usages--
	if this.provider.usages < 0 {
		panic("less than 0 usages!?")
	}
	if this.provider.usages == 0 {
		if err := this.provider.V.Close(); err != nil {
			return err
		}
	}
	return nil
}

type failingRepositoryProvider struct{}

func (this failingRepositoryProvider) Create(context.Context) (CloseableRepository, error) {
	return nil, errors.Newf(errors.System, "no such repository")
}

// DeleteOpts adds some more hints what should happen when
// Repository.DeleteById or its derivates is used.
type DeleteOpts struct {
	// HomeDir defines if the home directory of the User should be
	// deleted or not (does not affect Group). Default: true
	HomeDir *bool

	// KillProcesses will also kill all running processes of this user
	// if any.
	KillProcesses *bool
}

func (this *DeleteOpts) IsHomeDir() bool {
	if this != nil {
		if v := this.HomeDir; v != nil {
			return *v
		}
	}
	return true
}

func (this *DeleteOpts) IsKillProcesses() bool {
	if this != nil {
		if v := this.KillProcesses; v != nil {
			return *v
		}
	}
	return true
}
