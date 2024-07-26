package user

import "errors"

var (
	// ErrNoSuchUser indicates that a User which was requested
	// does not exist.
	ErrNoSuchUser = errors.New("no such user")

	// ErrNoSuchGroup indicates that a Group which was requested
	// does not exist.
	ErrNoSuchGroup = errors.New("no such group")
)

// Repository gives access to User and Group objects.
type Repository interface {
	Ensurer

	// LookupByName is used to look up a user by its name. If the
	// user does not exist ErrNoSuchUser is returned.
	LookupByName(string) (*User, error)

	// LookupById is used to look up a user by its Id. If the
	// user does not exist ErrNoSuchUser is returned.
	LookupById(Id) (*User, error)

	// LookupGroupByName is used to look up a group by its name. If
	// the group does not exist ErrNoSuchGroup is returned.
	LookupGroupByName(string) (*Group, error)

	// LookupGroupById is used to look up a group by its GroupId.
	// If the group does not exist ErrNoSuchGroup is returned.
	LookupGroupById(GroupId) (*Group, error)
}
