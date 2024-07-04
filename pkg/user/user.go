package user

import (
	"errors"
	"fmt"
	"github.com/engity/pam-oidc/pkg/execution"
)

type User struct {
	Name        string
	DisplayName string
	Uid         uint64
	Group       Group
	Groups      Groups
	Shell       string
	HomeDir     string
}

func (this User) String() string {
	return fmt.Sprintf("%d(%s)", this.Uid, this.Name)
}

func (this User) IsEqualTo(other *User) bool {
	if other == nil {
		return false
	}
	return this.Name == other.Name &&
		this.DisplayName == other.DisplayName &&
		this.Uid == other.Uid &&
		this.Group.IsEqualTo(&other.Group) &&
		this.Groups.IsEqualTo(&other.Groups) &&
		this.Shell == other.Shell &&
		this.HomeDir == other.HomeDir
}

type DeleteOpts struct {
	RemoveHomeDir *bool
	Force         *bool
}

func Delete(name string, opts *DeleteOpts, using execution.Executor) error {
	if len(name) == 0 {
		return fmt.Errorf("cannot delete user with empty name")
	}
	fail := func(err error) error {
		return fmt.Errorf("cannot delete user %s: %w", name, err)
	}
	failf := func(message string, args ...any) error {
		return fail(fmt.Errorf(message, args...))
	}

	tOpts := opts.OrDefaults()
	var args []string
	if v := tOpts.Force; v != nil && *v {
		args = append(args, "-f")
	}
	if v := tOpts.RemoveHomeDir; v != nil && *v {
		args = append(args, "-r")
	}
	args = append(args, name)

	if err := using.Execute("userdel", args...); err != nil {
		var ee *execution.Error
		if errors.As(err, &ee) && ee.ExitCode == 6 {
			// This means already deleted: ok for us.
		} else {
			return failf("cannot delete group %s: %w", name, err)
		}
	}

	return nil
}

func (this DeleteOpts) Clone() DeleteOpts {
	var rhd *bool
	if v := this.RemoveHomeDir; v != nil {
		nv := *v
		rhd = &nv
	}
	var fr *bool
	if v := this.Force; v != nil {
		nv := *v
		fr = &nv
	}
	return DeleteOpts{
		rhd,
		fr,
	}
}

func (this *DeleteOpts) OrDefaults() DeleteOpts {
	var result DeleteOpts
	if v := this; v != nil {
		result = v.Clone()
	}
	if v := result.RemoveHomeDir; v == nil {
		nv := true
		result.RemoveHomeDir = &nv
	}
	if v := result.Force; v == nil {
		nv := true
		result.Force = &nv
	}
	return result
}
