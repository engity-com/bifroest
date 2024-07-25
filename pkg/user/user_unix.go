//go:build unix && !android

package user

import (
	"errors"
	"fmt"
	"github.com/engity-com/bifroest/pkg/sys"
	"strconv"
	"syscall"
)

type Id uint32

func (this Id) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *Id) UnmarshalText(text []byte) error {
	buf, err := strconv.ParseUint(string(text), 0, 32)
	if err != nil {
		return fmt.Errorf("illegal user id: %s", string(text))
	}
	*this = Id(buf)
	return nil
}

func (this Id) String() string {
	return strconv.FormatUint(uint64(this), 10)
}

type User struct {
	Name        string
	DisplayName string
	Uid         Id
	Group       Group
	Groups      Groups
	Shell       string
	HomeDir     string
}

func (this User) String() string {
	return fmt.Sprintf("%d(%s)", this.Uid, this.Name)
}

func (this User) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case User:
		return this.isEqualTo(&v)
	case *User:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this User) isEqualTo(other *User) bool {
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

func Delete(name string, opts *DeleteOpts, using sys.Executor) error {
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
		var ee *sys.Error
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

func (this User) ToCredentials() syscall.Credential {
	gids := make([]uint32, len(this.Groups))
	for i, gid := range this.Groups {
		gids[i] = uint32(gid.Gid)
	}
	return syscall.Credential{
		Uid:    uint32(this.Uid),
		Gid:    uint32(this.Group.Gid),
		Groups: gids,
	}
}
