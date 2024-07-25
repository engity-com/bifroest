//go:build unix && !android

package user

import (
	"errors"
	"fmt"
	"github.com/engity-com/bifroest/pkg/sys"
	"strconv"
	"strings"
)

type GroupId uint32

func (this GroupId) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this *GroupId) UnmarshalText(text []byte) error {
	buf, err := strconv.ParseUint(string(text), 0, 32)
	if err != nil {
		return fmt.Errorf("illegal group id: %s", string(text))
	}
	*this = GroupId(buf)
	return nil
}

func (this GroupId) String() string {
	return strconv.FormatUint(uint64(this), 10)
}

type Group struct {
	Gid  GroupId
	Name string
}

func (this Group) String() string {
	return fmt.Sprintf("%d(%s)", this.Gid, this.Name)
}

func (this Group) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Group:
		return this.isEqualTo(&v)
	case *Group:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Group) isEqualTo(other *Group) bool {
	return this.Gid == other.Gid &&
		this.Name == other.Name
}

func formatGidsOfGroups(ins ...*Group) string {
	strs := make([]string, len(ins))
	for i, in := range ins {
		strs[i] = strconv.FormatUint(uint64(in.Gid), 10)
	}
	return strings.Join(strs, ",")
}

type DeleteGroupOpts struct {
	Force *bool
}

func DeleteGroup(name string, opts *DeleteGroupOpts, using sys.Executor) error {
	if len(name) == 0 {
		return fmt.Errorf("cannot delete group with empty name")
	}
	fail := func(err error) error {
		return fmt.Errorf("cannot delete group %s: %w", name, err)
	}
	failf := func(message string, args ...any) error {
		return fail(fmt.Errorf(message, args...))
	}

	tOpts := opts.OrDefaults()
	var args []string
	if v := tOpts.Force; v != nil && *v {
		args = append(args, "-f")
	}
	args = append(args, name)

	if err := using.Execute("groupdel", args...); err != nil {
		var ee *sys.Error
		if errors.As(err, &ee) && ee.ExitCode == 6 {
			// This means already deleted: ok for us.
		} else {
			return failf("cannot delete group %s: %w", name, err)
		}
	}

	return nil
}

func (this DeleteGroupOpts) Clone() DeleteGroupOpts {
	var fr *bool
	if v := this.Force; v != nil {
		nv := *v
		fr = &nv
	}
	return DeleteGroupOpts{
		fr,
	}
}

func (this *DeleteGroupOpts) OrDefaults() DeleteGroupOpts {
	var result DeleteGroupOpts
	if v := this; v != nil {
		result = v.Clone()
	}
	if v := result.Force; v == nil {
		nv := true
		result.Force = &nv
	}
	return result
}

type Groups []Group

func (this Groups) IsZero() bool {
	return len(this) == 0
}

func (this Groups) Contains(other *Group) bool {
	if other == nil {
		return false
	}
	for _, candidate := range this {
		if candidate.IsEqualTo(other) {
			return true
		}
	}
	return false
}

func (this Groups) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Groups:
		return this.isEqualTo(&v)
	case *Groups:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Groups) isEqualTo(other *Groups) bool {
	if len(this) != len(*other) {
		return false
	}

	for i, candidate := range this {
		if candidate.IsEqualTo(&(*other)[i]) {
			return true
		}
	}
	return false
}
