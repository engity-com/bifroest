package user

import (
	"errors"
	"fmt"
	"github.com/engity/pam-oidc/pkg/execution"
	"strconv"
	"strings"
)

type Group struct {
	Gid  uint64
	Name string
}

func (this Group) String() string {
	return fmt.Sprintf("%d(%s)", this.Gid, this.Name)
}

func (this Group) IsEqualTo(other *Group) bool {
	if other == nil {
		return false
	}
	return this.Gid == other.Gid &&
		this.Name == other.Name
}

func formatGidsOfGroups(ins ...*Group) string {
	strs := make([]string, len(ins))
	for i, in := range ins {
		strs[i] = strconv.FormatUint(in.Gid, 10)
	}
	return strings.Join(strs, ",")
}

type DeleteGroupOpts struct {
	Force *bool
}

func DeleteGroup(name string, opts *DeleteGroupOpts, using execution.Executor) error {
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
		var ee *execution.Error
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

func lookupGroups(gids ...uint64) (Groups, error) {
	gs := make(Groups, len(gids))
	for i, gid := range gids {
		g, err := LookupGid(gid)
		if err != nil {
			return nil, err
		}
		if g == nil {
			gs[i] = Group{
				Gid:  gid,
				Name: strconv.FormatUint(gid, 10),
			}
		} else {
			gs[i] = *g
		}
	}
	return gs, nil
}

func lookupGroupsOf(username string, gid uint64) (Groups, error) {
	gids, err := lookupGids(username, gid)
	if err != nil {
		return nil, err
	}
	return lookupGroups(gids...)
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

func (this Groups) IsEqualTo(other *Groups) bool {
	if other == nil {
		return len(this) == 0
	}
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
