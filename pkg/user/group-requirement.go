package user

import (
	"fmt"
	"strconv"
	"strings"
)

type GroupRequirement struct {
	Gid  uint64
	Name string
}

func (this GroupRequirement) Ensure() (*Group, error) {
	var existing *Group
	var err error
	if this.Gid > 0 {
		if existing, err = LookupGid(this.Gid); err != nil {
			return nil, err
		}
	} else if len(this.Name) > 0 {
		if existing, err = LookupGroup(this.Name); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("group requirement with neither GID nor name")
	}

	if existing == nil {
		return this.create()
	}

	return nil, fmt.Errorf("TODO!!!!!")
}

func (this GroupRequirement) create() (*Group, error) {
	name := strings.Clone(this.Name)
	if len(name) == 0 {
		name = fmt.Sprintf("group%d", this.Gid)
	}

	var args []string
	if v := this.Gid; v > 0 {
		args = append(args, "-g", strconv.FormatUint(v, 10))
	}
	args = append(args, name)

	if err := execCommand("groupadd", args...); err != nil {
		return nil, fmt.Errorf("cannot create group %s: %w", name, err)
	}

	return LookupGroup(name)
}
