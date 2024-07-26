//go:build unix

package user

import (
	"fmt"
	"strconv"
	"strings"
)

var defaultGroupName = "bifroest"

type GroupRequirement struct {
	Gid  *GroupId `yaml:"gid,omitempty"`
	Name string   `yaml:"name,omitempty"`
}

func (this GroupRequirement) Clone() GroupRequirement {
	return GroupRequirement{
		this.Gid,
		strings.Clone(this.Name),
	}
}

func (this GroupRequirement) IsZero() bool {
	return this.Gid == nil &&
		len(this.Name) == 0
}

func (this GroupRequirement) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case GroupRequirement:
		return this.isEqualTo(&v)
	case *GroupRequirement:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this GroupRequirement) isEqualTo(other *GroupRequirement) bool {
	return GroupIdEqualsP(this.Gid, other.Gid) &&
		this.Name == other.Name
}

func (this GroupRequirement) doesFulfilRef(ref *etcGroupRef) bool {
	if ref == nil {
		return false
	}
	gid := GroupId(ref.gid)
	return GroupIdEqualsP(this.Gid, &gid) &&
		this.Name == string(ref.name)
}

func (this GroupRequirement) String() string {
	if name := this.Name; len(name) > 0 {
		if gid := this.Gid; gid != nil {
			return fmt.Sprintf("%d(%s)", gid, name)
		} else {
			return strings.Clone(name)
		}
	} else if gid := this.Gid; gid != nil {
		return strconv.FormatUint(uint64(*gid), 10)
	} else {
		return "<empty>"
	}
}

type GroupRequirements []GroupRequirement

func (this GroupRequirements) Clone() GroupRequirements {
	result := make(GroupRequirements, len(this))
	for i, v := range this {
		result[i] = v.Clone()
	}
	return result
}

func (this GroupRequirements) IsZero() bool {
	return len(this) == 0
}

func (this GroupRequirements) Contains(other *GroupRequirement) bool {
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

func (this GroupRequirements) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case GroupRequirements:
		return this.isEqualTo(&v)
	case *GroupRequirements:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this GroupRequirements) isEqualTo(other *GroupRequirements) bool {
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
