package user

import (
	"fmt"
	"strconv"
	"strings"
)

var defaultGroup = GroupRequirement{1500, "yasshd"}

type GroupRequirement struct {
	Gid  uint32 `yaml:"gid,omitempty"`
	Name string `yaml:"name,omitempty"`
}

func (this GroupRequirement) Clone() GroupRequirement {
	return GroupRequirement{
		this.Gid,
		strings.Clone(this.Name),
	}
}

func (this GroupRequirement) IsZero() bool {
	return this.Gid == 0 &&
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
	return this.Gid == other.Gid &&
		this.Name == other.Name
}

func (this GroupRequirement) DoesFulfil(other *Group) bool {
	if other == nil {
		return false
	}
	return this.Gid == other.Gid &&
		this.Name == other.Name
}

func (this GroupRequirement) String() string {
	if name := this.Name; len(name) > 0 {
		if gid := this.Gid; gid > 0 {
			return fmt.Sprintf("%d(%s)", gid, name)
		} else {
			return strings.Clone(name)
		}
	} else if gid := this.Gid; gid > 0 {
		return strconv.FormatUint(uint64(gid), 10)
	} else {
		return "<empty>"
	}
}

func (this GroupRequirement) name() string {
	name := strings.Clone(this.Name)
	if len(name) > 0 {
		return name
	}
	if gid := this.Gid; gid > 0 {
		return fmt.Sprintf("group-%d", gid)
	}
	return ""
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

func (this GroupRequirements) DoesFulfil(other *Groups) bool {
	if other == nil {
		return len(this) == 0
	}
	if len(this) != len(*other) {
		return false
	}

	for i, candidate := range this {
		if candidate.DoesFulfil(&(*other)[i]) {
			return true
		}
	}
	return false
}
