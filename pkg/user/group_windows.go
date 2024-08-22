//go:build windows

package user

import (
	"fmt"
)

type Group struct {
	Gid  GroupId
	Name string
}

func (this Group) GetField(name string) (any, bool, error) {
	switch name {
	case "name":
		return this.Name, true, nil
	case "gid":
		return this.Gid, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
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

type GroupId string

func GroupIdEqualsP(a, b *GroupId) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
