//go:build unix

package user

import (
	"fmt"
	"strconv"
	"strings"
)

type Group struct {
	Gid  GroupId
	Name string
}

func (this Group) Clone() (*Group, error) {
	return &Group{
		Gid:  this.Gid,
		Name: strings.Clone(this.Name),
	}, nil
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

func (this Groups) Clone() (*Groups, error) {
	result := make(Groups, len(this))
	for i, v := range this {
		nv, err := v.Clone()
		if err != nil {
			return nil, err
		}
		result[i] = *nv
	}
	return &result, nil
}

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

func GroupIdEqualsP(a, b *GroupId) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
