//go:build windows

package user

import (
	"fmt"
	"strings"
)

type Requirement struct {
	Name  string `yaml:"name,omitempty"`
	Uid   *Id    `yaml:"uid,omitempty"`
	Shell string `yaml:"strign,omitempty"`
}

func (this Requirement) IsZero() bool {
	return len(this.Name) == 0 &&
		this.Uid == nil &&
		this.Shell == ""
}

func (this Requirement) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Requirement:
		return this.isEqualTo(&v)
	case *Requirement:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Requirement) isEqualTo(other *Requirement) bool {
	return this.Name == other.Name &&
		IdEqualsP(this.Uid, other.Uid) &&
		this.Shell == other.Shell
}

func (this Requirement) String() string {
	if name := this.Name; len(name) > 0 {
		if uid := this.Uid; uid != nil {
			return fmt.Sprintf("%v(%s)", uid, name)
		} else {
			return strings.Clone(name)
		}
	} else if uid := this.Uid; uid != nil {
		return uid.String()
	} else {
		return "<empty>"
	}
}
