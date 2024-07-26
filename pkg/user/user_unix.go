//go:build unix

package user

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

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

func (this User) Clone() (*User, error) {
	group, err := this.Group.Clone()
	if err != nil {
		return nil, err
	}
	groups, err := this.Groups.Clone()
	if err != nil {
		return nil, err
	}

	return &User{
		strings.Clone(this.Name),
		strings.Clone(this.DisplayName),
		this.Uid,
		*group,
		*groups,
		strings.Clone(this.Shell),
		strings.Clone(this.HomeDir),
	}, nil
}

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

func IdEqualsP(a, b *Id) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
