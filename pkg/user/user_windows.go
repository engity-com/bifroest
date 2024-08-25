//go:build windows

package user

import (
	"bytes"
	"fmt"
	"syscall"
)

type User struct {
	Name        string
	DisplayName string
	Uid         Id
	HomeDir     string
}

func (this User) GetField(name string) (any, bool, error) {
	switch name {
	case "name":
		return this.Name, true, nil
	case "displayName":
		return this.DisplayName, true, nil
	case "uid":
		return this.Uid, true, nil
	case "homeDir":
		return this.HomeDir, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this User) String() string {
	return fmt.Sprintf("%v(%s)", this.Uid, this.Name)
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
		this.HomeDir == other.HomeDir
}

type Id struct {
	*syscall.SID
}

func (this Id) MarshalText() (text []byte, err error) {
	sid := this.SID
	if sid == nil {
		return nil, nil
	}
	v, err := sid.String()
	if err != nil {
		return nil, err
	}
	return []byte(v), nil
}

func (this *Id) UnmarshalText(text []byte) error {
	buf, err := syscall.StringToSid(string(text))
	if err != nil {
		return fmt.Errorf("illegal user id: %v", string(text))
	}
	*this = Id{buf}
	return nil
}

func (this *Id) Set(plain string) error {
	return this.UnmarshalText([]byte(plain))
}

func (this Id) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}
	return string(v)
}

func (this Id) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Id:
		return this.isEqualTo(&v)
	case *Id:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Id) isEqualTo(other *Id) bool {
	if other == nil {
		return false
	}
	if this.SID == nil && other.SID == nil {
		return true
	}
	if this.SID == nil || other.SID == nil {
		return false
	}
	tv, tErr := this.MarshalText()
	ov, oErr := other.MarshalText()
	return bytes.Equal(tv, ov) &&
		tErr == oErr
}

func IdEqualsP(a, b *Id) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.isEqualTo(b)
}
