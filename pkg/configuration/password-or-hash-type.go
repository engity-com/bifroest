package configuration

import (
	"github.com/engity-com/bifroest/pkg/errors"
)

type PasswordOrHashType uint8

const (
	PasswordOrHashTypePlain PasswordOrHashType = iota
	PasswordOrHashTypeBcrypt
)

func (this PasswordOrHashType) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return err.Error()
	}
	return string(v)
}

func (this PasswordOrHashType) MarshalText() ([]byte, error) {
	switch this {
	case PasswordOrHashTypePlain:
		return []byte("plain"), nil
	case PasswordOrHashTypeBcrypt:
		return []byte("bcrypt"), nil
	default:
		return nil, errors.Config.Newf("unknown-password-or-hash-type-%d", this)
	}
}

func (this *PasswordOrHashType) Set(plain string) error {
	switch plain {
	case "plain":
		*this = PasswordOrHashTypePlain
		return nil
	case "bcrypt":
		*this = PasswordOrHashTypeBcrypt
		return nil
	default:
		return errors.Config.Newf("invalid password or hash type: %q", plain)
	}
}

func (this *PasswordOrHashType) UnmarshalText(b []byte) error {
	return this.Set(string(b))
}

func (this PasswordOrHashType) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this PasswordOrHashType) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PasswordOrHashType:
		return this.isEqualTo(&v)
	case *PasswordOrHashType:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PasswordOrHashType) isEqualTo(other *PasswordOrHashType) bool {
	return this == *other
}
