package configuration

import (
	"bytes"
	"fmt"
	"github.com/engity-com/bifroest/pkg/errors"
	"strings"
)

var (
	ErrIllegalPasswordOrHash = errors.Config.Newf("illegal password or hash")
)

type PasswordOrHash []byte

func (this PasswordOrHash) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return err.Error()
	}
	return string(v)
}

func (this PasswordOrHash) MarshalText() ([]byte, error) {
	switch this {
	case PasswordOrHashTypePlain:
		return []byte("plain"), nil
	case PasswordOrHashTypeBcrypt:
		return []byte("bcrypt"), nil
	default:
		return nil, fmt.Errorf("unknown-password-or-hash-type-%d", this)
	}
}

func (this *PasswordOrHash) Set(plain string) error {
	parts := strings.SplitAfterN(plain, ":", 2)
	if len(parts) != 2 {
		return errors.Config.Newf("%w: %v")
	}
	switch plain {
	case "plain":
		*this = PasswordOrHashTypePlain
		return nil
	case "bcrypt":
		*this = PasswordOrHashTypeBcrypt
		return nil
	default:
		return fmt.Errorf("invalid password or hash type: %q", plain)
	}
}

func (this *PasswordOrHash) UnmarshalText(b []byte) error {
	return this.Set(string(b))
}

func (this PasswordOrHash) Validate() error {
	return validateSlice(this)
}

func (this PasswordOrHash) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PasswordOrHash:
		return this.isEqualTo(&v)
	case *PasswordOrHash:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PasswordOrHash) isEqualTo(other *PasswordOrHash) bool {
	return bytes.Equal(this, *other)
}
