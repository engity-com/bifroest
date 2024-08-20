package configuration

import (
	"bytes"
	"github.com/engity-com/bifroest/pkg/errors"
	"strings"
)

var (
	ErrIllegalPasswordOrHash = errors.Config.Newf("illegal password or hash")
)

type PasswordOrHash []byte

func (this PasswordOrHash) String() string {
	return string(this)
}

func (this PasswordOrHash) MarshalText() ([]byte, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	return bytes.Clone(this), nil
}

func (this *PasswordOrHash) Set(plain string) error {
	buf := PasswordOrHash(plain)
	if err := buf.Validate(); err != nil {
		return err
	}
	*this = buf
	return nil
}

func (this *PasswordOrHash) UnmarshalText(b []byte) error {
	return this.Set(string(b))
}

func (this PasswordOrHash) Validate() error {
	parts := strings.SplitAfterN(string(this), ":", 2)
	if len(parts) != 2 {
		return errors.Config.Newf("%w: %v", ErrIllegalPasswordOrHash, string(this))
	}

	var t PasswordOrHashType
	if err := t.Set(parts[0]); err != nil {
		return errors.Config.Newf("%w: %v: %v", ErrIllegalPasswordOrHash, string(this), err)
	}

	return nil
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
