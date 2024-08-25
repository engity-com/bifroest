package crypto

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	ErrIllegalPasswordType = errors.New("illegal password type")
)

type PasswordType uint8

const (
	PasswordTypePlain PasswordType = iota
	PasswordTypeBcrypt
)

func (this PasswordType) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return fmt.Sprintf("illegal-password-type-%d", this)
	}
	return string(v)
}

func (this PasswordType) MarshalText() ([]byte, error) {
	switch this {
	case PasswordTypePlain:
		return []byte("plain"), nil
	case PasswordTypeBcrypt:
		return []byte("bcrypt"), nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrIllegalPasswordType, this)
	}
}

func (this *PasswordType) Set(plain string) error {
	switch plain {
	case "plain":
		*this = PasswordTypePlain
		return nil
	case "bcrypt":
		*this = PasswordTypeBcrypt
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrIllegalPasswordType, plain)
	}
}

func (this PasswordType) Encode(password []byte) ([]byte, error) {
	switch this {
	case PasswordTypePlain:
		return password, nil
	case PasswordTypeBcrypt:
		return this.encodeBcrypt(password)
	default:
		return nil, fmt.Errorf("%w: %d", ErrIllegalPasswordType, this)
	}
}

func (this PasswordType) Compare(encoded, password []byte) (bool, error) {
	switch this {
	case PasswordTypePlain:
		return bytes.Equal(encoded, password), nil
	case PasswordTypeBcrypt:
		return this.compareBcrypt(encoded, password)
	default:
		return false, fmt.Errorf("%w: %d", ErrIllegalPasswordType, this)
	}
}

func (this *PasswordType) UnmarshalText(b []byte) error {
	return this.Set(string(b))
}

func (this PasswordType) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this PasswordType) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PasswordType:
		return this.isEqualTo(&v)
	case *PasswordType:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PasswordType) isEqualTo(other *PasswordType) bool {
	return this == *other
}