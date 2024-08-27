package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrIllegalPassword = errors.New("illegal password")
)

type Password []byte

func (this Password) String() string {
	return string(this)
}

func (this Password) MarshalText() ([]byte, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	return bytes.Clone(this), nil
}

func (this *Password) Set(plain string) error {
	buf := Password(plain)
	if err := buf.Validate(); err != nil {
		return err
	}
	*this = buf
	return nil
}

func (this *Password) UnmarshalText(b []byte) error {
	return this.Set(string(b))
}

func (this Password) Compare(withPassword []byte) (bool, error) {
	i := bytes.Index(this, []byte{':'})
	if i < 0 || len(this) < i+1 {
		return false, fmt.Errorf("%w: %v", ErrIllegalPassword, string(this))
	}

	var t PasswordType
	if err := t.UnmarshalText(this[:i]); err != nil {
		return false, fmt.Errorf("%w: %v: %v", ErrIllegalPassword, string(this), err)
	}

	return t.Compare(this[i+1:], withPassword)
}

func (this *Password) SetPassword(t PasswordType, password []byte) error {
	bt, err := t.MarshalText()
	if err != nil {
		return err
	}
	*this = bytes.Join([][]byte{bt, password}, []byte{})
	return nil
}

func (this Password) Validate() error {
	parts := strings.SplitN(string(this), ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: %v", ErrIllegalPassword, string(this))
	}

	var t PasswordType
	if err := t.Set(parts[0]); err != nil {
		return fmt.Errorf("%w: %v: %v", ErrIllegalPassword, string(this), err)
	}

	return nil
}

func (this Password) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Password:
		return this.isEqualTo(&v)
	case *Password:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Password) IsZero() bool {
	return len(this) == 0
}

func (this Password) isEqualTo(other *Password) bool {
	return bytes.Equal(this, *other)
}
