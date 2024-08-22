package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"strconv"
)

var (
	ErrIllegalAuthorizedKeyOption = errors.New("illegal authorized key option")
)

type AuthorizedKeyOption struct {
	Type  AuthorizedKeyOptionType
	Value string
}

func (this AuthorizedKeyOption) MarshalText() ([]byte, error) {
	t := this.Type
	if t.IsZero() {
		return nil, nil
	}

	mt, err := t.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIllegalAuthorizedKeyOption, err)
	}

	if t.hasValue() {
		v := this.Value
		if v == "" {
			return nil, fmt.Errorf("%w: option type %v requires a value, but is absent", ErrIllegalAuthorizedKeyOption, t)
		}

		strconv.Quote(this.Value)

		return bytes.Join([][]byte{
			mt,
			{'='},
			[]byte(strconv.Quote(this.Value)),
		}, nil), nil
	}
	return mt, nil
}

func (this *AuthorizedKeyOption) UnmarshalText(text []byte) error {
	parts := bytes.SplitN(text, []byte("="), 2)

	var buf AuthorizedKeyOption
	if err := buf.Type.UnmarshalText(parts[0]); err != nil {
		return fmt.Errorf("%w: %v", ErrIllegalAuthorizedKeyOption, err)
	}

	if buf.Type.hasValue() {
		if len(parts) != 2 {
			return fmt.Errorf("%w: option type %v requires a value, but is absent", ErrIllegalAuthorizedKeyOption, buf.Type)
		}
		var err error
		buf.Value, err = strconv.Unquote(string(parts[1]))
		if err != nil {
			return fmt.Errorf("%w: option's value is not correctly quoted: %s", ErrIllegalAuthorizedKeyOption, string(parts[1]))
		}
	} else if len(parts) > 1 {
		return fmt.Errorf("%w: option type %v does not allow any value, but there was one provided: %q", ErrIllegalAuthorizedKeyOption, buf.Type, string(parts[1]))
	}
	*this = buf
	return nil

}

func (this AuthorizedKeyOption) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return "ERR: " + err.Error()
	}
	return string(v)
}

func (this *AuthorizedKeyOption) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this AuthorizedKeyOption) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this AuthorizedKeyOption) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizedKeyOption:
		return this.isEqualTo(&v)
	case *AuthorizedKeyOption:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizedKeyOption) isEqualTo(other *AuthorizedKeyOption) bool {
	return this.Type.isEqualTo(&other.Type) &&
		this.Value == other.Value
}

type AuthorizedKeyWithOptions struct {
	ssh.PublicKey
	Options []AuthorizedKeyOption
}
