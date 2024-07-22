package user

import (
	"fmt"
	"strconv"
)

func NewUserRef(plain string) (UserRef, error) {
	var buf UserRef
	if err := buf.Set(plain); err != nil {
		return UserRef{}, nil
	}
	return buf, nil
}

type UserRef struct {
	v     *User
	plain string
}

func (this UserRef) IsZero() bool {
	return this.v == nil
}

func (this UserRef) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this UserRef) String() string {
	return this.plain
}

func (this *UserRef) UnmarshalText(text []byte) error {
	buf := UserRef{
		plain: string(text),
	}

	if len(buf.plain) > 0 {
		if id, err := strconv.ParseUint(buf.plain, 10, 32); err == nil {
			buf.v, err = LookupUid(uint32(id), true, true)
			if err != nil {
				return fmt.Errorf("cannot resolve user by ID #%d: %w", id, err)
			}
		}
		if buf.v == nil {
			var err error
			buf.v, err = Lookup(buf.plain, true, true)
			if err != nil {
				return fmt.Errorf("cannot resolve user by name %q: %w", buf.plain, err)
			}
		}
		if buf.v == nil {
			return fmt.Errorf("unknown user: %s", buf.plain)
		}
	}

	*this = buf
	return nil
}

func (this *UserRef) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this *UserRef) Get() *User {
	return this.v
}
