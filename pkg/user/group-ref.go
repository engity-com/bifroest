package user

import (
	"fmt"
	"strconv"
)

func NewGroupRef(plain string) (GroupRef, error) {
	var buf GroupRef
	if err := buf.Set(plain); err != nil {
		return GroupRef{}, nil
	}
	return buf, nil
}

type GroupRef struct {
	v     *Group
	plain string
}

func (this GroupRef) IsZero() bool {
	return this.v == nil
}

func (this GroupRef) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this GroupRef) String() string {
	return this.plain
}

func (this *GroupRef) UnmarshalText(text []byte) error {
	buf := GroupRef{
		plain: string(text),
	}

	if len(buf.plain) > 0 {
		if id, err := strconv.ParseUint(buf.plain, 10, 32); err == nil {
			buf.v, err = LookupGid(uint32(id), true, true)
			if err != nil {
				return fmt.Errorf("cannot resolve group by ID #%d: %w", id, err)
			}
		}
		if buf.v == nil {
			var err error
			buf.v, err = LookupGroup(buf.plain, true, true)
			if err != nil {
				return fmt.Errorf("cannot resolve group by name %q: %w", buf.plain, err)
			}
		}
		if buf.v == nil {
			return fmt.Errorf("unknown group: %s", buf.plain)
		}
	}

	*this = buf
	return nil
}

func (this *GroupRef) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this *GroupRef) Get() *Group {
	return this.v
}
