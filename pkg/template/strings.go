package template

import (
	"fmt"
)

func NewStrings(plains ...string) (Strings, error) {
	buf := make(Strings, len(plains))
	var err error
	for i, plain := range plains {
		if err = buf[i].Set(plain); err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
	}
	return buf, nil
}

func MustNewStrings(plains ...string) Strings {
	buf, err := NewStrings(plains...)
	if err != nil {
		panic(err)
	}
	return buf
}

type Strings []String

func (this Strings) Render(data any) ([]string, error) {
	result := make([]string, len(this))
	for i, v := range this {
		rv, err := v.Render(data)
		if err != nil {
			return nil, fmt.Errorf("[%d] %w", i, err)
		}
		result[i] = rv
	}
	return result, nil
}

func (this Strings) IsZero() bool {
	return len(this) == 0
}

func (this Strings) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Strings:
		return this.isEqualTo(&v)
	case *Strings:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Strings) isEqualTo(other *Strings) bool {
	if len(this) != len(*other) {
		return false
	}
	for i, tv := range this {
		if !tv.isEqualTo(&(*other)[i]) {
			return false
		}
	}
	return true
}
