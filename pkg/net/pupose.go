package net

import (
	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrIllegalPurpose = errors.Config.Newf("illegal purpose")
)

type Purpose string

func (this Purpose) String() string {
	return string(this)
}

func (this Purpose) MarshalText() ([]byte, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	return []byte(this.String()), nil
}

func (this *Purpose) UnmarshalText(in []byte) error {
	buf := Purpose(in)
	if err := this.Validate(); err != nil {
		return err
	}
	*this = buf
	return nil
}

func (this *Purpose) Set(in string) error {
	return this.UnmarshalText([]byte(in))
}

func (this Purpose) Clone() Purpose {
	return this
}

func (this Purpose) IsZero() bool {
	return false
}

func (this Purpose) Validate() error {
	illegal := func() error {
		return ErrIllegalPurpose.Extend(string(this))
	}

	if len(this) == 0 {
		return nil
	}

	segmentStart := true
	for _, c := range this {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			segmentStart = false
			continue
		}
		if c >= '0' && c <= '9' {
			if segmentStart {
				return illegal()
			}
			segmentStart = false
			continue
		}

		if c == '-' || c == '.' || c == '_' {
			if segmentStart {
				return illegal()
			}
			segmentStart = true
			continue
		}

		return illegal()
	}

	if segmentStart {
		return illegal()
	}

	return nil
}

func (this Purpose) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Purpose:
		return this.isEqualTo(&v)
	case *Purpose:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Purpose) isEqualTo(other *Purpose) bool {
	return this == *other
}
