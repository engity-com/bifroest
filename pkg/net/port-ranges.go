package net

import (
	"bytes"
	"iter"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
)

func NewPortRanges(in string) (result PortRanges, err error) {
	err = result.Set(in)
	return
}

func MustNewPortRanges(in string) PortRanges {
	result, err := NewPortRanges(in)
	common.Must(err)
	return result
}

type PortRanges []PortRange

func (this PortRanges) Test(candidate uint16) bool {
	for _, v := range this {
		if v.Test(candidate) {
			return true
		}
	}
	return false
}

func (this PortRanges) Iterate() iter.Seq2[uint16, error] {
	return func(yield func(uint16, error) bool) {
		for _, inner := range this {
			for v, err := range inner.Iterate() {
				if !yield(v, err) {
					return
				}
			}
		}
	}
}

func (this PortRanges) Strings() []string {
	strs := make([]string, len(this))
	for i, v := range this {
		strs[i] = v.String()
	}
	return strs
}

func (this PortRanges) String() string {
	return strings.Join(this.Strings(), ",")
}

func (this PortRanges) marshalTexts() ([][]byte, error) {
	var err error
	bs := make([][]byte, len(this))
	for i, v := range this {
		if bs[i], err = v.MarshalText(); err != nil {
			return nil, err
		}
	}
	return bs, nil
}

func (this PortRanges) MarshalText() ([]byte, error) {
	bs, err := this.marshalTexts()
	if err != nil {
		return nil, err
	}
	return bytes.Join(bs, []byte(",")), nil
}

func (this *PortRanges) UnmarshalText(in []byte) error {
	if len(in) == 0 {
		*this = PortRanges{}
		return nil
	}

	parts := bytes.Split(in, []byte(","))
	buf := make(PortRanges, len(parts))
	for i, v := range parts {
		if err := buf[i].UnmarshalText(v); err != nil {
			return err
		}
	}
	*this = buf
	return nil
}

func (this *PortRanges) Set(in string) error {
	return this.UnmarshalText([]byte(in))
}

func (this PortRanges) Clone() PortRanges {
	result := make(PortRanges, len(this))
	for i, v := range this {
		result[i] = v.Clone()
	}
	return result
}

func (this PortRanges) IsZero() bool {
	for _, v := range this {
		if !v.IsZero() {
			return false
		}
	}
	return true
}

func (this PortRanges) Validate() error {
	for _, v := range this {
		if err := v.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (this PortRanges) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PortRanges:
		return this.isEqualTo(&v)
	case *PortRanges:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PortRanges) isEqualTo(other *PortRanges) bool {
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
