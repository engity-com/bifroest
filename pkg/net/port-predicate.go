package net

import (
	"bytes"
	"iter"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
)

func NewPortPredicate(in string) (result PortPredicate, err error) {
	err = result.Set(in)
	return
}

func MustNewPortPredicate(in string) PortPredicate {
	result, err := NewPortPredicate(in)
	common.Must(err)
	return result
}

type PortPredicate struct {
	Includes PortRanges
	Excludes PortRanges
}

func (this PortPredicate) Test(candidate uint16) bool {
	if candidate == 0 {
		return false
	}
	if len(this.Includes) > 0 && !this.Includes.Test(candidate) {
		return false
	}
	if len(this.Excludes) > 0 && this.Excludes.Test(candidate) {
		return false
	}
	return true
}

func (this PortPredicate) iterateIncludes() iter.Seq2[uint16, error] {
	return func(yield func(uint16, error) bool) {
		if len(this.Includes) == 0 {
			for v := uint16(0); v < 65535; v++ {
				if !yield(v+1, nil) {
					return
				}
			}
			return
		}

		for v, err := range this.Includes.Iterate() {
			if !yield(v, err) {
				return
			}
		}
	}
}

func (this PortPredicate) Iterate() iter.Seq2[uint16, error] {
	return func(yield func(uint16, error) bool) {
		if err := this.Validate(); err != nil {
			yield(0, err)
			return
		}
		for v, err := range this.iterateIncludes() {
			if err != nil {
				if !yield(v, err) {
					return
				}
				continue
			}

			if this.Excludes.Test(v) {
				continue
			}

			if !yield(v, nil) {
				return
			}
		}
	}
}

func (this PortPredicate) String() string {
	iss := this.Includes.Strings()
	ess := this.Excludes.Strings()
	for i, es := range ess {
		ess[i] = "!" + es
	}
	return strings.Join(append(iss, ess...), ",")
}

func (this PortPredicate) MarshalText() ([]byte, error) {
	ibs, err := this.Includes.marshalTexts()
	if err != nil {
		return nil, err
	}
	ebs, err := this.Excludes.marshalTexts()
	if err != nil {
		return nil, err
	}
	for i, eb := range ebs {
		ebs[i] = append([]byte("!"), eb...)
	}
	return bytes.Join(append(ibs, ebs...), []byte(",")), nil
}

func (this *PortPredicate) UnmarshalText(in []byte) error {
	if len(in) == 0 {
		*this = PortPredicate{}
		return nil
	}

	parts := bytes.Split(in, []byte(","))
	buf := PortPredicate{
		Includes: make(PortRanges, len(parts)),
		Excludes: make(PortRanges, len(parts)),
	}
	nIncludes, nExcludes := 0, 0

	for _, part := range parts {
		including := true
		if len(part) > 0 && part[0] == '!' {
			part = part[1:]
			including = false
		}

		var pr PortRange
		if err := pr.UnmarshalText(part); err != nil {
			return err
		}

		if including {
			buf.Includes[nIncludes] = pr
			nIncludes++
		} else {
			buf.Excludes[nExcludes] = pr
			nExcludes++
		}
	}

	buf.Includes = buf.Includes[:nIncludes]
	buf.Excludes = buf.Excludes[:nExcludes]

	*this = buf
	return nil
}

func (this *PortPredicate) Set(in string) error {
	return this.UnmarshalText([]byte(in))
}

func (this PortPredicate) Clone() PortPredicate {
	return PortPredicate{
		Includes: this.Includes.Clone(),
		Excludes: this.Excludes.Clone(),
	}
}

func (this PortPredicate) IsZero() bool {
	return this.Includes.IsZero() && this.Excludes.IsZero()
}

func (this PortPredicate) Validate() error {
	if err := this.Includes.Validate(); err != nil {
		return err
	}
	if err := this.Excludes.Validate(); err != nil {
		return err
	}
	return nil
}

func (this PortPredicate) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PortPredicate:
		return this.isEqualTo(&v)
	case *PortPredicate:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PortPredicate) isEqualTo(other *PortPredicate) bool {
	return this.Includes.isEqualTo(&other.Includes) &&
		this.Excludes.isEqualTo(&other.Excludes)
}
