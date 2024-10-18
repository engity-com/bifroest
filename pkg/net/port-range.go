package net

import (
	"iter"
	"strconv"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

func NewPortRange(in string) (result PortRange, err error) {
	err = result.Set(in)
	return
}

func MustNewPortRange(in string) PortRange {
	result, err := NewPortRange(in)
	common.Must(err)
	return result
}

type PortRange struct {
	Start uint16
	End   uint16
}

func (this PortRange) Test(candidate uint16) bool {
	if this.Start == 0 && this.End == 0 {
		return false
	}
	if this.Start > 0 && this.End > 0 {
		return this.Start <= candidate && candidate <= this.End
	}
	return this.Start == candidate
}

func (this PortRange) Iterate() iter.Seq2[uint16, error] {
	return func(yield func(uint16, error) bool) {
		if this.End == 0 {
			if this.Start == 0 {
				return
			}
			yield(this.Start, nil)
			return
		}
		if this.Start > this.End {
			yield(0, errors.Config.Newf("illegal port-range: %v", this))
			return
		}
		for i := this.Start; i <= this.End; i++ {
			if !yield(i, nil) {
				return
			}
		}
	}
}

func (this PortRange) String() string {
	if this.End == 0 {
		return strconv.FormatUint(uint64(this.Start), 10)
	}
	return strconv.FormatUint(uint64(this.Start), 10) + "-" + strconv.FormatUint(uint64(this.End), 10)
}

func (this PortRange) MarshalText() ([]byte, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	return []byte(this.String()), nil
}

func (this *PortRange) UnmarshalText(in []byte) error {
	if len(in) == 0 {
		*this = PortRange{}
		return nil
	}

	parts := strings.SplitN(string(in), "-", 2)

	start, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return errors.Config.Newf("illegal port-range: %s", string(in))
	}

	var buf PortRange
	if len(parts) > 1 {
		end, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return errors.Config.Newf("illegal port-range: %s", string(in))
		}
		if start == end {
			buf = PortRange{uint16(start), 0}
		} else {
			buf = PortRange{uint16(start), uint16(end)}
		}
	} else {
		buf = PortRange{uint16(start), 0}
	}

	if err := buf.Validate(); err != nil {
		return err
	}

	*this = buf
	return nil
}

func (this *PortRange) Set(in string) error {
	return this.UnmarshalText([]byte(in))
}

func (this PortRange) Clone() PortRange {
	return PortRange{
		this.Start,
		this.End,
	}
}

func (this PortRange) IsZero() bool {
	return this.Start == 0 && this.End == 0
}

func (this PortRange) Validate() error {
	if this.Start == 0 && this.End == 0 {
		return nil
	}
	if (this.End > 0 && this.Start > this.End) || (this.Start == 0 && this.End > 0) {
		return errors.Config.Newf("illegal port-range: %v", this)
	}
	return nil
}

func (this PortRange) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PortRange:
		return this.isEqualTo(&v)
	case *PortRange:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PortRange) isEqualTo(other *PortRange) bool {
	return this.Start == other.Start &&
		this.End == other.End
}
