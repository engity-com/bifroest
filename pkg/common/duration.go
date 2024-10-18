package common

import (
	"fmt"
	"time"
)

func NewDuration(plain string) (Duration, error) {
	var buf Duration
	if err := buf.Set(plain); err != nil {
		return Duration{}, nil
	}
	return buf, nil
}

func DurationOf(native time.Duration) Duration {
	return Duration{native}
}

func MustNewDuration(plain string) Duration {
	buf, err := NewDuration(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Duration struct {
	v time.Duration
}

func (this Duration) IsZero() bool {
	return this.v == 0
}

func (this Duration) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this Duration) String() string {
	if v := this.v; v != 0 {
		return v.String()
	}
	return ""
}

func (this *Duration) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		this.v = 0
		return nil
	}

	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("illegal duration")
	}

	this.v = v
	return nil
}

func (this *Duration) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this *Duration) Native() time.Duration {
	return this.v
}

func (this *Duration) SetNative(v time.Duration) {
	this.v = v
}

func (this *Duration) Validate() error {
	return nil
}

func (this Duration) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case time.Duration:
		return this.isEqualTo(&v)
	case *time.Duration:
		return this.isEqualTo(v)
	case Duration:
		return this.isEqualTo(&v.v)
	case *Duration:
		return this.isEqualTo(&v.v)
	default:
		return false
	}
}

func (this Duration) isEqualTo(other *time.Duration) bool {
	return this.v == *other
}
