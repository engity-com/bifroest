package configuration

import (
	"fmt"
)

type FlowKey string

func (this FlowKey) IsZero() bool {
	return len(this) == 0
}

func (this FlowKey) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this FlowKey) String() string {
	return string(this)
}

func (this *FlowKey) UnmarshalText(text []byte) error {
	buf := FlowKey(text)
	if err := buf.Validate(); err != nil {
		return err
	}
	*this = buf
	return nil
}

func (this *FlowKey) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this FlowKey) Validate() error {
	if len(this) == 0 {
		return fmt.Errorf("illegal flow key: empty")
	}
	for _, c := range string(this) {
		if (c >= 'a' && 'z' <= c) ||
			(c >= 'A' && 'Z' <= c) ||
			(c >= '0' && '9' <= c) ||
			c == '-' || c == '.' {
			// Ok
		} else {
			return fmt.Errorf("illegal flow key: %q", this)
		}
	}
	return nil
}

func (this FlowKey) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case FlowKey:
		return this.isEqualTo(&v)
	case *FlowKey:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this FlowKey) isEqualTo(other *FlowKey) bool {
	return this == *other
}
