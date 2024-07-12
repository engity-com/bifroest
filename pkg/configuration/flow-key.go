package configuration

import (
	"fmt"
)

type FlowName string

func (this FlowName) IsZero() bool {
	return len(this) == 0
}

func (this FlowName) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this FlowName) String() string {
	return string(this)
}

func (this *FlowName) UnmarshalText(text []byte) error {
	buf := FlowName(text)
	if err := buf.Validate(); err != nil {
		return err
	}
	*this = buf
	return nil
}

func (this *FlowName) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this FlowName) Validate() error {
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

func (this FlowName) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case string:
		return string(this) == v
	case *string:
		return string(this) == *v
	case FlowName:
		return this.isEqualTo(&v)
	case *FlowName:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this FlowName) isEqualTo(other *FlowName) bool {
	return this == *other
}
