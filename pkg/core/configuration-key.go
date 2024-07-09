package core

import (
	"fmt"
)

const (
	DefaultConfigurationKey ConfigurationKey = "default"
)

type ConfigurationKey string

func (this ConfigurationKey) IsZero() bool {
	return len(this) == 0
}

func (this ConfigurationKey) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this ConfigurationKey) String() string {
	return string(this)
}

func (this *ConfigurationKey) UnmarshalText(text []byte) error {
	buf := ConfigurationKey(text)
	if err := buf.Validate(); err != nil {
		return err
	}
	*this = buf
	return nil
}

func (this *ConfigurationKey) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this ConfigurationKey) Validate() error {
	if len(this) == 0 {
		return fmt.Errorf("illegal configuration key: empty")
	}
	for _, c := range string(this) {
		if (c >= 'a' && 'z' <= c) ||
			(c >= 'A' && 'Z' <= c) ||
			(c >= '0' && '9' <= c) ||
			c == '-' || c == '.' {
			// Ok
		} else {
			return fmt.Errorf("illegal configuration key: %q", this)
		}
	}
	return nil
}
