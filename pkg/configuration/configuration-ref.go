package configuration

import (
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/errors"
)

type ConfigurationRef struct {
	v  Configuration
	fn string
}

func (this ConfigurationRef) IsZero() bool {
	return len(this.fn) == 0
}

func (this ConfigurationRef) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this ConfigurationRef) String() string {
	return this.fn
}

func (this *ConfigurationRef) UnmarshalText(text []byte) error {
	buf := ConfigurationRef{
		fn: string(text),
	}

	if len(buf.fn) > 0 {
		if err := buf.v.LoadFromFile(buf.fn); err != nil {
			return err
		}
	}

	*this = buf
	return nil
}

func (this *ConfigurationRef) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this *ConfigurationRef) Get() *Configuration {
	return &this.v
}

func (this *ConfigurationRef) GetFilename() string {
	return this.fn
}

func (this *ConfigurationRef) MakeAbsolute() error {
	abs, err := filepath.Abs(this.fn)
	if err != nil {
		return errors.Config.Newf("canont make this configuration file reference absolute: %w", err)
	}
	return this.Set(abs)
}

func (this ConfigurationRef) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case ConfigurationRef:
		return this.isEqualTo(&v)
	case *ConfigurationRef:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this ConfigurationRef) isEqualTo(other *ConfigurationRef) bool {
	return this.fn == other.fn
}
