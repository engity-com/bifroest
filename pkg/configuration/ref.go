package configuration

import (
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/errors"
)

type Ref struct {
	v  Configuration
	fn string
}

func (this Ref) IsZero() bool {
	return len(this.fn) == 0
}

func (this Ref) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this Ref) String() string {
	return this.fn
}

func (this *Ref) UnmarshalText(text []byte) error {
	buf := Ref{
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

func (this *Ref) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this *Ref) Get() *Configuration {
	return &this.v
}

func (this *Ref) GetFilename() string {
	return this.fn
}

func (this *Ref) MakeAbsolute() error {
	abs, err := filepath.Abs(this.fn)
	if err != nil {
		return errors.Config.Newf("canont make this configuration file reference absolute: %w", err)
	}
	return this.Set(abs)
}

func (this Ref) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Ref:
		return this.isEqualTo(&v)
	case *Ref:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Ref) isEqualTo(other *Ref) bool {
	return this.fn == other.fn
}
