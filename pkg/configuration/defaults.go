package configuration

import (
	"path/filepath"

	"github.com/echocat/cli4g/codec"
)

func (this StrOpts) LoadConfiguration() (*Configuration, error) {
	fn := this.Configuration
	if fn == "" {
		return nil, codec.NewValidationErrorf("empty configuration")
	}

	var result Configuration
	if err := result.LoadFromFile(fn); err != nil {
		return nil, codec.NewValidationError("cannot load configuration", err)
	}
	return &result, nil
}

func (this StrOpts) GetAbsoluteConfiguration() (string, error) {
	fn := this.Configuration
	if fn == "" {
		return "", codec.NewValidationErrorf("empty configuration")
	}
	return filepath.Abs(this.Configuration)
}

type EmptyStrOpts struct {
	Configuration string `flag:"configuration" short:"c" description:"Configuration which should be used."`
}

func (this EmptyStrOpts) LoadConfiguration(fallbackToDefault bool) (*Configuration, bool, error) {
	fn := this.Configuration
	if fn == "" {
		if !fallbackToDefault {
			return nil, false, nil
		}
		fn = DefaultRef
	}

	var result Configuration
	if err := result.LoadFromFile(fn); err != nil {
		return nil, false, codec.NewValidationError("cannot load configuration", err)
	}
	return &result, true, nil
}
