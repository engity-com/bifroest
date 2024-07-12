package configuration

import (
	"github.com/engity-com/yasshd/pkg/errors"
	"gopkg.in/yaml.v3"
	"io"
	"os"
)

type Configuration struct {
	Ssh   Ssh   `yaml:"ssh"`
	Flows Flows `yaml:"flows"`
}

func (this *Configuration) SetDefaults() error {
	return setDefaults(this,
		func(v *Configuration) (string, defaulter) { return "ssh", &v.Ssh },
		func(v *Configuration) (string, defaulter) { return "flows", &v.Flows },
	)
}

func (this *Configuration) Trim() error {
	return trim(this,
		func(v *Configuration) (string, trimmer) { return "ssh", &v.Ssh },
		func(v *Configuration) (string, trimmer) { return "flows", &v.Flows },
	)
}

func (this *Configuration) Validate() error {
	return validate(this,
		func(v *Configuration) (string, validator) { return "ssh", &v.Ssh },
		func(v *Configuration) (string, validator) { return "flows", &v.Flows },
		notEmptySliceValidate("flows", func(v *Configuration) *[]Flow { return (*[]Flow)(&v.Flows) }),
	)
}

func (this *Configuration) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Configuration, node *yaml.Node) error {
		type raw Configuration
		return node.Decode((*raw)(target))
	})
}

func (this *Configuration) LoadFromFile(fn string) error {
	f, err := os.Open(fn)
	if os.IsNotExist(err) {
		return errors.Newf(errors.TypeConfig, "configuration file %q does not exist", fn)
	}
	if err != nil {
		return errors.Newf(errors.TypeConfig, "cannot open configuration file %q: %w", fn, err)
	}
	defer func() { _ = f.Close() }()

	return this.LoadFromYaml(f, fn)
}

func (this *Configuration) LoadFromYaml(reader io.Reader, fn string) error {
	if fn == "" {
		fn = "<anonymous>"
	}

	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	var buf Configuration
	if err := decoder.Decode(&buf); err != nil {
		return errors.Newf(errors.TypeConfig, "cannot parse configuration file %q: %w", fn, err)
	}

	if err := buf.Validate(); err != nil {
		return errors.Newf(errors.TypeConfig, "configuration file %q contains problems: %w", fn, err)
	}

	*this = buf
	return nil
}

func (this Configuration) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Configuration:
		return this.isEqualTo(&v)
	case *Configuration:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Configuration) isEqualTo(other *Configuration) bool {
	return isEqual(&this.Ssh, &other.Ssh) &&
		isEqual(&this.Flows, &other.Flows)
}
