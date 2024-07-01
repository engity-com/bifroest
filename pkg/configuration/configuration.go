package configuration

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
	"gopkg.in/yaml.v3"
	"io"
	"os"
)

type Configuration struct {
	Ssh Ssh `yaml:"ssh"`

	// Session defines how new and existing sessions (a connection relates to) should be treated by the service.
	// These session should not be mixed up with [ssh sessions].
	//
	// [ssh sessions]: https://datatracker.ietf.org/doc/html/rfc4254#section-6
	Session Session `yaml:"session"`

	Flows Flows `yaml:"flows"`

	HouseKeeping HouseKeeping `yaml:"housekeeping"`
}

func (this *Configuration) SetDefaults() error {
	return setDefaults(this,
		func(v *Configuration) (string, defaulter) { return "ssh", &v.Ssh },
		func(v *Configuration) (string, defaulter) { return "session", &v.Session },
		func(v *Configuration) (string, defaulter) { return "flows", &v.Flows },
		func(v *Configuration) (string, defaulter) { return "houseKeeping", &v.HouseKeeping },
	)
}

func (this *Configuration) Trim() error {
	return trim(this,
		func(v *Configuration) (string, trimmer) { return "ssh", &v.Ssh },
		func(v *Configuration) (string, trimmer) { return "session", &v.Session },
		func(v *Configuration) (string, trimmer) { return "flows", &v.Flows },
		func(v *Configuration) (string, trimmer) { return "houseKeeping", &v.HouseKeeping },
	)
}

func (this *Configuration) Validate() error {
	return validate(this,
		func(v *Configuration) (string, validator) { return "ssh", &v.Ssh },
		func(v *Configuration) (string, validator) { return "session", &v.Session },
		func(v *Configuration) (string, validator) { return "flows", &v.Flows },
		notEmptySliceValidate("flows", func(v *Configuration) *[]Flow { return (*[]Flow)(&v.Flows) }),
		func(v *Configuration) (string, validator) { return "houseKeeping", &v.HouseKeeping },
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
	if sys.IsNotExist(err) {
		return errors.Newf(errors.Config, "configuration file %q does not exist", fn)
	}
	if err != nil {
		return errors.Newf(errors.Config, "cannot open configuration file %q: %w", fn, err)
	}
	defer common.IgnoreCloseError(f)

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
		return errors.Newf(errors.Config, "cannot parse configuration file %q: %w", fn, err)
	}

	if err := buf.Validate(); err != nil {
		return errors.Newf(errors.Config, "configuration file %q contains problems: %w", fn, err)
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
		isEqual(&this.Session, &other.Session) &&
		isEqual(&this.Flows, &other.Flows) &&
		isEqual(&this.HouseKeeping, &other.HouseKeeping)
}
