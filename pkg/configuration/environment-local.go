package configuration

import (
	"github.com/engity-com/bifroest/pkg/template"
	"gopkg.in/yaml.v3"
)

var (
	DefaultEnvironmentLocalLoginAllowed          = template.BoolOf(true)
	DefaultEnvironmentLocalCreateIfAbsent        = template.BoolOf(false)
	DefaultEnvironmentLocalUpdateIfDifferent     = template.BoolOf(false)
	DefaultEnvironmentLocalBanner                = template.MustNewString("")
	DefaultEnvironmentLocalPortForwardingAllowed = template.BoolOf(true)
)

type EnvironmentLocal struct {
	User UserRequirementTemplate `yaml:",inline"`

	LoginAllowed template.Bool `yaml:"loginAllowed,omitempty"`

	CreateIfAbsent    template.Bool           `yaml:"createIfAbsent,omitempty"`
	UpdateIfDifferent template.Bool           `yaml:"updateIfDifferent,omitempty"`
	Dispose           EnvironmentLocalDispose `yaml:"dispose"`

	Banner template.String `yaml:"banner,omitempty"`

	PortForwardingAllowed template.Bool `yaml:"portForwardingAllowed,omitempty"`
}

func (this *EnvironmentLocal) SetDefaults() error {
	return setDefaults(this,
		func(v *EnvironmentLocal) (string, defaulter) { return "", &v.User },

		fixedDefault("loginAllowed", func(v *EnvironmentLocal) *template.Bool { return &v.LoginAllowed }, DefaultEnvironmentLocalLoginAllowed),

		fixedDefault("createIfAbsent", func(v *EnvironmentLocal) *template.Bool { return &v.CreateIfAbsent }, DefaultEnvironmentLocalCreateIfAbsent),
		fixedDefault("updateIfDifferent", func(v *EnvironmentLocal) *template.Bool { return &v.UpdateIfDifferent }, DefaultEnvironmentLocalUpdateIfDifferent),
		func(v *EnvironmentLocal) (string, defaulter) { return "dispose", &v.Dispose },

		fixedDefault("banner", func(v *EnvironmentLocal) *template.String { return &v.Banner }, DefaultEnvironmentLocalBanner),

		fixedDefault("portForwardingAllowed", func(v *EnvironmentLocal) *template.Bool { return &v.PortForwardingAllowed }, DefaultEnvironmentLocalPortForwardingAllowed),
	)
}

func (this *EnvironmentLocal) Trim() error {
	return trim(this,
		func(v *EnvironmentLocal) (string, trimmer) { return "", &v.User },

		noopTrim[EnvironmentLocal]("loginAllowed"),

		noopTrim[EnvironmentLocal]("createIfAbsent"),
		noopTrim[EnvironmentLocal]("updateIfDifferent"),
		func(v *EnvironmentLocal) (string, trimmer) { return "dispose", &v.Dispose },

		noopTrim[EnvironmentLocal]("banner"),

		noopTrim[EnvironmentLocal]("portForwardingAllowed"),
	)
}

func (this *EnvironmentLocal) Validate() error {
	return validate(this,
		func(v *EnvironmentLocal) (string, validator) { return "", &v.User },

		noopValidate[EnvironmentLocal]("loginAllowed"),

		noopValidate[EnvironmentLocal]("createIfAbsent"),
		noopValidate[EnvironmentLocal]("updateIfDifferent"),
		func(v *EnvironmentLocal) (string, validator) { return "dispose", &v.Dispose },

		noopValidate[EnvironmentLocal]("banner"),

		noopValidate[EnvironmentLocal]("portForwardingAllowed"),
	)
}

func (this *EnvironmentLocal) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentLocal, node *yaml.Node) error {
		type raw EnvironmentLocal
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentLocal) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case EnvironmentLocal:
		return this.isEqualTo(&v)
	case *EnvironmentLocal:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentLocal) isEqualTo(other *EnvironmentLocal) bool {
	return isEqual(&this.User, &other.User) &&
		isEqual(&this.LoginAllowed, &other.LoginAllowed) &&
		isEqual(&this.CreateIfAbsent, &other.CreateIfAbsent) &&
		isEqual(&this.UpdateIfDifferent, &other.UpdateIfDifferent) &&
		isEqual(&this.Dispose, &other.Dispose) &&
		isEqual(&this.Banner, &other.Banner) &&
		isEqual(&this.PortForwardingAllowed, &other.PortForwardingAllowed)
}
