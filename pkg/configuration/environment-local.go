package configuration

import (
	"github.com/engity-com/yasshd/pkg/template"
	"gopkg.in/yaml.v3"
)

const (
	DefaultEnvironmentLocalLoginAllowedTmpl      = "true"
	DefaultEnvironmentLocalCreateIfAbsentTmpl    = "true"
	DefaultEnvironmentLocalUpdateIfDifferentTmpl = "true"
)

type EnvironmentLocal struct {
	User UserRequirementTemplate `yaml:",inline"`

	LoginAllowed template.Bool `yaml:"loginAllowed,omitempty"`

	CreateIfAbsent    template.Bool `yaml:"createIfAbsent,omitempty"`
	UpdateIfDifferent template.Bool `yaml:"updateIfDifferent,omitempty"`
}

func (this *EnvironmentLocal) SetDefaults() error {
	return setDefaults(this,
		func(v *EnvironmentLocal) (string, defaulter) { return "", &v.User },

		fixedDefault("loginAllowed", func(v *EnvironmentLocal) *template.Bool { return &v.LoginAllowed }, template.MustNewBool(DefaultEnvironmentLocalLoginAllowedTmpl)),

		fixedDefault("createIfAbsent", func(v *EnvironmentLocal) *template.Bool { return &v.CreateIfAbsent }, template.MustNewBool(DefaultEnvironmentLocalCreateIfAbsentTmpl)),
		fixedDefault("updateIfDifferent", func(v *EnvironmentLocal) *template.Bool { return &v.UpdateIfDifferent }, template.MustNewBool(DefaultEnvironmentLocalUpdateIfDifferentTmpl)),
	)
}

func (this *EnvironmentLocal) Trim() error {
	return trim(this,
		func(v *EnvironmentLocal) (string, trimmer) { return "", &v.User },

		noopTrim[EnvironmentLocal]("loginAllowed"),

		noopTrim[EnvironmentLocal]("createIfAbsent"),
		noopTrim[EnvironmentLocal]("updateIfDifferent"),
	)
}

func (this *EnvironmentLocal) Validate() error {
	return validate(this,
		func(v *EnvironmentLocal) (string, validator) { return "", &v.User },

		noopValidate[EnvironmentLocal]("loginAllowed"),

		noopValidate[EnvironmentLocal]("createIfAbsent"),
		noopValidate[EnvironmentLocal]("updateIfDifferent"),
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
		isEqual(&this.UpdateIfDifferent, &other.UpdateIfDifferent)
}
