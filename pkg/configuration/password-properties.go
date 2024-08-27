package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultPasswordAllowed            = template.BoolOf(true)
	DefaultPasswordInteractiveAllowed = template.BoolOf(true)
	DefaultPasswordEmptyAllowed       = template.BoolOf(false)
)

type PasswordProperties struct {
	Allowed            template.Bool `yaml:"allowed"`
	InteractiveAllowed template.Bool `yaml:"interactiveAllowed"`
	EmptyAllowed       template.Bool `yaml:"emptyAllowed"`
}

func (this *PasswordProperties) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("allowed", func(v *PasswordProperties) *template.Bool { return &v.Allowed }, DefaultPasswordAllowed),
		fixedDefault("interactiveAllowed", func(v *PasswordProperties) *template.Bool { return &v.InteractiveAllowed }, DefaultPasswordInteractiveAllowed),
		fixedDefault("emptyAllowed", func(v *PasswordProperties) *template.Bool { return &v.EmptyAllowed }, DefaultPasswordEmptyAllowed),
	)
}

func (this *PasswordProperties) Trim() error {
	return trim(this,
		noopTrim[PasswordProperties]("allowed"),
		noopTrim[PasswordProperties]("interactiveAllowed"),
		noopTrim[PasswordProperties]("emptyAllowed"),
	)
}

func (this *PasswordProperties) Validate() error {
	return validate(this,
		noopValidate[PasswordProperties]("allowed"),
		noopValidate[PasswordProperties]("interactiveAllowed"),
		noopValidate[PasswordProperties]("emptyAllowed"),
	)
}

func (this *PasswordProperties) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *PasswordProperties, node *yaml.Node) error {
		type raw PasswordProperties
		return node.Decode((*raw)(target))
	})
}

func (this PasswordProperties) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PasswordProperties:
		return this.isEqualTo(&v)
	case *PasswordProperties:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PasswordProperties) isEqualTo(other *PasswordProperties) bool {
	return isEqual(&this.Allowed, &other.Allowed) &&
		isEqual(&this.InteractiveAllowed, &other.InteractiveAllowed) &&
		isEqual(&this.EmptyAllowed, &other.EmptyAllowed)
}
