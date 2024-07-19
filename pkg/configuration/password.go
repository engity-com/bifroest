package configuration

import (
	"github.com/engity-com/bifroest/pkg/template"
	"gopkg.in/yaml.v3"
)

var (
	DefaultPasswordAllowed            = template.MustNewBool("true")
	DefaultPasswordInteractiveAllowed = template.MustNewBool("true")
	DefaultPasswordEmptyAllowed       = template.MustNewBool("false")
)

type Password struct {
	Allowed            template.Bool `yaml:"allowed"`
	InteractiveAllowed template.Bool `yaml:"interactiveAllowed"`
	EmptyAllowed       template.Bool `yaml:"emptyAllowed"`
}

func (this *Password) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("allowed", func(v *Password) *template.Bool { return &v.Allowed }, DefaultPasswordAllowed),
		fixedDefault("interactiveAllowed", func(v *Password) *template.Bool { return &v.InteractiveAllowed }, DefaultPasswordInteractiveAllowed),
		fixedDefault("emptyAllowed", func(v *Password) *template.Bool { return &v.EmptyAllowed }, DefaultPasswordEmptyAllowed),
	)
}

func (this *Password) Trim() error {
	return trim(this,
		noopTrim[Password]("allowed"),
		noopTrim[Password]("interactiveAllowed"),
		noopTrim[Password]("emptyAllowed"),
	)
}

func (this *Password) Validate() error {
	return validate(this,
		noopValidate[Password]("allowed"),
		noopValidate[Password]("interactiveAllowed"),
		noopValidate[Password]("emptyAllowed"),
	)
}

func (this *Password) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Password, node *yaml.Node) error {
		type raw Password
		return node.Decode((*raw)(target))
	})
}

func (this Password) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Password:
		return this.isEqualTo(&v)
	case *Password:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Password) isEqualTo(other *Password) bool {
	return isEqual(&this.Allowed, &other.Allowed) &&
		isEqual(&this.InteractiveAllowed, &other.InteractiveAllowed) &&
		isEqual(&this.EmptyAllowed, &other.EmptyAllowed)
}
