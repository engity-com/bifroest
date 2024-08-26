package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultEnvironmentDummyLoginAllowed = template.BoolOf(true)
	DefaultEnvironmentDummyIntroduction = template.MustNewString(`[::bu]Welcome to [:::https://github.com/engity-com/bifroest]Engity's Bifröst![:::-][::-]

You've entered Bifröst's dummy environment. It is meant to demonstrate basic interactions with [:::https://en.wikipedia.org/wiki/Pseudoterminal]PTYs[:::-].

You can either hit different keys and see what you've hit within the [::i]Properties[::-] section (below) or draw on the white panel (on the right) with your mouse.

Supported keys:
* [Ctrl[]+[C[] or [Q[] to exit
* [C[] to clean the white draw panel (right)
`)
	DefaultEnvironmentDummyIntroductionStyled = template.BoolOf(true)

	_ = RegisterEnvironmentV(func() EnvironmentV {
		return &EnvironmentDummy{}
	})
)

type EnvironmentDummy struct {
	LoginAllowed       template.Bool   `yaml:"loginAllowed,omitempty"`
	Introduction       template.String `yaml:"introduction,omitempty"`
	IntroductionStyled template.Bool   `yaml:"introductionStyled,omitempty"`
}

func (this *EnvironmentDummy) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("loginAllowed", func(v *EnvironmentDummy) *template.Bool { return &v.LoginAllowed }, DefaultEnvironmentDummyLoginAllowed),
		fixedDefault("introduction", func(v *EnvironmentDummy) *template.String { return &v.Introduction }, DefaultEnvironmentDummyIntroduction),
		fixedDefault("introductionStyled", func(v *EnvironmentDummy) *template.Bool { return &v.IntroductionStyled }, DefaultEnvironmentDummyIntroductionStyled),
	)
}

func (this *EnvironmentDummy) Trim() error {
	return trim(this,
		noopTrim[EnvironmentDummy]("loginAllowed"),
		noopTrim[EnvironmentDummy]("introduction"),
		noopTrim[EnvironmentDummy]("introductionStyled"),
	)
}

func (this *EnvironmentDummy) Validate() error {
	return validate(this,
		noopValidate[EnvironmentDummy]("loginAllowed"),
		noopValidate[EnvironmentDummy]("introduction"),
		noopValidate[EnvironmentDummy]("introductionStyled"),
	)
}

func (this *EnvironmentDummy) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentDummy, node *yaml.Node) error {
		type raw EnvironmentDummy
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentDummy) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case EnvironmentDummy:
		return this.isEqualTo(&v)
	case *EnvironmentDummy:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentDummy) isEqualTo(other *EnvironmentDummy) bool {
	return isEqual(&this.LoginAllowed, &other.LoginAllowed) &&
		isEqual(&this.Introduction, &other.Introduction) &&
		isEqual(&this.IntroductionStyled, &other.IntroductionStyled)
}

func (this EnvironmentDummy) Types() []string {
	return []string{"dummy"}
}
