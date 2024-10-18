package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultEnvironmentDummyExitCode = template.Int64Of(0)
	DefaultEnvironmentDummyBanner   = template.MustNewString("")

	_ = RegisterEnvironmentV(func() EnvironmentV {
		return &EnvironmentDummy{}
	})
)

type EnvironmentDummy struct {
	ExitCode template.Int64  `yaml:"exitCode,omitempty"`
	Banner   template.String `yaml:"banner,omitempty"`
}

func (this *EnvironmentDummy) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("exitCode", func(v *EnvironmentDummy) *template.Int64 { return &v.ExitCode }, DefaultEnvironmentDummyExitCode),
		fixedDefault("banner", func(v *EnvironmentDummy) *template.String { return &v.Banner }, DefaultEnvironmentDummyBanner),
	)
}

func (this *EnvironmentDummy) Trim() error {
	return trim(this,
		noopTrim[EnvironmentDummy]("exitCode"),
		noopTrim[EnvironmentDummy]("banner"),
	)
}

func (this *EnvironmentDummy) Validate() error {
	return validate(this,
		func(v *EnvironmentDummy) (string, validator) { return "exitCode", &v.ExitCode },
		func(v *EnvironmentDummy) (string, validator) { return "banner", &v.Banner },
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
	return isEqual(&this.ExitCode, &other.ExitCode) &&
		isEqual(&this.Banner, &other.Banner)
}

func (this EnvironmentDummy) Types() []string {
	return []string{"dummy"}
}

func (this EnvironmentDummy) FeatureFlags() []string {
	return []string{"dummy"}
}
