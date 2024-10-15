package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/net"
)

var (
	DefaultEnvironmentImpBindingHost = net.MustNewHost("127.0.0.1")
)

type EnvironmentImp struct {
	BindingHost net.Host `yaml:"bindingHost"`
}

func (this *EnvironmentImp) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("bindingHost", func(v *EnvironmentImp) *net.Host { return &v.BindingHost }, DefaultEnvironmentImpBindingHost),
	)
}

func (this *EnvironmentImp) Trim() error {
	return trim(this,
		noopTrim[EnvironmentImp]("bindingHost"),
	)
}

func (this *EnvironmentImp) Validate() error {
	return validate(this,
		func(v *EnvironmentImp) (string, validator) { return "bindingHost", v.BindingHost },
	)
}

func (this *EnvironmentImp) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentImp, node *yaml.Node) error {
		type raw EnvironmentImp
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentImp) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case EnvironmentImp:
		return this.isEqualTo(&v)
	case *EnvironmentImp:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentImp) isEqualTo(other *EnvironmentImp) bool {
	return isEqual(&this.BindingHost, &other.BindingHost)
}
