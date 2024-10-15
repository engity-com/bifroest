package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/net"
)

var (
	DefaultEnvironmentImpBindingPorts = net.MustNewPortPredicate("30000-65500")
	DefaultEnvironmentImpBindingHost  = net.MustNewHost("127.0.0.1")
	DefaultEnvironmentImpHost         = DefaultEnvironmentImpBindingHost
)

type EnvironmentImp struct {
	BindingPorts net.PortPredicate `yaml:"bindingPorts"`
	BindingHost  net.Host          `yaml:"bindingHost"`
	Host         net.Host          `yaml:"host"`
}

func (this *EnvironmentImp) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("bindingPorts", func(v *EnvironmentImp) *net.PortPredicate { return &v.BindingPorts }, DefaultEnvironmentImpBindingPorts),
		fixedDefault("bindingHost", func(v *EnvironmentImp) *net.Host { return &v.BindingHost }, DefaultEnvironmentImpBindingHost),
		fixedDefault("host", func(v *EnvironmentImp) *net.Host { return &v.Host }, DefaultEnvironmentImpHost),
	)
}

func (this *EnvironmentImp) Trim() error {
	return trim(this,
		noopTrim[EnvironmentImp]("bindingPorts"),
		noopTrim[EnvironmentImp]("bindingHost"),
		noopTrim[EnvironmentImp]("host"),
	)
}

func (this *EnvironmentImp) Validate() error {
	return validate(this,
		func(v *EnvironmentImp) (string, validator) { return "bindingPorts", v.BindingPorts },
		func(v *EnvironmentImp) (string, validator) { return "bindingHost", v.BindingHost },
		func(v *EnvironmentImp) (string, validator) { return "host", v.Host },
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
	return isEqual(&this.BindingPorts, &other.BindingPorts) &&
		isEqual(&this.BindingHost, &other.BindingHost) &&
		isEqual(&this.Host, &other.Host)
}
