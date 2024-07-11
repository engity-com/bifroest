package configuration

import (
	"github.com/engity/pam-oidc/pkg/common"
	"gopkg.in/yaml.v3"
)

var (
	DefaultSshAddress = []common.NetAddress{common.MustNewNetAddress(":2222")}
)

type Ssh struct {
	Address common.NetAddresses `yaml:"address"`
	HostKey string              `yaml:"hostKey"`
}

func (this *Ssh) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("address", func(v *Ssh) *common.NetAddresses { return &v.Address }, DefaultSshAddress),
		fixedDefault("hostKey", func(v *Ssh) *string { return &v.HostKey }, DefaultHostKeyLocation),
	)
}

func (this *Ssh) Trim() error {
	return trim(this,
		func(v *Ssh) (string, trimmer) { return "address", &v.Address },
		func(v *Ssh) (string, trimmer) { return "hostKey", &stringTrimmer{&v.HostKey} },
	)
}

func (this *Ssh) Validate() error {
	return validate(this,
		func(v *Ssh) (string, validator) { return "address", &v.Address },
		notEmptySliceValidate("address", func(v *Ssh) *[]common.NetAddress { return (*[]common.NetAddress)(&v.Address) }),
		notEmptyStringValidate("hostKey", func(v *Ssh) *string { return &v.HostKey }),
	)
}

func (this *Ssh) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Ssh, node *yaml.Node) error {
		type raw Ssh
		return node.Decode((*raw)(target))
	})
}

func (this Ssh) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Ssh:
		return this.isEqualTo(&v)
	case *Ssh:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Ssh) isEqualTo(other *Ssh) bool {
	return isEqual(&this.Address, &other.Address) &&
		this.HostKey == other.HostKey
}
