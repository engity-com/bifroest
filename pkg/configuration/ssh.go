package configuration

import (
	"github.com/engity-com/yasshd/pkg/common"
	"gopkg.in/yaml.v3"
)

var (
	DefaultSshAddresses   = []common.NetAddress{common.MustNewNetAddress(":2222")}
	DefaultSshIdleTimeout = common.MustNewDuration("30m")
	DefaultSshMaxTimeout  = common.MustNewDuration("0")
	DefaultMaxAuthTries   = uint8(6)
)

type Ssh struct {
	Addresses    common.NetAddresses `yaml:"addresses"`
	Keys         Keys                `yaml:"keys"`
	IdleTimeout  common.Duration     `yaml:"idleTimeout"`
	MaxTimeout   common.Duration     `yaml:"maxTimeout"`
	MaxAuthTries uint8               `yaml:"maxAuthTries"`
}

func (this *Ssh) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("addresses", func(v *Ssh) *common.NetAddresses { return &v.Addresses }, DefaultSshAddresses),
		func(v *Ssh) (string, defaulter) { return "keys", &v.Keys },
		fixedDefault("idleTimeout", func(v *Ssh) *common.Duration { return &v.IdleTimeout }, DefaultSshIdleTimeout),
		fixedDefault("maxTimeout", func(v *Ssh) *common.Duration { return &v.MaxTimeout }, DefaultSshMaxTimeout),
		fixedDefault("maxAuthTries", func(v *Ssh) *uint8 { return &v.MaxAuthTries }, DefaultMaxAuthTries),
	)
}

func (this *Ssh) Trim() error {
	return trim(this,
		func(v *Ssh) (string, trimmer) { return "addresses", &v.Addresses },
		func(v *Ssh) (string, trimmer) { return "keys", &v.Keys },
		func(v *Ssh) (string, trimmer) { return "idleTimeout", &v.Keys },
		func(v *Ssh) (string, trimmer) { return "maxTimeout", &v.Keys },
		func(v *Ssh) (string, trimmer) { return "maxAuthTries", &v.Keys },
	)
}

func (this *Ssh) Validate() error {
	return validate(this,
		func(v *Ssh) (string, validator) { return "addresses", &v.Addresses },
		func(v *Ssh) (string, validator) { return "keys", &v.Keys },
		func(v *Ssh) (string, validator) { return "idleTimeout", &v.Keys },
		func(v *Ssh) (string, validator) { return "maxTimeout", &v.Keys },
		func(v *Ssh) (string, validator) { return "maxAuthTries", &v.Keys },
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
	return isEqual(&this.Addresses, &other.Addresses) &&
		isEqual(&this.Keys, &other.Keys) &&
		isEqual(&this.IdleTimeout, &other.IdleTimeout) &&
		isEqual(&this.MaxTimeout, &other.MaxTimeout) &&
		this.MaxAuthTries == other.MaxAuthTries
}
