package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/ssh"
)

var (
	DefaultMessagesAuthentications = ssh.DefaultMessageAuthentications
	DefaultMessagesCiphers         = ssh.DefaultCiphers
)

type Messages struct {
	Authentications ssh.MessageAuthentications `yaml:"authentications"`
	Ciphers         ssh.Ciphers                `yaml:"ciphers"`
}

func (this *Messages) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("authentications", func(v *Messages) *ssh.MessageAuthentications { return &v.Authentications }, DefaultMessagesAuthentications),
		fixedDefault("ciphers", func(v *Messages) *ssh.Ciphers { return &v.Ciphers }, DefaultMessagesCiphers),
	)
}

func (this *Messages) Trim() error {
	return trim(this,
		noopTrim[Messages]("authentications"),
		noopTrim[Messages]("ciphers"),
	)
}

func (this *Messages) Validate() error {
	return validate(this,
		func(v *Messages) (string, validator) { return "authentications", &v.Authentications },
		notZeroValidate("authentications", func(v *Messages) *ssh.MessageAuthentications { return &v.Authentications }),
		func(v *Messages) (string, validator) { return "ciphers", &v.Ciphers },
		notZeroValidate("ciphers", func(v *Messages) *ssh.Ciphers { return &v.Ciphers }),
	)
}

func (this *Messages) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Messages, node *yaml.Node) error {
		type raw Messages
		return node.Decode((*raw)(target))
	})
}

func (this Messages) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Messages:
		return this.isEqualTo(&v)
	case *Messages:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Messages) isEqualTo(other *Messages) bool {
	return isEqual(&this.Authentications, &other.Authentications) &&
		isEqual(&this.Ciphers, &other.Ciphers)
}
