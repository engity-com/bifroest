package configuration

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/template"
	"gopkg.in/yaml.v3"
)

var (
	// DefaultSshAddresses is the default setting for Ssh.Addresses.
	DefaultSshAddresses = []common.NetAddress{common.MustNewNetAddress(":2222")}

	// DefaultSshIdleTimeout is the default setting for Ssh.IdleTimeout.
	DefaultSshIdleTimeout = common.MustNewDuration("5m")

	// DefaultSshMaxTimeout is the default setting for Ssh.MaxTimeout.
	DefaultSshMaxTimeout = common.MustNewDuration("0")

	// DefaultSshMaxAuthTries is the default setting for Ssh.MaxAuthTries.
	DefaultSshMaxAuthTries = uint8(6)

	// DefaultSshBanner is the default setting for Ssh.Banner.
	DefaultSshBanner = template.MustNewString("{{`/etc/ssh/sshd-banner` | file `optional` | default `Transcend with Engity's Bifröst\n\n` }}")
)

// Ssh defines how the ssh part of the service should be defined.
type Ssh struct {
	// Addresses which the service will bind to. This can be more than one but at least one.
	// Defaults to DefaultSshAddresses.
	Addresses common.NetAddresses `yaml:"addresses"`

	// Keys represents all key related settings of the service.
	Keys Keys `yaml:"keys"`

	// IdleTimeout represents the duration a connection can be idle until it will be forcibly closed.
	// 0 means no limitation at all. Defaults to DefaultSshIdleTimeout.
	IdleTimeout common.Duration `yaml:"idleTimeout"`

	// MaxTimeout represents the maximum duration a whole connection can last, regardless if it is idle or active
	// until it will be forcibly closed. 0 means no limitation at all. Defaults to DefaultSshMaxTimeout.
	MaxTimeout common.Duration `yaml:"maxTimeout"`

	// MaxAuthTries represents the maximum amount of tries a client can do while a connection with different
	// authorizations before the connection will be forcibly closed. 0 means no limitation at all.
	// Defaults to DefaultSshMaxAuthTries.
	MaxAuthTries uint8 `yaml:"maxAuthTries"`

	// Banner will be displayed if the clients connects to the server before any other action takes place.
	Banner template.String `yaml:"banner,omitempty"`
}

func (this *Ssh) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("addresses", func(v *Ssh) *common.NetAddresses { return &v.Addresses }, DefaultSshAddresses),
		func(v *Ssh) (string, defaulter) { return "keys", &v.Keys },
		fixedDefault("idleTimeout", func(v *Ssh) *common.Duration { return &v.IdleTimeout }, DefaultSshIdleTimeout),
		fixedDefault("maxTimeout", func(v *Ssh) *common.Duration { return &v.MaxTimeout }, DefaultSshMaxTimeout),
		fixedDefault("maxAuthTries", func(v *Ssh) *uint8 { return &v.MaxAuthTries }, DefaultSshMaxAuthTries),
		fixedDefault("banner", func(v *Ssh) *template.String { return &v.Banner }, DefaultSshBanner),
	)
}

func (this *Ssh) Trim() error {
	return trim(this,
		func(v *Ssh) (string, trimmer) { return "addresses", &v.Addresses },
		func(v *Ssh) (string, trimmer) { return "keys", &v.Keys },
		noopTrim[Ssh]("idleTimeout"),
		noopTrim[Ssh]("maxTimeout"),
		noopTrim[Ssh]("maxAuthTries"),
		noopTrim[Ssh]("banner"),
	)
}

func (this *Ssh) Validate() error {
	return validate(this,
		func(v *Ssh) (string, validator) { return "addresses", &v.Addresses },
		func(v *Ssh) (string, validator) { return "keys", &v.Keys },
		noopValidate[Ssh]("idleTimeout"),
		noopValidate[Ssh]("maxTimeout"),
		noopValidate[Ssh]("maxAuthTries"),
		noopValidate[Ssh]("banner"),
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
		this.MaxAuthTries == other.MaxAuthTries &&
		isEqual(&this.Banner, &other.Banner)
}
