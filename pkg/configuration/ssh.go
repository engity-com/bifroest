package configuration

import (
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/template"
)

var (
	// DefaultSshAddresses is the default setting for Ssh.Addresses.
	DefaultSshAddresses = []net.Address{net.MustNewAddress(":22")}

	// DefaultSshIdleTimeout is the default setting for Ssh.IdleTimeout.
	DefaultSshIdleTimeout = common.DurationOf(10 * time.Minute)

	// DefaultSshMaxTimeout is the default setting for Ssh.MaxTimeout.
	DefaultSshMaxTimeout = common.DurationOf(0)

	// DefaultSshMaxAuthTries is the default setting for Ssh.MaxAuthTries.
	DefaultSshMaxAuthTries = uint8(6)

	// DefaultSshMaxConnections is the default setting for Ssh.MaxConnections.
	DefaultSshMaxConnections = uint32(255)

	DefaultProxyProtocol = false

	// DefaultSshBanner is the default setting for Ssh.Banner.
	DefaultSshBanner = template.MustNewString("{{`/etc/ssh/sshd-banner` | file `optional` | default `Transcend with Engity's Bifröst\n\n` }}")
)

// Ssh defines how the ssh part of the service should be defined.
type Ssh struct {
	// Addresses which the service will bind to. This can be more than one but at least one.
	// Defaults to DefaultSshAddresses.
	Addresses net.NetAddresses `yaml:"addresses"`

	// Keys represents all key related settings of the service.
	Keys Keys `yaml:"keys"`

	// Messages represents all message related settings of the service.
	Messages Messages `yaml:"messages"`

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

	// MaxConnections defines how many connection can be connected to this service in parallel. If there is a new
	// connection created which exceeds this number, this will be closed immediately.
	// Defaults to DefaultSshMaxConnections.
	MaxConnections uint32 `yaml:"maxConnections"`

	// ProxyProtocol defines if the proxy protocol should be respected.
	ProxyProtocol bool `yaml:"proxyProtocol,omitempty"`

	// Banner will be displayed if the clients connects to the server before any other action takes place.
	Banner template.String `yaml:"banner,omitempty"`

	// PreparationMessages will be displayed if any kind of preparation is required before the ssh session can
	// finally be used.
	PreparationMessages PreparationMessages `yaml:"preparationMessages,omitempty"`
}

func (this *Ssh) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("addresses", func(v *Ssh) *net.NetAddresses { return &v.Addresses }, DefaultSshAddresses),
		func(v *Ssh) (string, defaulter) { return "keys", &v.Keys },
		func(v *Ssh) (string, defaulter) { return "messages", &v.Messages },
		fixedDefault("idleTimeout", func(v *Ssh) *common.Duration { return &v.IdleTimeout }, DefaultSshIdleTimeout),
		fixedDefault("maxTimeout", func(v *Ssh) *common.Duration { return &v.MaxTimeout }, DefaultSshMaxTimeout),
		fixedDefault("maxAuthTries", func(v *Ssh) *uint8 { return &v.MaxAuthTries }, DefaultSshMaxAuthTries),
		fixedDefault("maxConnections", func(v *Ssh) *uint32 { return &v.MaxConnections }, DefaultSshMaxConnections),
		fixedDefault("proxyProtocol", func(v *Ssh) *bool { return &v.ProxyProtocol }, DefaultProxyProtocol),
		fixedDefault("banner", func(v *Ssh) *template.String { return &v.Banner }, DefaultSshBanner),
		func(v *Ssh) (string, defaulter) { return "preparationMessages", &v.PreparationMessages },
	)
}

func (this *Ssh) Trim() error {
	return trim(this,
		func(v *Ssh) (string, trimmer) { return "addresses", &v.Addresses },
		func(v *Ssh) (string, trimmer) { return "keys", &v.Keys },
		func(v *Ssh) (string, trimmer) { return "messages", &v.Messages },
		noopTrim[Ssh]("idleTimeout"),
		noopTrim[Ssh]("maxTimeout"),
		noopTrim[Ssh]("maxAuthTries"),
		noopTrim[Ssh]("maxConnections"),
		noopTrim[Ssh]("proxyProtocol"),
		noopTrim[Ssh]("banner"),
		func(v *Ssh) (string, trimmer) { return "preparationMessages", &v.PreparationMessages },
	)
}

func (this *Ssh) Validate() error {
	return validate(this,
		func(v *Ssh) (string, validator) { return "addresses", &v.Addresses },
		func(v *Ssh) (string, validator) { return "keys", &v.Keys },
		func(v *Ssh) (string, validator) { return "messages", &v.Messages },
		func(v *Ssh) (string, validator) { return "idleTimeout", &v.IdleTimeout },
		func(v *Ssh) (string, validator) { return "maxTimeout", &v.MaxTimeout },
		noopValidate[Ssh]("maxAuthTries"),
		noopValidate[Ssh]("maxConnections"),
		noopValidate[Ssh]("proxyProtocol"),
		func(v *Ssh) (string, validator) { return "banner", &v.Banner },
		func(v *Ssh) (string, validator) { return "preparationMessages", &v.PreparationMessages },
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
		isEqual(&this.Messages, &other.Messages) &&
		isEqual(&this.IdleTimeout, &other.IdleTimeout) &&
		isEqual(&this.MaxTimeout, &other.MaxTimeout) &&
		this.MaxAuthTries == other.MaxAuthTries &&
		this.MaxConnections == other.MaxConnections &&
		this.ProxyProtocol == other.ProxyProtocol &&
		isEqual(&this.Banner, &other.Banner) &&
		isEqual(&this.PreparationMessages, &other.PreparationMessages)
}
