package configuration

import (
	"fmt"
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

	// DefaultSshGracefulShutdownTimeout is the default setting for Ssh.GracefulShutdownTimeout.
	DefaultSshGracefulShutdownTimeout = common.DurationOf(30 * time.Second)

	// DefaultSshHandshakeTimeout is the default setting for Ssh.HandshakeTimeout.
	DefaultSshHandshakeTimeout = common.DurationOf(2 * time.Minute)

	// DefaultSshSessionRequestTimeout is the default setting for Ssh.SessionRequestTimeout.
	DefaultSshSessionRequestTimeout = common.DurationOf(30 * time.Second)

	// DefaultSshMaxAuthTries is the default setting for Ssh.MaxAuthTries.
	DefaultSshMaxAuthTries = uint8(6)

	// DefaultSshMaxConnections is the default setting for Ssh.MaxConnections.
	DefaultSshMaxConnections = uint32(255)

	// DefaultSshMaxStartupsStart is the default setting for Ssh.MaxStartupsStart.
	DefaultSshMaxStartupsStart = uint16(10)

	// DefaultSshMaxStartupsRate is the default setting for Ssh.MaxStartupsRate.
	DefaultSshMaxStartupsRate = uint8(30)

	// DefaultSshMaxStartupsFull is the default setting for Ssh.MaxStartupsFull.
	DefaultSshMaxStartupsFull = uint16(100)

	// DefaultSshMaxSessionsPerConnection is the default setting for Ssh.MaxSessionsPerConnection.
	DefaultSshMaxSessionsPerConnection = uint16(10)

	// DefaultSshMaxChannelsPerConnection is the default setting for Ssh.MaxChannelsPerConnection.
	DefaultSshMaxChannelsPerConnection = uint16(64)

	// DefaultSshMaxReverseForwardsPerConnection is the default setting for Ssh.MaxReverseForwardsPerConnection.
	DefaultSshMaxReverseForwardsPerConnection = uint16(16)

	// DefaultSshMaxChannels is the default setting for Ssh.MaxChannels.
	DefaultSshMaxChannels = uint16(64)

	// DefaultSshMaxReverseForwards is the default setting for Ssh.MaxReverseForwards.
	DefaultSshMaxReverseForwards = uint16(256)

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

	// GracefulShutdownTimeout represents how long active connections may finish during a graceful shutdown before
	// they are forcibly closed. 0 disables graceful shutdown. Defaults to DefaultSshGracefulShutdownTimeout.
	GracefulShutdownTimeout common.Duration `yaml:"gracefulShutdownTimeout"`

	// HandshakeTimeout represents the maximum duration until a connection has authenticated successfully.
	// 0 means no limitation at all. Defaults to DefaultSshHandshakeTimeout.
	HandshakeTimeout common.Duration `yaml:"handshakeTimeout"`

	// SessionRequestTimeout represents how long an accepted session channel may wait for its initial shell, exec or
	// subsystem request. 0 means no limitation at all. Defaults to DefaultSshSessionRequestTimeout.
	SessionRequestTimeout common.Duration `yaml:"sessionRequestTimeout"`

	// MaxAuthTries represents the maximum amount of tries a client can do while a connection with different
	// authorizations before the connection will be forcibly closed. 0 means no limitation at all.
	// Defaults to DefaultSshMaxAuthTries.
	MaxAuthTries uint8 `yaml:"maxAuthTries"`

	// MaxConnections defines how many connection can be connected to this service in parallel. If there is a new
	// connection created which exceeds this number, this will be closed immediately.
	// Defaults to DefaultSshMaxConnections.
	MaxConnections uint32 `yaml:"maxConnections"`

	// MaxStartupsStart defines how many unauthenticated connections per listener are accepted before random early drop starts.
	// Defaults to DefaultSshMaxStartupsStart.
	MaxStartupsStart uint16 `yaml:"maxStartupsStart"`

	// MaxStartupsRate defines the initial drop probability in percent once MaxStartupsStart is reached.
	// Defaults to DefaultSshMaxStartupsRate.
	MaxStartupsRate uint8 `yaml:"maxStartupsRate"`

	// MaxStartupsFull defines the maximum amount of unauthenticated connections. 0 disables the complete
	// pre-authentication connection limit. Defaults to DefaultSshMaxStartupsFull.
	MaxStartupsFull uint16 `yaml:"maxStartupsFull"`

	// MaxSessionsPerConnection defines the maximum amount of active session channels per connection.
	// 0 means no limitation at all. Defaults to DefaultSshMaxSessionsPerConnection.
	MaxSessionsPerConnection uint16 `yaml:"maxSessionsPerConnection"`

	// MaxChannelsPerConnection defines the maximum amount of active channels per connection.
	// 0 means no limitation at all. Defaults to DefaultSshMaxChannelsPerConnection.
	MaxChannelsPerConnection uint16 `yaml:"maxChannelsPerConnection"`

	// MaxReverseForwardsPerConnection defines the maximum amount of active reverse forwards per connection.
	// 0 means no limitation at all. Defaults to DefaultSshMaxReverseForwardsPerConnection.
	MaxReverseForwardsPerConnection uint16 `yaml:"maxReverseForwardsPerConnection"`

	// MaxChannels defines the maximum amount of active channels per SSH listener.
	// 0 means no limitation at all. Defaults to DefaultSshMaxChannels.
	MaxChannels uint16 `yaml:"maxChannels"`

	// MaxReverseForwards defines the maximum amount of active reverse forwards per SSH listener.
	// 0 means no limitation at all. Defaults to DefaultSshMaxReverseForwards.
	MaxReverseForwards uint16 `yaml:"maxReverseForwards"`

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
		fixedDefault("gracefulShutdownTimeout", func(v *Ssh) *common.Duration { return &v.GracefulShutdownTimeout }, DefaultSshGracefulShutdownTimeout),
		fixedDefault("handshakeTimeout", func(v *Ssh) *common.Duration { return &v.HandshakeTimeout }, DefaultSshHandshakeTimeout),
		fixedDefault("sessionRequestTimeout", func(v *Ssh) *common.Duration { return &v.SessionRequestTimeout }, DefaultSshSessionRequestTimeout),
		fixedDefault("maxAuthTries", func(v *Ssh) *uint8 { return &v.MaxAuthTries }, DefaultSshMaxAuthTries),
		fixedDefault("maxConnections", func(v *Ssh) *uint32 { return &v.MaxConnections }, DefaultSshMaxConnections),
		fixedDefault("maxStartupsStart", func(v *Ssh) *uint16 { return &v.MaxStartupsStart }, DefaultSshMaxStartupsStart),
		fixedDefault("maxStartupsRate", func(v *Ssh) *uint8 { return &v.MaxStartupsRate }, DefaultSshMaxStartupsRate),
		fixedDefault("maxStartupsFull", func(v *Ssh) *uint16 { return &v.MaxStartupsFull }, DefaultSshMaxStartupsFull),
		fixedDefault("maxSessionsPerConnection", func(v *Ssh) *uint16 { return &v.MaxSessionsPerConnection }, DefaultSshMaxSessionsPerConnection),
		fixedDefault("maxChannelsPerConnection", func(v *Ssh) *uint16 { return &v.MaxChannelsPerConnection }, DefaultSshMaxChannelsPerConnection),
		fixedDefault("maxReverseForwardsPerConnection", func(v *Ssh) *uint16 { return &v.MaxReverseForwardsPerConnection }, DefaultSshMaxReverseForwardsPerConnection),
		fixedDefault("maxChannels", func(v *Ssh) *uint16 { return &v.MaxChannels }, DefaultSshMaxChannels),
		fixedDefault("maxReverseForwards", func(v *Ssh) *uint16 { return &v.MaxReverseForwards }, DefaultSshMaxReverseForwards),
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
		noopTrim[Ssh]("gracefulShutdownTimeout"),
		noopTrim[Ssh]("handshakeTimeout"),
		noopTrim[Ssh]("sessionRequestTimeout"),
		noopTrim[Ssh]("maxAuthTries"),
		noopTrim[Ssh]("maxConnections"),
		noopTrim[Ssh]("maxStartupsStart"),
		noopTrim[Ssh]("maxStartupsRate"),
		noopTrim[Ssh]("maxStartupsFull"),
		noopTrim[Ssh]("maxSessionsPerConnection"),
		noopTrim[Ssh]("maxChannelsPerConnection"),
		noopTrim[Ssh]("maxReverseForwardsPerConnection"),
		noopTrim[Ssh]("maxChannels"),
		noopTrim[Ssh]("maxReverseForwards"),
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
		func(v *Ssh) (string, validator) { return "idleTimeout", nonNegativeDurationValidator(&v.IdleTimeout) },
		func(v *Ssh) (string, validator) { return "maxTimeout", nonNegativeDurationValidator(&v.MaxTimeout) },
		func(v *Ssh) (string, validator) {
			return "gracefulShutdownTimeout", nonNegativeDurationValidator(&v.GracefulShutdownTimeout)
		},
		func(v *Ssh) (string, validator) {
			return "handshakeTimeout", nonNegativeDurationValidator(&v.HandshakeTimeout)
		},
		func(v *Ssh) (string, validator) {
			return "sessionRequestTimeout", nonNegativeDurationValidator(&v.SessionRequestTimeout)
		},
		noopValidate[Ssh]("maxAuthTries"),
		noopValidate[Ssh]("maxConnections"),
		noopValidate[Ssh]("maxStartupsStart"),
		func(v *Ssh) (string, validator) {
			return "maxStartupsRate", validatorFunc(func() error {
				if v.MaxStartupsRate > 100 {
					return fmt.Errorf("must be less than or equal to 100")
				}
				return nil
			})
		},
		func(v *Ssh) (string, validator) {
			return "maxStartupsFull", validatorFunc(func() error {
				if v.MaxStartupsFull > 0 && v.MaxStartupsStart > v.MaxStartupsFull {
					return fmt.Errorf("must be greater than or equal to maxStartupsStart")
				}
				return nil
			})
		},
		noopValidate[Ssh]("maxSessionsPerConnection"),
		noopValidate[Ssh]("maxChannelsPerConnection"),
		noopValidate[Ssh]("maxReverseForwardsPerConnection"),
		noopValidate[Ssh]("maxChannels"),
		noopValidate[Ssh]("maxReverseForwards"),
		noopValidate[Ssh]("proxyProtocol"),
		func(v *Ssh) (string, validator) { return "banner", &v.Banner },
		func(v *Ssh) (string, validator) { return "preparationMessages", &v.PreparationMessages },
	)
}

func nonNegativeDurationValidator(value *common.Duration) validator {
	return validatorFunc(func() error {
		if err := value.Validate(); err != nil {
			return err
		}
		if value.Native() < 0 {
			return fmt.Errorf("must be greater than or equal to 0")
		}
		return nil
	})
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
		isEqual(&this.GracefulShutdownTimeout, &other.GracefulShutdownTimeout) &&
		isEqual(&this.HandshakeTimeout, &other.HandshakeTimeout) &&
		isEqual(&this.SessionRequestTimeout, &other.SessionRequestTimeout) &&
		this.MaxAuthTries == other.MaxAuthTries &&
		this.MaxConnections == other.MaxConnections &&
		this.MaxStartupsStart == other.MaxStartupsStart &&
		this.MaxStartupsRate == other.MaxStartupsRate &&
		this.MaxStartupsFull == other.MaxStartupsFull &&
		this.MaxSessionsPerConnection == other.MaxSessionsPerConnection &&
		this.MaxChannelsPerConnection == other.MaxChannelsPerConnection &&
		this.MaxReverseForwardsPerConnection == other.MaxReverseForwardsPerConnection &&
		this.MaxChannels == other.MaxChannels &&
		this.MaxReverseForwards == other.MaxReverseForwards &&
		this.ProxyProtocol == other.ProxyProtocol &&
		isEqual(&this.Banner, &other.Banner) &&
		isEqual(&this.PreparationMessages, &other.PreparationMessages)
}
