package configuration

import (
	"github.com/engity-com/yasshd/pkg/common"
	"gopkg.in/yaml.v3"
)

var (
	// DefaultSessionIdleTimeout is the default setting for Session.IdleTimeout.
	DefaultSessionIdleTimeout = common.MustNewDuration("30m")

	// DefaultSessionMaxTimeout is the default setting for Session.MaxTimeout.
	DefaultSessionMaxTimeout = common.MustNewDuration("0")

	// DefaultSessionMaxConnections is the default setting for Session.MaxConnections.
	DefaultSessionMaxConnections uint16 = 10
)

// Session defines how the service should treat its sessions of a Flow.
type Session struct {
	// IdleTimeout represents the duration a session can be idle until it will be forcibly closed.
	// 0 means no limitation at all. Defaults to DefaultSessionIdleTimeout
	IdleTimeout common.Duration `yaml:"idleTimeout"`

	// MaxTimeout represents the maximum duration a whole session can last, regardless if it is idle or active
	// until it will be forcibly closed. 0 means no limitation at all. Defaults to DefaultSessionMaxTimeout
	MaxTimeout common.Duration `yaml:"maxTimeout"`

	// MaxConnections represents the maximum amount of connections that are related to one session. More than
	// this amount means that all new connections will be forcibly closed while connection process.
	// 0 means no limitation at all. Defaults to DefaultSessionMaxConnections
	MaxConnections uint16 `yaml:"maxConnections"`
}

func (this *Session) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("idleTimeout", func(v *Session) *common.Duration { return &v.IdleTimeout }, DefaultSessionIdleTimeout),
		fixedDefault("maxTimeout", func(v *Session) *common.Duration { return &v.MaxTimeout }, DefaultSessionMaxTimeout),
		fixedDefault("maxConnections", func(v *Session) *uint16 { return &v.MaxConnections }, DefaultSessionMaxConnections),
	)
}

func (this *Session) Trim() error {
	return trim(this,
		noopTrim[Session]("idleTimeout"),
		noopTrim[Session]("maxTimeout"),
		noopTrim[Session]("maxConnections"),
	)
}

func (this *Session) Validate() error {
	return validate(this,
		noopValidate[Session]("idleTimeout"),
		noopValidate[Session]("maxTimeout"),
		noopValidate[Session]("maxConnections"),
	)
}

func (this *Session) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Session, node *yaml.Node) error {
		type raw Session
		return node.Decode((*raw)(target))
	})
}

func (this Session) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Session:
		return this.isEqualTo(&v)
	case *Session:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Session) isEqualTo(other *Session) bool {
	return isEqual(&this.IdleTimeout, &other.IdleTimeout) &&
		isEqual(&this.MaxTimeout, &other.MaxTimeout) &&
		this.MaxConnections == other.MaxConnections
}
