package configuration

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
	"gopkg.in/yaml.v3"
)

var (
	// DefaultSessionFsStorage is the default setting for SessionFs.Storage.
	DefaultSessionFsStorage = defaultSessionFsStorage
	// DefaultSessionFsFileMode is the default setting for SessionFs.FileMode.
	DefaultSessionFsFileMode = sys.FileMode(0600)

	_ = RegisterSessionV(func() SessionV {
		return &SessionFs{}
	})
)

// SessionFs defines an implementation of Session on file system base.
type SessionFs struct {
	// IdleTimeout represents the duration a session can be idle until it will be forcibly closed,
	// cleaned up and no new access is possible. 0 means no limitation at all.
	// Defaults to DefaultSessionIdleTimeout
	IdleTimeout common.Duration `yaml:"idleTimeout"`

	// MaxTimeout represents the maximum duration a whole session can last, regardless if it is idle
	// or active until it will be forcibly closed, cleaned up and no new access is possible. 0 means
	// no limitation at all. Defaults to DefaultSessionMaxTimeout
	MaxTimeout common.Duration `yaml:"maxTimeout"`

	// MaxConnections represents the maximum amount of connections that are related to one session. More than
	// this amount means that all new connections will be forcibly closed while connection process.
	// 0 means no limitation at all. Defaults to DefaultSessionMaxConnections
	MaxConnections uint16 `yaml:"maxConnections"`

	// Storage defines where are session.Fs are stored. Defaults to DefaultSessionFsStorage
	Storage string `yaml:"storage"`

	// FileMode defines with which permissions the files should be stored. Defaults to DefaultSessionFsFileMode.
	FileMode sys.FileMode `yaml:"fileMode"`
}

func (this *SessionFs) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("idleTimeout", func(v *SessionFs) *common.Duration { return &v.IdleTimeout }, DefaultSessionIdleTimeout),
		fixedDefault("maxTimeout", func(v *SessionFs) *common.Duration { return &v.MaxTimeout }, DefaultSessionMaxTimeout),
		fixedDefault("maxConnections", func(v *SessionFs) *uint16 { return &v.MaxConnections }, DefaultSessionMaxConnections),
		fixedDefault("storage", func(v *SessionFs) *string { return &v.Storage }, DefaultSessionFsStorage),
		fixedDefault("fileMode", func(v *SessionFs) *sys.FileMode { return &v.FileMode }, DefaultSessionFsFileMode),
	)
}

func (this *SessionFs) Trim() error {
	return trim(this,
		noopTrim[SessionFs]("idleTimeout"),
		noopTrim[SessionFs]("maxTimeout"),
		noopTrim[SessionFs]("maxConnections"),
		noopTrim[SessionFs]("storage"),
		noopTrim[SessionFs]("fileMode"),
	)
}

func (this *SessionFs) Validate() error {
	return validate(this,
		noopValidate[SessionFs]("idleTimeout"),
		noopValidate[SessionFs]("maxTimeout"),
		noopValidate[SessionFs]("maxConnections"),
		noopValidate[SessionFs]("storage"),
		noopValidate[SessionFs]("fileMode"),
	)
}

func (this *SessionFs) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *SessionFs, node *yaml.Node) error {
		type raw SessionFs
		return node.Decode((*raw)(target))
	})
}

func (this SessionFs) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case SessionFs:
		return this.isEqualTo(&v)
	case *SessionFs:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this SessionFs) isEqualTo(other *SessionFs) bool {
	return isEqual(&this.IdleTimeout, &other.IdleTimeout) &&
		isEqual(&this.MaxTimeout, &other.MaxTimeout) &&
		this.MaxConnections == other.MaxConnections &&
		this.Storage == other.Storage &&
		this.FileMode == other.FileMode
}

func (this SessionFs) Types() []string {
	return []string{"fs", "file-system"}
}
