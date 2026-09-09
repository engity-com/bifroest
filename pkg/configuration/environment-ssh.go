package configuration

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultEnvironmentSshConnectTimeout        = template.DurationOf(10 * time.Second)
	DefaultEnvironmentSshOs                    = sys.OsLinux
	DefaultEnvironmentSshLoginAllowed          = template.BoolOf(true)
	DefaultEnvironmentSshBanner                = template.MustNewString("")
	DefaultEnvironmentSshPortForwardingAllowed = template.BoolOf(true)

	_ = RegisterEnvironmentV(func() EnvironmentV { return &EnvironmentSsh{} })
)

type EnvironmentSsh struct {
	Address template.String `yaml:"address"`
	User    template.String `yaml:"user"`
	Os      sys.Os          `yaml:"os,omitempty"`

	KnownHosts        crypto.KnownHosts     `yaml:"knownHosts,omitempty"`
	KnownHostsFile    crypto.KnownHostsFile `yaml:"knownHostsFile,omitempty"`
	AcceptAllHostKeys bool                  `yaml:"acceptAllHostKeys,omitempty"`

	IdentityFiles  template.Strings           `yaml:"identityFiles,omitempty"`
	Certificate    *EnvironmentSshCertificate `yaml:"certificate,omitempty"`
	ConnectTimeout template.Duration          `yaml:"connectTimeout,omitempty"`

	LoginAllowed          template.Bool   `yaml:"loginAllowed,omitempty"`
	Banner                template.String `yaml:"banner,omitempty"`
	PortForwardingAllowed template.Bool   `yaml:"portForwardingAllowed,omitempty"`
}

func (this *EnvironmentSsh) SetDefaults() error {
	return setDefaults(this,
		noopSetDefault[EnvironmentSsh]("address"),
		noopSetDefault[EnvironmentSsh]("user"),
		fixedDefault("os", func(v *EnvironmentSsh) *sys.Os { return &v.Os }, DefaultEnvironmentSshOs),
		noopSetDefault[EnvironmentSsh]("knownHosts"),
		noopSetDefault[EnvironmentSsh]("knownHostsFile"),
		noopSetDefault[EnvironmentSsh]("acceptAllHostKeys"),
		noopSetDefault[EnvironmentSsh]("identityFiles"),
		noopSetDefault[EnvironmentSsh]("certificate"),
		fixedDefault("connectTimeout", func(v *EnvironmentSsh) *template.Duration { return &v.ConnectTimeout }, DefaultEnvironmentSshConnectTimeout),
		fixedDefault("loginAllowed", func(v *EnvironmentSsh) *template.Bool { return &v.LoginAllowed }, DefaultEnvironmentSshLoginAllowed),
		fixedDefault("banner", func(v *EnvironmentSsh) *template.String { return &v.Banner }, DefaultEnvironmentSshBanner),
		fixedDefault("portForwardingAllowed", func(v *EnvironmentSsh) *template.Bool { return &v.PortForwardingAllowed }, DefaultEnvironmentSshPortForwardingAllowed),
	)
}

func (this *EnvironmentSsh) Trim() error {
	return trim(this,
		noopTrim[EnvironmentSsh]("address"),
		noopTrim[EnvironmentSsh]("user"),
		noopTrim[EnvironmentSsh]("os"),
		func(v *EnvironmentSsh) (string, trimmer) { return "knownHosts", &v.KnownHosts },
		func(v *EnvironmentSsh) (string, trimmer) { return "knownHostsFile", &v.KnownHostsFile },
		noopTrim[EnvironmentSsh]("acceptAllHostKeys"),
		noopTrim[EnvironmentSsh]("identityFiles"),
		noopTrim[EnvironmentSsh]("certificate"),
		noopTrim[EnvironmentSsh]("connectTimeout"),
		noopTrim[EnvironmentSsh]("loginAllowed"),
		noopTrim[EnvironmentSsh]("banner"),
		noopTrim[EnvironmentSsh]("portForwardingAllowed"),
	)
}

func (this *EnvironmentSsh) Validate() error {
	if len(this.IdentityFiles) > 0 && this.Certificate != nil {
		return fmt.Errorf("[identityFiles] cannot be combined with [certificate]")
	}
	if this.AcceptAllHostKeys && (!this.KnownHosts.IsZero() || !this.KnownHostsFile.IsZero()) {
		return fmt.Errorf("[acceptAllHostKeys] cannot be combined with knownHosts or knownHostsFile")
	}
	if !this.AcceptAllHostKeys && this.KnownHosts.IsZero() && this.KnownHostsFile.IsZero() {
		return fmt.Errorf("[knownHosts] or [knownHostsFile] required unless [acceptAllHostKeys] is true")
	}
	for i, identity := range this.IdentityFiles {
		if identity.IsZero() {
			return fmt.Errorf("[identityFiles][%d] required but absent", i)
		}
	}
	if this.Address.IsHardCoded() {
		var address net.HostPort
		if err := address.Set(this.Address.String()); err != nil {
			return fmt.Errorf("[address] %w", err)
		}
		if err := address.Validate(); err != nil {
			return fmt.Errorf("[address] %w", err)
		}
	}
	if this.User.IsHardCoded() && strings.TrimSpace(this.User.String()) == "" {
		return fmt.Errorf("[user] required but absent")
	}
	if this.ConnectTimeout.IsHardCoded() {
		value, _ := this.ConnectTimeout.Render(nil)
		if value < 0 {
			return fmt.Errorf("[connectTimeout] cannot be negative")
		}
	}
	return validate(this,
		notZeroValidate("address", func(v *EnvironmentSsh) *template.String { return &v.Address }),
		notZeroValidate("user", func(v *EnvironmentSsh) *template.String { return &v.User }),
		func(v *EnvironmentSsh) (string, validator) { return "os", &v.Os },
		func(v *EnvironmentSsh) (string, validator) { return "knownHosts", &v.KnownHosts },
		func(v *EnvironmentSsh) (string, validator) { return "knownHostsFile", &v.KnownHostsFile },
		func(v *EnvironmentSsh) (string, validator) { return "identityFiles", &v.IdentityFiles },
		func(v *EnvironmentSsh) (string, validator) { return "certificate", v.Certificate },
		func(v *EnvironmentSsh) (string, validator) { return "connectTimeout", &v.ConnectTimeout },
		func(v *EnvironmentSsh) (string, validator) { return "loginAllowed", &v.LoginAllowed },
		func(v *EnvironmentSsh) (string, validator) { return "banner", &v.Banner },
		func(v *EnvironmentSsh) (string, validator) { return "portForwardingAllowed", &v.PortForwardingAllowed },
	)
}

func (this *EnvironmentSsh) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentSsh, node *yaml.Node) error {
		type raw EnvironmentSsh
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentSsh) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case EnvironmentSsh:
		return this.isEqualTo(&v)
	case *EnvironmentSsh:
		return v != nil && this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentSsh) isEqualTo(other *EnvironmentSsh) bool {
	return isEqual(&this.Address, &other.Address) &&
		isEqual(&this.User, &other.User) &&
		isEqual(&this.Os, &other.Os) &&
		isEqual(&this.KnownHosts, &other.KnownHosts) &&
		isEqual(&this.KnownHostsFile, &other.KnownHostsFile) &&
		this.AcceptAllHostKeys == other.AcceptAllHostKeys &&
		isEqual(&this.IdentityFiles, &other.IdentityFiles) &&
		isEqual(this.Certificate, other.Certificate) &&
		isEqual(&this.ConnectTimeout, &other.ConnectTimeout) &&
		isEqual(&this.LoginAllowed, &other.LoginAllowed) &&
		isEqual(&this.Banner, &other.Banner) &&
		isEqual(&this.PortForwardingAllowed, &other.PortForwardingAllowed)
}

func (this EnvironmentSsh) Types() []string { return []string{"ssh"} }

func (this EnvironmentSsh) FeatureFlags() []string { return []string{"ssh"} }

func (this EnvironmentSsh) SupportsEnvironmentVariables() bool { return true }
