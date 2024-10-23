package configuration

import (
	"github.com/docker/docker/api/types/network"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultEnvironmentDockerLoginAllowed = template.BoolOf(true)

	DefaultEnvironmentDockerHost       = template.MustNewString("{{ env `DOCKER_HOST` }}")
	DefaultEnvironmentDockerApiVersion = template.MustNewString("{{ env `DOCKER_API_VERSION` }}")
	DefaultEnvironmentDockerCertPath   = template.MustNewString("{{ env `DOCKER_CERT_PATH` }}")
	DefaultEnvironmentDockerTlsVerify  = template.MustNewBool("{{ env `DOCKER_TLS_VERIFY` | ne `` }}")

	DefaultEnvironmentDockerImage                = template.MustNewString("alpine")
	DefaultEnvironmentDockerImagePullPolicy      = PullPolicyIfAbsent
	DefaultEnvironmentDockerImagePullCredentials = template.MustNewString("")
	DefaultEnvironmentDockerNetworks             = template.MustNewStrings(network.NetworkDefault)
	DefaultEnvironmentDockerVolumes              = template.MustNewStrings()
	DefaultEnvironmentDockerMounts               = template.MustNewStrings()
	DefaultEnvironmentDockerCapabilities         = template.MustNewStrings()
	DefaultEnvironmentDockerPrivileged           = template.BoolOf(false)
	DefaultEnvironmentDockerDnsServers           = template.MustNewStrings()
	DefaultEnvironmentDockerDnsSearch            = template.MustNewStrings()
	DefaultEnvironmentDockerShellCommand         = template.MustNewStrings()
	DefaultEnvironmentDockerExecCommand          = template.MustNewStrings()
	DefaultEnvironmentDockerSftpCommand          = template.MustNewStrings()
	DefaultEnvironmentDockerDirectory            = template.MustNewString("")
	DefaultEnvironmentDockerUser                 = template.MustNewString("")

	DefaultEnvironmentDockerBanner                = template.MustNewString("")
	DefaultEnvironmentDockerPortForwardingAllowed = template.BoolOf(true)
	DefaultEnvironmentDockerImpPublishHost        = net.MustNewHost("")

	DefaultEnvironmentDockerCleanOrphan = template.BoolOf(true)

	_ = RegisterEnvironmentV(func() EnvironmentV {
		return &EnvironmentDocker{}
	})
)

type EnvironmentDocker struct {
	LoginAllowed template.Bool `yaml:"loginAllowed,omitempty"`

	Host       template.String `yaml:"host,omitempty"`
	ApiVersion template.String `yaml:"apiVersion,omitempty"`
	CertPath   template.String `yaml:"certPath,omitempty"`
	TlsVerify  template.Bool   `yaml:"tlsVerify,omitempty"`

	Image                template.String  `yaml:"image"`
	ImagePullPolicy      PullPolicy       `yaml:"imagePullPolicy,omitempty"`
	ImagePullCredentials template.String  `yaml:"imagePullCredentials,omitempty"`
	Networks             template.Strings `yaml:"networks"`
	Volumes              template.Strings `yaml:"volumes,omitempty"`
	Mounts               template.Strings `yaml:"mounts,omitempty"`
	Capabilities         template.Strings `yaml:"capabilities,omitempty"`
	Privileged           template.Bool    `yaml:"privileged,omitempty"`
	DnsServers           template.Strings `yaml:"dnsServers,omitempty"`
	DnsSearch            template.Strings `yaml:"dnsSearch,omitempty"`

	ShellCommand template.Strings `yaml:"shellCommand,omitempty"`
	ExecCommand  template.Strings `yaml:"execCommand,omitempty"`
	SftpCommand  template.Strings `yaml:"sftpCommand,omitempty"`
	Directory    template.String  `yaml:"directory"`
	User         template.String  `yaml:"user,omitempty"`

	Banner template.String `yaml:"banner,omitempty"`

	PortForwardingAllowed template.Bool `yaml:"portForwardingAllowed,omitempty"`
	ImpPublishHost        net.Host      `yaml:"impPublishHost,omitempty"`

	CleanOrphan template.Bool `yaml:"cleanOrphan,omitempty"`
}

func (this *EnvironmentDocker) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("loginAllowed", func(v *EnvironmentDocker) *template.Bool { return &v.LoginAllowed }, DefaultEnvironmentDockerLoginAllowed),

		fixedDefault("host", func(v *EnvironmentDocker) *template.String { return &v.Host }, DefaultEnvironmentDockerHost),
		fixedDefault("apiVersion", func(v *EnvironmentDocker) *template.String { return &v.ApiVersion }, DefaultEnvironmentDockerApiVersion),
		fixedDefault("certPath", func(v *EnvironmentDocker) *template.String { return &v.CertPath }, DefaultEnvironmentDockerCertPath),
		fixedDefault("tlsVerify", func(v *EnvironmentDocker) *template.Bool { return &v.TlsVerify }, DefaultEnvironmentDockerTlsVerify),

		fixedDefault("image", func(v *EnvironmentDocker) *template.String { return &v.Image }, DefaultEnvironmentDockerImage),
		fixedDefault("imagePullPolicy", func(v *EnvironmentDocker) *PullPolicy { return &v.ImagePullPolicy }, DefaultEnvironmentDockerImagePullPolicy),
		fixedDefault("imagePullCredentials", func(v *EnvironmentDocker) *template.String { return &v.ImagePullCredentials }, DefaultEnvironmentDockerImagePullCredentials),
		fixedDefault("network", func(v *EnvironmentDocker) *template.Strings { return &v.Networks }, DefaultEnvironmentDockerNetworks),
		fixedDefault("volumes", func(v *EnvironmentDocker) *template.Strings { return &v.Volumes }, DefaultEnvironmentDockerVolumes),
		fixedDefault("mounts", func(v *EnvironmentDocker) *template.Strings { return &v.Mounts }, DefaultEnvironmentDockerMounts),
		fixedDefault("capabilities", func(v *EnvironmentDocker) *template.Strings { return &v.Capabilities }, DefaultEnvironmentDockerCapabilities),
		fixedDefault("privileged", func(v *EnvironmentDocker) *template.Bool { return &v.Privileged }, DefaultEnvironmentDockerPrivileged),
		fixedDefault("dnsServers", func(v *EnvironmentDocker) *template.Strings { return &v.DnsServers }, DefaultEnvironmentDockerDnsServers),
		fixedDefault("dnsSearch", func(v *EnvironmentDocker) *template.Strings { return &v.DnsSearch }, DefaultEnvironmentDockerDnsSearch),

		fixedDefault("shellCommand", func(v *EnvironmentDocker) *template.Strings { return &v.ShellCommand }, DefaultEnvironmentDockerShellCommand),
		fixedDefault("execCommand", func(v *EnvironmentDocker) *template.Strings { return &v.ExecCommand }, DefaultEnvironmentDockerExecCommand),
		fixedDefault("sftpCommand", func(v *EnvironmentDocker) *template.Strings { return &v.SftpCommand }, DefaultEnvironmentDockerSftpCommand),
		fixedDefault("directory", func(v *EnvironmentDocker) *template.String { return &v.Directory }, DefaultEnvironmentDockerDirectory),
		fixedDefault("user", func(v *EnvironmentDocker) *template.String { return &v.User }, DefaultEnvironmentDockerUser),

		fixedDefault("banner", func(v *EnvironmentDocker) *template.String { return &v.Banner }, DefaultEnvironmentDockerBanner),

		fixedDefault("portForwardingAllowed", func(v *EnvironmentDocker) *template.Bool { return &v.PortForwardingAllowed }, DefaultEnvironmentDockerPortForwardingAllowed),
		fixedDefault("impPublishHost", func(v *EnvironmentDocker) *net.Host { return &v.ImpPublishHost }, DefaultEnvironmentDockerImpPublishHost),

		fixedDefault("cleanOrphan", func(v *EnvironmentDocker) *template.Bool { return &v.CleanOrphan }, DefaultEnvironmentDockerCleanOrphan),
	)
}

func (this *EnvironmentDocker) Trim() error {
	return trim(this,
		noopTrim[EnvironmentDocker]("loginAllowed"),

		noopTrim[EnvironmentDocker]("host"),
		noopTrim[EnvironmentDocker]("apiVersion"),
		noopTrim[EnvironmentDocker]("certPath"),
		noopTrim[EnvironmentDocker]("tlsVerify"),

		noopTrim[EnvironmentDocker]("name"),
		noopTrim[EnvironmentDocker]("image"),
		noopTrim[EnvironmentDocker]("imagePullPolicy"),
		noopTrim[EnvironmentDocker]("imagePullCredentials"),
		noopTrim[EnvironmentDocker]("network"),
		noopTrim[EnvironmentDocker]("volumes"),
		noopTrim[EnvironmentDocker]("mounts"),
		noopTrim[EnvironmentDocker]("capabilities"),
		noopTrim[EnvironmentDocker]("privileged"),
		noopTrim[EnvironmentDocker]("dnsServers"),
		noopTrim[EnvironmentDocker]("dnsSearch"),
		noopTrim[EnvironmentDocker]("shellCommand"),
		noopTrim[EnvironmentDocker]("execCommand"),
		noopTrim[EnvironmentDocker]("sftpCommand"),
		noopTrim[EnvironmentDocker]("directory"),
		noopTrim[EnvironmentDocker]("user"),

		noopTrim[EnvironmentDocker]("banner"),

		noopTrim[EnvironmentDocker]("portForwardingAllowed"),

		noopTrim[EnvironmentDocker]("impPublishHost"),

		noopTrim[EnvironmentDocker]("cleanOrphan"),
	)
}

func (this *EnvironmentDocker) Validate() error {
	return validate(this,
		func(v *EnvironmentDocker) (string, validator) { return "loginAllowed", &v.LoginAllowed },

		func(v *EnvironmentDocker) (string, validator) { return "host", &v.Host },
		func(v *EnvironmentDocker) (string, validator) { return "apiVersion", &v.ApiVersion },
		func(v *EnvironmentDocker) (string, validator) { return "certPath", &v.CertPath },
		func(v *EnvironmentDocker) (string, validator) { return "tlsVerify", &v.TlsVerify },

		func(v *EnvironmentDocker) (string, validator) { return "image", &v.Image },
		notZeroValidate("image", func(v *EnvironmentDocker) *template.String { return &v.Image }),
		func(v *EnvironmentDocker) (string, validator) { return "imagePullPolicy", &v.ImagePullPolicy },
		func(v *EnvironmentDocker) (string, validator) { return "imagePullCredentials", &v.ImagePullCredentials },
		func(v *EnvironmentDocker) (string, validator) { return "network", &v.Networks },
		notZeroValidate("network", func(v *EnvironmentDocker) *template.Strings { return &v.Networks }),
		func(v *EnvironmentDocker) (string, validator) { return "volumes", &v.Volumes },
		func(v *EnvironmentDocker) (string, validator) { return "mounts", &v.Mounts },
		func(v *EnvironmentDocker) (string, validator) { return "capabilities", &v.Capabilities },
		func(v *EnvironmentDocker) (string, validator) { return "privileged", &v.Privileged },
		func(v *EnvironmentDocker) (string, validator) { return "dnsServers", &v.DnsServers },
		func(v *EnvironmentDocker) (string, validator) { return "dnsSearch", &v.DnsSearch },
		func(v *EnvironmentDocker) (string, validator) { return "shellCommand", &v.ShellCommand },
		func(v *EnvironmentDocker) (string, validator) { return "execCommand", &v.ExecCommand },
		func(v *EnvironmentDocker) (string, validator) { return "sftpCommand", &v.SftpCommand },
		func(v *EnvironmentDocker) (string, validator) { return "directory", &v.Directory },
		func(v *EnvironmentDocker) (string, validator) { return "user", &v.User },

		func(v *EnvironmentDocker) (string, validator) { return "banner", &v.Banner },

		func(v *EnvironmentDocker) (string, validator) {
			return "portForwardingAllowed", &v.PortForwardingAllowed
		},

		func(v *EnvironmentDocker) (string, validator) { return "impPublishHost", &v.ImpPublishHost },

		func(v *EnvironmentDocker) (string, validator) { return "cleanOrphan", &v.CleanOrphan },
	)
}

func (this *EnvironmentDocker) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentDocker, node *yaml.Node) error {
		type raw EnvironmentDocker
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentDocker) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case EnvironmentDocker:
		return this.isEqualTo(&v)
	case *EnvironmentDocker:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentDocker) isEqualTo(other *EnvironmentDocker) bool {
	return isEqual(&this.LoginAllowed, &other.LoginAllowed) &&
		isEqual(&this.Host, &other.Host) &&
		isEqual(&this.ApiVersion, &other.ApiVersion) &&
		isEqual(&this.CertPath, &other.CertPath) &&
		isEqual(&this.TlsVerify, &other.TlsVerify) &&
		isEqual(&this.Image, &other.Image) &&
		isEqual(&this.ImagePullPolicy, &other.ImagePullPolicy) &&
		isEqual(&this.ImagePullCredentials, &other.ImagePullCredentials) &&
		isEqual(&this.Networks, &other.Networks) &&
		isEqual(&this.Volumes, &other.Volumes) &&
		isEqual(&this.Mounts, &other.Mounts) &&
		isEqual(&this.Capabilities, &other.Capabilities) &&
		isEqual(&this.Privileged, &other.Privileged) &&
		isEqual(&this.DnsServers, &other.DnsServers) &&
		isEqual(&this.DnsSearch, &other.DnsSearch) &&
		isEqual(&this.ShellCommand, &other.ShellCommand) &&
		isEqual(&this.ExecCommand, &other.ExecCommand) &&
		isEqual(&this.SftpCommand, &other.SftpCommand) &&
		isEqual(&this.Directory, &other.Directory) &&
		isEqual(&this.User, &other.User) &&
		isEqual(&this.Banner, &other.Banner) &&
		isEqual(&this.PortForwardingAllowed, &other.PortForwardingAllowed) &&
		isEqual(&this.ImpPublishHost, &other.ImpPublishHost) &&
		isEqual(&this.CleanOrphan, &other.CleanOrphan)
}

func (this EnvironmentDocker) Types() []string {
	return []string{"docker"}
}

func (this EnvironmentDocker) FeatureFlags() []string {
	return []string{"docker"}
}
