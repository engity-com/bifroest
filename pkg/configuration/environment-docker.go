package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultEnvironmentDockerLoginAllowed = template.BoolOf(true)

	DefaultEnvironmentDockerHost       = template.MustNewString("{{ env `DOCKER_HOST` }}")
	DefaultEnvironmentDockerApiVersion = template.MustNewString("{{ env `DOCKER_API_VERSION` }}")
	DefaultEnvironmentDockerCertPath   = template.MustNewString("{{ env `DOCKER_CERT_PATH` }}")
	DefaultEnvironmentDockerTlsVerify  = template.MustNewBool("{{ env `DOCKER_TLS_VERIFY` | ne `` }}")

	DefaultEnvironmentDockerName         = template.MustNewString("bifroest-{{ .authorization.session.id }}")
	DefaultEnvironmentDockerImage        = template.MustNewString("alpine:latest")
	DefaultEnvironmentDockerShellCommand = template.MustNewStrings()
	DefaultEnvironmentDockerExecCommand  = template.MustNewStrings()
	DefaultEnvironmentDockerSftpCommand  = template.MustNewStrings()
	DefaultEnvironmentDockerBlockCommand = template.MustNewStrings()
	DefaultEnvironmentDockerDirectory    = template.MustNewString("")
	DefaultEnvironmentDockerUser         = template.MustNewString("")

	DefaultEnvironmentDockerBanner                = template.MustNewString("")
	DefaultEnvironmentDockerPortForwardingAllowed = template.BoolOf(true)

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

	Name         template.String  `yaml:"name"`
	Image        template.String  `yaml:"image"`
	ShellCommand template.Strings `yaml:"shellCommand,omitempty"`
	ExecCommand  template.Strings `yaml:"execCommand,omitempty"`
	SftpCommand  template.Strings `yaml:"sftpCommand,omitempty"`
	BlockCommand template.Strings `yaml:"blockCommand,omitempty"`
	Directory    template.String  `yaml:"directory"`
	User         template.String  `yaml:"user,omitempty"`

	Banner template.String `yaml:"banner,omitempty"`

	PortForwardingAllowed template.Bool `yaml:"portForwardingAllowed,omitempty"`
}

func (this *EnvironmentDocker) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("loginAllowed", func(v *EnvironmentDocker) *template.Bool { return &v.LoginAllowed }, DefaultEnvironmentDockerLoginAllowed),

		fixedDefault("host", func(v *EnvironmentDocker) *template.String { return &v.Host }, DefaultEnvironmentDockerHost),
		fixedDefault("apiVersion", func(v *EnvironmentDocker) *template.String { return &v.ApiVersion }, DefaultEnvironmentDockerApiVersion),
		fixedDefault("certPath", func(v *EnvironmentDocker) *template.String { return &v.CertPath }, DefaultEnvironmentDockerCertPath),
		fixedDefault("tlsVerify", func(v *EnvironmentDocker) *template.Bool { return &v.TlsVerify }, DefaultEnvironmentDockerTlsVerify),

		fixedDefault("name", func(v *EnvironmentDocker) *template.String { return &v.Name }, DefaultEnvironmentDockerName),
		fixedDefault("image", func(v *EnvironmentDocker) *template.String { return &v.Image }, DefaultEnvironmentDockerImage),
		fixedDefault("shellCommand", func(v *EnvironmentDocker) *template.Strings { return &v.ShellCommand }, DefaultEnvironmentDockerShellCommand),
		fixedDefault("execCommand", func(v *EnvironmentDocker) *template.Strings { return &v.ExecCommand }, DefaultEnvironmentDockerExecCommand),
		fixedDefault("sftpCommand", func(v *EnvironmentDocker) *template.Strings { return &v.SftpCommand }, DefaultEnvironmentDockerSftpCommand),
		fixedDefault("blockCommand", func(v *EnvironmentDocker) *template.Strings { return &v.BlockCommand }, DefaultEnvironmentDockerBlockCommand),
		fixedDefault("directory", func(v *EnvironmentDocker) *template.String { return &v.Directory }, DefaultEnvironmentDockerDirectory),
		fixedDefault("user", func(v *EnvironmentDocker) *template.String { return &v.User }, DefaultEnvironmentDockerUser),

		fixedDefault("banner", func(v *EnvironmentDocker) *template.String { return &v.Banner }, DefaultEnvironmentDockerBanner),

		fixedDefault("portForwardingAllowed", func(v *EnvironmentDocker) *template.Bool { return &v.PortForwardingAllowed }, DefaultEnvironmentDockerPortForwardingAllowed),
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
		noopTrim[EnvironmentDocker]("shellCommand"),
		noopTrim[EnvironmentDocker]("execCommand"),
		noopTrim[EnvironmentDocker]("blockCommand"),
		noopTrim[EnvironmentDocker]("sftpCommand"),
		noopTrim[EnvironmentDocker]("directory"),
		noopTrim[EnvironmentDocker]("user"),

		noopTrim[EnvironmentDocker]("banner"),

		noopTrim[EnvironmentDocker]("portForwardingAllowed"),
	)
}

func (this *EnvironmentDocker) Validate() error {
	return validate(this,
		noopValidate[EnvironmentDocker]("loginAllowed"),

		noopValidate[EnvironmentDocker]("host"),
		noopValidate[EnvironmentDocker]("apiVersion"),
		noopValidate[EnvironmentDocker]("certPath"),
		noopValidate[EnvironmentDocker]("tlsVerify"),

		notZeroValidate("name", func(v *EnvironmentDocker) *template.String { return &v.Name }),
		notZeroValidate("image", func(v *EnvironmentDocker) *template.String { return &v.Image }),
		noopValidate[EnvironmentDocker]("shellCommand"),
		noopValidate[EnvironmentDocker]("execCommand"),
		noopValidate[EnvironmentDocker]("blockCommand"),
		noopValidate[EnvironmentDocker]("sftpCommand"),
		noopValidate[EnvironmentDocker]("directory"),
		noopValidate[EnvironmentDocker]("user"),

		noopValidate[EnvironmentDocker]("banner"),

		noopValidate[EnvironmentDocker]("portForwardingAllowed"),
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
		isEqual(&this.Name, &other.Name) &&
		isEqual(&this.Image, &other.Image) &&
		isEqual(&this.ShellCommand, &other.ShellCommand) &&
		isEqual(&this.ExecCommand, &other.ExecCommand) &&
		isEqual(&this.BlockCommand, &other.BlockCommand) &&
		isEqual(&this.SftpCommand, &other.SftpCommand) &&
		isEqual(&this.Directory, &other.Directory) &&
		isEqual(&this.User, &other.User) &&
		isEqual(&this.Banner, &other.Banner) &&
		isEqual(&this.PortForwardingAllowed, &other.PortForwardingAllowed)
}

func (this EnvironmentDocker) Types() []string {
	return []string{"docker"}
}

func (this EnvironmentDocker) FeatureFlags() []string {
	return []string{"docker"}
}
