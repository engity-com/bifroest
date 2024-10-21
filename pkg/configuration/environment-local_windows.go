//go:build windows

package configuration

import (
	"os"
	"os/user"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultShell = func() string {
		v, ok := os.LookupEnv("COMSPEC")
		if ok {
			return v
		}
		return `C:\WINDOWS\system32\cmd.exe`
	}()

	DefaultEnvironmentLocalShellCommand      = template.MustNewStrings(DefaultShell)
	DefaultEnvironmentLocalExecCommandPrefix = template.MustNewStrings(DefaultShell, "/C")
	DefaultEnvironmentLocalDirectory         = template.MustNewString(func() string {
		u, err := user.Current()
		if err == nil && u.HomeDir != "" {
			return u.HomeDir
		}
		return ""
	}())
)

type EnvironmentLocal struct {
	LoginAllowed template.Bool `yaml:"loginAllowed,omitempty"`

	Banner template.String `yaml:"banner,omitempty"`

	ShellCommand          template.Strings `yaml:"shellCommand,omitempty"`
	ExecCommandPrefix     template.Strings `yaml:"execCommandPrefix,omitempty"`
	Directory             template.String  `yaml:"directory,omitempty"`
	PortForwardingAllowed template.Bool    `yaml:"portForwardingAllowed,omitempty"`
}

func (this *EnvironmentLocal) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("loginAllowed", func(v *EnvironmentLocal) *template.Bool { return &v.LoginAllowed }, DefaultEnvironmentLocalLoginAllowed),
		fixedDefault("banner", func(v *EnvironmentLocal) *template.String { return &v.Banner }, DefaultEnvironmentLocalBanner),
		fixedDefault("shellCommand", func(v *EnvironmentLocal) *template.Strings { return &v.ShellCommand }, DefaultEnvironmentLocalShellCommand),
		fixedDefault("execCommandPrefix", func(v *EnvironmentLocal) *template.Strings { return &v.ExecCommandPrefix }, DefaultEnvironmentLocalExecCommandPrefix),
		fixedDefault("directory", func(v *EnvironmentLocal) *template.String { return &v.Directory }, DefaultEnvironmentLocalDirectory),
		fixedDefault("portForwardingAllowed", func(v *EnvironmentLocal) *template.Bool { return &v.PortForwardingAllowed }, DefaultEnvironmentLocalPortForwardingAllowed),
	)
}

func (this *EnvironmentLocal) Trim() error {
	return trim(this,
		noopTrim[EnvironmentLocal]("loginAllowed"),
		noopTrim[EnvironmentLocal]("banner"),
		noopTrim[EnvironmentLocal]("shellCommand"),
		noopTrim[EnvironmentLocal]("execCommandPrefix"),
		noopTrim[EnvironmentLocal]("directory"),
		noopTrim[EnvironmentLocal]("portForwardingAllowed"),
	)
}

func (this *EnvironmentLocal) Validate() error {
	return validate(this,
		func(v *EnvironmentLocal) (string, validator) { return "loginAllowed", &v.LoginAllowed },
		func(v *EnvironmentLocal) (string, validator) { return "banner", &v.Banner },
		func(v *EnvironmentLocal) (string, validator) { return "shellCommand", &v.ShellCommand },
		func(v *EnvironmentLocal) (string, validator) { return "execCommandPrefix", &v.ExecCommandPrefix },
		func(v *EnvironmentLocal) (string, validator) { return "directory", &v.Directory },
		func(v *EnvironmentLocal) (string, validator) {
			return "portForwardingAllowed", &v.PortForwardingAllowed
		},
	)
}

func (this *EnvironmentLocal) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentLocal, node *yaml.Node) error {
		type raw EnvironmentLocal
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentLocal) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case EnvironmentLocal:
		return this.isEqualTo(&v)
	case *EnvironmentLocal:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentLocal) isEqualTo(other *EnvironmentLocal) bool {
	return isEqual(&this.LoginAllowed, &other.LoginAllowed) &&
		isEqual(&this.Banner, &other.Banner) &&
		isEqual(&this.ShellCommand, &other.ShellCommand) &&
		isEqual(&this.ExecCommandPrefix, &other.ExecCommandPrefix) &&
		isEqual(&this.Directory, &other.Directory) &&
		isEqual(&this.PortForwardingAllowed, &other.PortForwardingAllowed)
}

func (this EnvironmentLocal) Types() []string {
	return []string{"local"}
}

func (this EnvironmentLocal) FeatureFlags() []string {
	return []string{"local"}
}
