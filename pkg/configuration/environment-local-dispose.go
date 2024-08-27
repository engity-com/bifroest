//go:build unix

package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultEnvironmentLocalDisposeDeleteManagedUser        = template.BoolOf(true)
	DefaultEnvironmentLocalDisposeDeleteManagedUserHomeDir = template.BoolOf(true)
	DefaultEnvironmentLocalDisposeKillManagedUserProcesses = template.BoolOf(true)
)

type EnvironmentLocalDispose struct {
	DeleteManagedUser        template.Bool `yaml:"deleteManagedUser,omitempty"`
	DeleteManagedUserHomeDir template.Bool `yaml:"deleteManagedUserHomeDir,omitempty"`
	KillManagedUserProcesses template.Bool `yaml:"killManagedUserProcesses,omitempty"`
}

func (this *EnvironmentLocalDispose) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("deleteManagedUser", func(v *EnvironmentLocalDispose) *template.Bool { return &v.DeleteManagedUser }, DefaultEnvironmentLocalDisposeDeleteManagedUser),
		fixedDefault("deleteManagedUserHomeDir", func(v *EnvironmentLocalDispose) *template.Bool { return &v.DeleteManagedUserHomeDir }, DefaultEnvironmentLocalDisposeDeleteManagedUserHomeDir),
		fixedDefault("killManagedUserProcesses", func(v *EnvironmentLocalDispose) *template.Bool { return &v.KillManagedUserProcesses }, DefaultEnvironmentLocalDisposeKillManagedUserProcesses),
	)
}

func (this *EnvironmentLocalDispose) Trim() error {
	return trim(this,
		noopTrim[EnvironmentLocalDispose]("deleteManagedUser"),
		noopTrim[EnvironmentLocalDispose]("deleteManagedUserHomeDir"),
		noopTrim[EnvironmentLocalDispose]("killManagedUserProcesses"),
	)
}

func (this *EnvironmentLocalDispose) Validate() error {
	return validate(this,
		noopValidate[EnvironmentLocalDispose]("deleteManagedUser"),
		noopValidate[EnvironmentLocalDispose]("deleteManagedUserHomeDir"),
		noopValidate[EnvironmentLocalDispose]("killManagedUserProcesses"),
	)
}

func (this *EnvironmentLocalDispose) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentLocalDispose, node *yaml.Node) error {
		type raw EnvironmentLocalDispose
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentLocalDispose) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case EnvironmentLocalDispose:
		return this.isEqualTo(&v)
	case *EnvironmentLocalDispose:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentLocalDispose) isEqualTo(other *EnvironmentLocalDispose) bool {
	return isEqual(&this.DeleteManagedUser, &other.DeleteManagedUser) &&
		isEqual(&this.DeleteManagedUserHomeDir, &other.DeleteManagedUserHomeDir) &&
		isEqual(&this.KillManagedUserProcesses, &other.KillManagedUserProcesses)
}
