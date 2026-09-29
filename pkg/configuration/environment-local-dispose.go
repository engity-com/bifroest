package configuration

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

type EnvironmentLocalDispose struct {
	DeleteOnDispose          template.Bool `yaml:"deleteOnDispose,omitempty"`
	DeleteManagedUser        template.Bool `yaml:"deleteManagedUser,omitempty"`
	DeleteManagedUserHomeDir template.Bool `yaml:"deleteManagedUserHomeDir,omitempty"`
	KillManagedUserProcesses template.Bool `yaml:"killManagedUserProcesses,omitempty"`
}

func (this *EnvironmentLocalDispose) SetDefaults() error {
	return nil
}

func (this *EnvironmentLocalDispose) Trim() error {
	return trim(this,
		noopTrim[EnvironmentLocalDispose]("deleteOnDispose"),
		noopTrim[EnvironmentLocalDispose]("deleteManagedUser"),
		noopTrim[EnvironmentLocalDispose]("deleteManagedUserHomeDir"),
		noopTrim[EnvironmentLocalDispose]("killManagedUserProcesses"),
	)
}

func (this *EnvironmentLocalDispose) Validate() error {
	for _, field := range []struct {
		name, replacement string
		value             template.Bool
	}{
		{"deleteOnDispose", "deleteOnDispose", this.DeleteOnDispose},
		{"deleteManagedUser", "deleteOnDispose", this.DeleteManagedUser},
		{"deleteManagedUserHomeDir", "deleteHomeTogetherWithUser", this.DeleteManagedUserHomeDir},
		{"killManagedUserProcesses", "killProcessesOnDispose", this.KillManagedUserProcesses},
	} {
		if !field.value.IsZero() {
			return fmt.Errorf("[%s] replaced by top-level %s; migrate this setting explicitly", field.name, field.replacement)
		}
	}
	return nil
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
	return isEqual(&this.DeleteOnDispose, &other.DeleteOnDispose) &&
		isEqual(&this.DeleteManagedUser, &other.DeleteManagedUser) &&
		isEqual(&this.DeleteManagedUserHomeDir, &other.DeleteManagedUserHomeDir) &&
		isEqual(&this.KillManagedUserProcesses, &other.KillManagedUserProcesses)
}
