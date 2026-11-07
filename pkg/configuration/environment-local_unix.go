//go:build unix

package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultEnvironmentLocalShellCommand      = template.Strings{}
	DefaultEnvironmentLocalExecCommandPrefix = template.Strings{}
	DefaultEnvironmentLocalDirectory         = template.String{}
)

type EnvironmentLocal struct {
	User                   UserRequirementTemplate `yaml:",inline"`
	EnvironmentLocalCommon `yaml:",inline"`
}

func (this *EnvironmentLocal) SetDefaults() error {
	return setDefaults(this,
		func(v *EnvironmentLocal) (string, defaulter) { return "", &v.User },

		func(v *EnvironmentLocal) (string, defaulter) { return "", &v.EnvironmentLocalCommon },
	)
}

func (this *EnvironmentLocal) Trim() error {
	return trim(this,
		func(v *EnvironmentLocal) (string, trimmer) { return "", &v.User },

		func(v *EnvironmentLocal) (string, trimmer) { return "", &v.EnvironmentLocalCommon },
	)
}

func (this *EnvironmentLocal) Validate() error {
	return validate(this,
		func(v *EnvironmentLocal) (string, validator) { return "", &v.User },

		func(v *EnvironmentLocal) (string, validator) { return "", &v.EnvironmentLocalCommon },
	)
}

func (this *EnvironmentLocal) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentLocal, node *yaml.Node) error {
		type raw EnvironmentLocal
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentLocal) MarshalYAML() (any, error) {
	// yaml's inline unmarshaler handling omits the named User struct from its
	// encoder field list. Strip only that struct's decoding methods for output;
	// preserve its individual template encoders and the existing flat schema.
	type rawUser UserRequirementTemplate
	return struct {
		User                   rawUser `yaml:",inline"`
		EnvironmentLocalCommon `yaml:",inline"`
	}{User: rawUser(this.User), EnvironmentLocalCommon: this.EnvironmentLocalCommon}, nil
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
	return isEqual(&this.User, &other.User) &&
		isEqual(&this.EnvironmentLocalCommon, &other.EnvironmentLocalCommon)
}

func (this EnvironmentLocal) Types() []string {
	return []string{"local"}
}

func (this EnvironmentLocal) FeatureFlags() []string {
	return []string{"local[pty,impersonate]"}
}

func (this EnvironmentLocal) SupportsEnvironmentVariables() bool { return true }
