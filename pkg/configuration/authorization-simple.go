package configuration

import (
	"gopkg.in/yaml.v3"
)

var (
	_ = RegisterAuthorizationV(func() AuthorizationV {
		return &AuthorizationSimple{}
	})
)

type AuthorizationSimple struct {
	Entries AuthorizationSimpleEntries `yaml:"entries,omitempty"`
}

func (this *AuthorizationSimple) SetDefaults() error {
	return setDefaults(this,
		func(v *AuthorizationSimple) (string, defaulter) { return "entries", &v.Entries },
	)
}

func (this *AuthorizationSimple) Trim() error {
	return trim(this,
		func(v *AuthorizationSimple) (string, trimmer) { return "entries", &v.Entries },
	)
}

func (this *AuthorizationSimple) Validate() error {
	return validate(this,
		func(v *AuthorizationSimple) (string, validator) { return "entries", &v.Entries },
	)
}

func (this *AuthorizationSimple) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationSimple, node *yaml.Node) error {
		type raw AuthorizationSimple
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationSimple) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizationSimple:
		return this.isEqualTo(&v)
	case *AuthorizationSimple:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationSimple) isEqualTo(other *AuthorizationSimple) bool {
	return isEqual(&this.Entries, &other.Entries)
}

func (this AuthorizationSimple) Types() []string {
	return []string{"simple"}
}
