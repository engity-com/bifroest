package configuration

import (
	"gopkg.in/yaml.v3"
)

var (
	_ = RegisterAuthorizationV(func() AuthorizationV {
		return &AuthorizationNone{}
	})
)

type AuthorizationNone struct{}

func (this *AuthorizationNone) SetDefaults() error {
	return setDefaults(this)
}

func (this *AuthorizationNone) Trim() error {
	return trim(this)
}

func (this *AuthorizationNone) Validate() error {
	return validate(this)
}

func (this *AuthorizationNone) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationNone, node *yaml.Node) error {
		type raw AuthorizationNone
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationNone) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizationNone:
		return this.isEqualTo(&v)
	case *AuthorizationNone:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationNone) isEqualTo(_ *AuthorizationNone) bool {
	return true
}

func (this AuthorizationNone) Types() []string {
	return []string{"none"}
}

func (this AuthorizationNone) FeatureFlags() []string {
	return []string{"none"}
}
