package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	_ = RegisterAuthorizationV(func() AuthorizationV {
		return &AuthorizationSimple{}
	})
)

type AuthorizationSimple struct {
	UserCertificateAuthorityProperties `yaml:",inline"`
	RemoteName                         template.String            `yaml:"remoteName,omitempty"`
	Entries                            AuthorizationSimpleEntries `yaml:"entries,omitempty"`
}

func (this *AuthorizationSimple) SetDefaults() error {
	return setDefaults(this,
		func(v *AuthorizationSimple) (string, defaulter) { return "", &v.UserCertificateAuthorityProperties },
		fixedDefault("remoteName", func(v *AuthorizationSimple) *template.String { return &v.RemoteName }, DefaultAuthorizationRemoteName),
		func(v *AuthorizationSimple) (string, defaulter) { return "entries", &v.Entries },
	)
}

func (this *AuthorizationSimple) Trim() error {
	return trim(this,
		func(v *AuthorizationSimple) (string, trimmer) { return "", &v.UserCertificateAuthorityProperties },
		noopTrim[AuthorizationSimple]("remoteName"),
		func(v *AuthorizationSimple) (string, trimmer) { return "entries", &v.Entries },
	)
}

func (this *AuthorizationSimple) Validate() error {
	return validate(this,
		func(v *AuthorizationSimple) (string, validator) { return "", &v.UserCertificateAuthorityProperties },
		func(v *AuthorizationSimple) (string, validator) {
			return "remoteName", validatorFunc(func() error { return validateAuthorizationRemoteName(v.RemoteName) })
		},
		func(v *AuthorizationSimple) (string, validator) { return "entries", &v.Entries },
	)
}

func (this *AuthorizationSimple) UnmarshalYAML(node *yaml.Node) error {
	if err := validateAuthorizationRemoteNameYAML(node); err != nil {
		return err
	}
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
	return isEqual(&this.UserCertificateAuthorityProperties, &other.UserCertificateAuthorityProperties) &&
		isEqual(&this.RemoteName, &other.RemoteName) &&
		isEqual(&this.Entries, &other.Entries)
}

func (this AuthorizationSimple) Types() []string {
	return []string{"simple"}
}

func (this AuthorizationSimple) FeatureFlags() []string {
	return []string{"simple"}
}
