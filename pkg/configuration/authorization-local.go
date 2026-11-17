//go:build unix || windows

package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultAuthorizationLocalPamService     = defaultAuthorizationLocalPamService
	DefaultAuthorizationLocalAuthorizedKeys = template.MustNewStrings("{{.user.homeDir}}/.ssh/authorized_keys")

	_ = RegisterAuthorizationV(func() AuthorizationV {
		return &AuthorizationLocal{}
	})
)

type AuthorizationLocal struct {
	UserCertificateAuthorityProperties `yaml:",inline"`
	RemoteName                         template.String    `yaml:"remoteName,omitempty"`
	AuthorizedKeys                     template.Strings   `yaml:"authorizedKeys,omitempty"`
	Password                           PasswordProperties `yaml:"password,omitempty"`
	PamService                         string             `yaml:"pamService,omitempty"`
}

func (this *AuthorizationLocal) SetDefaults() error {
	return setDefaults(this,
		func(v *AuthorizationLocal) (string, defaulter) { return "", &v.UserCertificateAuthorityProperties },
		fixedDefault("remoteName", func(v *AuthorizationLocal) *template.String { return &v.RemoteName }, DefaultAuthorizationRemoteName),
		fixedDefault("authorizedKeys", func(v *AuthorizationLocal) *template.Strings { return &v.AuthorizedKeys }, DefaultAuthorizationLocalAuthorizedKeys),
		func(v *AuthorizationLocal) (string, defaulter) { return "password", &v.Password },
		fixedDefault("pamService", func(v *AuthorizationLocal) *string { return &v.PamService }, DefaultAuthorizationLocalPamService),
	)
}

func (this *AuthorizationLocal) Trim() error {
	return trim(this,
		func(v *AuthorizationLocal) (string, trimmer) { return "", &v.UserCertificateAuthorityProperties },
		noopTrim[AuthorizationLocal]("remoteName"),
		noopTrim[AuthorizationLocal]("authorizedKeys"),
		func(v *AuthorizationLocal) (string, trimmer) { return "password", &v.Password },
		func(v *AuthorizationLocal) (string, trimmer) { return "pamService", &stringTrimmer{&v.PamService} },
	)
}

func (this *AuthorizationLocal) Validate() error {
	if err := validate(this,
		func(v *AuthorizationLocal) (string, validator) { return "", &v.UserCertificateAuthorityProperties },
		func(v *AuthorizationLocal) (string, validator) {
			return "remoteName", validatorFunc(func() error { return validateAuthorizationRemoteName(v.RemoteName) })
		},
		func(v *AuthorizationLocal) (string, validator) { return "authorizedKeys", &v.AuthorizedKeys },
		func(v *AuthorizationLocal) (string, validator) { return "password", &v.Password },
		noopValidate[AuthorizationLocal]("pamService"),
	); err != nil {
		return err
	}
	if err := validateAuthorizationLocalPamService(this.PamService); err != nil {
		return err
	}
	return nil
}

func (this *AuthorizationLocal) UnmarshalYAML(node *yaml.Node) error {
	if err := validateAuthorizationRemoteNameYAML(node); err != nil {
		return err
	}
	return unmarshalYAML(this, node, func(target *AuthorizationLocal, node *yaml.Node) error {
		type raw AuthorizationLocal
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationLocal) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizationLocal:
		return this.isEqualTo(&v)
	case *AuthorizationLocal:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationLocal) isEqualTo(other *AuthorizationLocal) bool {
	return isEqual(&this.UserCertificateAuthorityProperties, &other.UserCertificateAuthorityProperties) &&
		isEqual(&this.RemoteName, &other.RemoteName) &&
		isEqual(&this.AuthorizedKeys, &other.AuthorizedKeys) &&
		isEqual(&this.Password, &other.Password) &&
		this.PamService == other.PamService
}

func (this AuthorizationLocal) Types() []string {
	return []string{"local"}
}
