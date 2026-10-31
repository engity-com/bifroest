//go:build unix || windows

package configuration

import (
	"fmt"

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
	AuthorizedKeys                     template.Strings   `yaml:"authorizedKeys,omitempty"`
	Password                           PasswordProperties `yaml:"password,omitempty"`
	PamService                         string             `yaml:"pamService,omitempty"`
	PamAccountResumeAllowed            bool               `yaml:"pamAccountResumeAllowed,omitempty"`
}

func (this *AuthorizationLocal) SetDefaults() error {
	return setDefaults(this,
		func(v *AuthorizationLocal) (string, defaulter) { return "", &v.UserCertificateAuthorityProperties },
		fixedDefault("authorizedKeys", func(v *AuthorizationLocal) *template.Strings { return &v.AuthorizedKeys }, DefaultAuthorizationLocalAuthorizedKeys),
		func(v *AuthorizationLocal) (string, defaulter) { return "password", &v.Password },
		fixedDefault("pamService", func(v *AuthorizationLocal) *string { return &v.PamService }, DefaultAuthorizationLocalPamService),
		fixedDefault("pamAccountResumeAllowed", func(v *AuthorizationLocal) *bool { return &v.PamAccountResumeAllowed }, false),
	)
}

func (this *AuthorizationLocal) Trim() error {
	return trim(this,
		func(v *AuthorizationLocal) (string, trimmer) { return "", &v.UserCertificateAuthorityProperties },
		noopTrim[AuthorizationLocal]("authorizedKeys"),
		func(v *AuthorizationLocal) (string, trimmer) { return "password", &v.Password },
		func(v *AuthorizationLocal) (string, trimmer) { return "pamService", &stringTrimmer{&v.PamService} },
		noopTrim[AuthorizationLocal]("pamAccountResumeAllowed"),
	)
}

func (this *AuthorizationLocal) Validate() error {
	if err := validate(this,
		func(v *AuthorizationLocal) (string, validator) { return "", &v.UserCertificateAuthorityProperties },
		func(v *AuthorizationLocal) (string, validator) { return "authorizedKeys", &v.AuthorizedKeys },
		func(v *AuthorizationLocal) (string, validator) { return "password", &v.Password },
		noopValidate[AuthorizationLocal]("pamService"),
		noopValidate[AuthorizationLocal]("pamAccountResumeAllowed"),
	); err != nil {
		return err
	}
	if err := validateAuthorizationLocalPamService(this.PamService); err != nil {
		return err
	}
	if this.PamAccountResumeAllowed && (!localPamAccountResumeAvailable || this.PamService == "") {
		return fmt.Errorf("pamAccountResumeAllowed requires a PAM-enabled Linux build and a non-empty pamService")
	}
	return nil
}

func (this *AuthorizationLocal) UnmarshalYAML(node *yaml.Node) error {
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
		isEqual(&this.AuthorizedKeys, &other.AuthorizedKeys) &&
		isEqual(&this.Password, &other.Password) &&
		this.PamService == other.PamService &&
		this.PamAccountResumeAllowed == other.PamAccountResumeAllowed
}

func (this AuthorizationLocal) Types() []string {
	return []string{"local"}
}
