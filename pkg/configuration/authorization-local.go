package configuration

import (
	"github.com/engity-com/bifroest/pkg/template"
	"gopkg.in/yaml.v3"
)

var (
	DefaultAuthorizationLocalAuthorizedKeys = []template.String{template.MustNewString("{{.User.HomeDir}}/.ssh/authorized_keys")}
	DefaultAuthorizationLocalPamService     = "sshd"
)

type AuthorizationLocal struct {
	AuthorizedKeys []template.String `yaml:"authorizedKeys,omitempty"`
	Password       Password          `yaml:"password,omitempty"`
	PamService     string            `yaml:"pamService,omitempty"`
}

func (this *AuthorizationLocal) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("authorizedKeys", func(v *AuthorizationLocal) *[]template.String { return &v.AuthorizedKeys }, DefaultAuthorizationLocalAuthorizedKeys),
		func(v *AuthorizationLocal) (string, defaulter) { return "password", &v.Password },
		fixedDefault("pamService", func(v *AuthorizationLocal) *string { return &v.PamService }, DefaultAuthorizationLocalPamService),
	)
}

func (this *AuthorizationLocal) Trim() error {
	return trim(this,
		noopTrim[AuthorizationLocal]("authorizedKeys"),
		func(v *AuthorizationLocal) (string, trimmer) { return "password", &v.Password },
		func(v *AuthorizationLocal) (string, trimmer) { return "pamService", &stringTrimmer{&v.PamService} },
	)
}

func (this *AuthorizationLocal) Validate() error {
	return validate(this,
		noopValidate[AuthorizationLocal]("authorizedKeys"),
		func(v *AuthorizationLocal) (string, validator) { return "password", &v.Password },
		noopValidate[AuthorizationLocal]("pamService"),
	)
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
	return isEqualSlice(&this.AuthorizedKeys, &other.AuthorizedKeys) &&
		isEqual(&this.Password, &other.Password) &&
		this.PamService == other.PamService
}
