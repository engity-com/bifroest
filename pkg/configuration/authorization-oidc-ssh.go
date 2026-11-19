package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

// AuthorizationOidcSsh contains presentation settings used only by SSH clients.
type AuthorizationOidcSsh struct {
	LoginMessage template.String `yaml:"loginMessage,omitempty"`
}

func (this *AuthorizationOidcSsh) SetDefaults() error {
	*this = AuthorizationOidcSsh{}
	return nil
}

func (this *AuthorizationOidcSsh) Trim() error { return this.Validate() }

func (this *AuthorizationOidcSsh) Validate() error {
	return validate(this, func(v *AuthorizationOidcSsh) (string, validator) {
		return "loginMessage", &v.LoginMessage
	})
}

func (this *AuthorizationOidcSsh) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationOidcSsh, node *yaml.Node) error {
		if err := rejectUnknownConfigurationFields(node, target); err != nil {
			return err
		}
		type raw AuthorizationOidcSsh
		return decodeConfigurationFields(node, (*raw)(target))
	})
}

func (this AuthorizationOidcSsh) IsZero() bool { return this.LoginMessage.IsZero() }

func (this AuthorizationOidcSsh) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case AuthorizationOidcSsh:
		return isEqual(&this.LoginMessage, &value.LoginMessage)
	case *AuthorizationOidcSsh:
		return value != nil && isEqual(&this.LoginMessage, &value.LoginMessage)
	default:
		return false
	}
}
