package configuration

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"gopkg.in/yaml.v3"
	"slices"
)

var (
	DefaultAuthorizationOidcScopes = []string{oidc.ScopeOpenID, "profile", "email"}
)

type AuthorizationOidc struct {
	Issuer       string   `yaml:"issuer"`
	ClientId     string   `yaml:"clientId"`
	ClientSecret string   `yaml:"clientSecret"`
	Scopes       []string `yaml:"scopes"`

	RetrieveIdToken  bool `yaml:"retrieveIdToken,omitempty"`
	RetrieveUserInfo bool `yaml:"retrieveUserInfo,omitempty"`
}

func (this *AuthorizationOidc) SetDefaults() error {
	return setDefaults(this,
		noopSetDefault[AuthorizationOidc]("issuer"),
		noopSetDefault[AuthorizationOidc]("clientId"),
		noopSetDefault[AuthorizationOidc]("clientSecret"),
		fixedDefault("scopes", func(v *AuthorizationOidc) *[]string { return &v.Scopes }, DefaultAuthorizationOidcScopes),

		fixedDefault("retrieveIdToken", func(v *AuthorizationOidc) *bool { return &v.RetrieveIdToken }, true),
		fixedDefault("retrieveUserInfo", func(v *AuthorizationOidc) *bool { return &v.RetrieveUserInfo }, false),
	)
}

func (this *AuthorizationOidc) Trim() error {
	return trim(this,
		noopTrim[AuthorizationOidc]("issuer"),
		noopTrim[AuthorizationOidc]("clientId"),
		noopTrim[AuthorizationOidc]("clientSecret"),
		trimSliceBy("scopes", func(v *AuthorizationOidc) *[]string { return &v.Scopes }, func(v string) bool { return v == "" }),

		noopTrim[AuthorizationOidc]("retrieveIdToken"),
		noopTrim[AuthorizationOidc]("retrieveUserInfo"),
	)
}

func (this *AuthorizationOidc) Validate() error {
	return validate(this,
		notEmptyStringValidate("issuer", func(v *AuthorizationOidc) *string { return &v.Issuer }),
		notEmptyStringValidate("clientId", func(v *AuthorizationOidc) *string { return &v.ClientId }),
		notEmptyStringValidate("clientSecret", func(v *AuthorizationOidc) *string { return &v.ClientSecret }),
		notEmptySliceValidate("scopes", func(v *AuthorizationOidc) *[]string { return &v.Scopes }),

		noopValidate[AuthorizationOidc]("retrieveIdToken"),
		noopValidate[AuthorizationOidc]("retrieveUserInfo"),
	)
}

func (this *AuthorizationOidc) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationOidc, node *yaml.Node) error {
		type raw AuthorizationOidc
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationOidc) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizationOidc:
		return this.isEqualTo(&v)
	case *AuthorizationOidc:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationOidc) isEqualTo(other *AuthorizationOidc) bool {
	return this.Issuer == other.Issuer &&
		this.ClientId == other.ClientId &&
		slices.EqualFunc(this.Scopes, other.Scopes, func(l, r string) bool { return l == r }) &&
		this.RetrieveIdToken == other.RetrieveIdToken &&
		this.RetrieveUserInfo == other.RetrieveUserInfo
}
