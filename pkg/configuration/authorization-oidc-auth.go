package configuration

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultAuthorizationOidcDefaultIssuer       = template.MustNewUrl("")
	DefaultAuthorizationOidcDefaultClientId     = template.MustNewString("")
	DefaultAuthorizationOidcDefaultClientSecret = template.MustNewString("")
	DefaultAuthorizationOidcScopes              = template.MustNewStrings(oidc.ScopeOpenID, "profile", "email")
	DefaultAuthorizationOidcRetrieveIdToken     = true
	DefaultAuthorizationOidcRetrieveUserInfo    = false

	_ = RegisterAuthorizationV(func() AuthorizationV {
		return &AuthorizationOidcDeviceAuth{}
	})
)

type AuthorizationOidcDeviceAuth struct {
	Issuer       template.Url     `yaml:"issuer"`
	ClientId     template.String  `yaml:"clientId"`
	ClientSecret template.String  `yaml:"clientSecret"`
	Scopes       template.Strings `yaml:"scopes"`

	RetrieveIdToken  bool `yaml:"retrieveIdToken,omitempty"`
	RetrieveUserInfo bool `yaml:"retrieveUserInfo,omitempty"`
}

func (this *AuthorizationOidcDeviceAuth) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("issuer", func(v *AuthorizationOidcDeviceAuth) *template.Url { return &v.Issuer }, DefaultAuthorizationOidcDefaultIssuer),
		fixedDefault("clientId", func(v *AuthorizationOidcDeviceAuth) *template.String { return &v.ClientId }, DefaultAuthorizationOidcDefaultClientId),
		fixedDefault("clientSecret", func(v *AuthorizationOidcDeviceAuth) *template.String { return &v.ClientSecret }, DefaultAuthorizationOidcDefaultClientSecret),
		fixedDefault("scopes", func(v *AuthorizationOidcDeviceAuth) *template.Strings { return &v.Scopes }, DefaultAuthorizationOidcScopes),

		fixedDefault("retrieveIdToken", func(v *AuthorizationOidcDeviceAuth) *bool { return &v.RetrieveIdToken }, DefaultAuthorizationOidcRetrieveIdToken),
		fixedDefault("retrieveUserInfo", func(v *AuthorizationOidcDeviceAuth) *bool { return &v.RetrieveUserInfo }, DefaultAuthorizationOidcRetrieveUserInfo),
	)
}

func (this *AuthorizationOidcDeviceAuth) Trim() error {
	return trim(this,
		noopTrim[AuthorizationOidcDeviceAuth]("issuer"),
		noopTrim[AuthorizationOidcDeviceAuth]("clientId"),
		noopTrim[AuthorizationOidcDeviceAuth]("clientSecret"),
		noopTrim[AuthorizationOidcDeviceAuth]("scopes"),

		noopTrim[AuthorizationOidcDeviceAuth]("retrieveIdToken"),
		noopTrim[AuthorizationOidcDeviceAuth]("retrieveUserInfo"),
	)
}

func (this *AuthorizationOidcDeviceAuth) Validate() error {
	return validate(this,
		func(v *AuthorizationOidcDeviceAuth) (string, validator) { return "issuer", &v.Issuer },
		notZeroValidate("issuer", func(v *AuthorizationOidcDeviceAuth) *template.Url { return &v.Issuer }),
		func(v *AuthorizationOidcDeviceAuth) (string, validator) { return "clientId", &v.ClientId },
		notZeroValidate("clientId", func(v *AuthorizationOidcDeviceAuth) *template.String { return &v.ClientId }),
		func(v *AuthorizationOidcDeviceAuth) (string, validator) { return "clientSecret", &v.ClientSecret },
		notZeroValidate("clientSecret", func(v *AuthorizationOidcDeviceAuth) *template.String { return &v.ClientSecret }),
		func(v *AuthorizationOidcDeviceAuth) (string, validator) { return "scopes", &v.Scopes },
		notZeroValidate("scopes", func(v *AuthorizationOidcDeviceAuth) *template.Strings { return &v.Scopes }),

		noopValidate[AuthorizationOidcDeviceAuth]("retrieveIdToken"),
		noopValidate[AuthorizationOidcDeviceAuth]("retrieveUserInfo"),
	)
}

func (this *AuthorizationOidcDeviceAuth) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationOidcDeviceAuth, node *yaml.Node) error {
		type raw AuthorizationOidcDeviceAuth
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationOidcDeviceAuth) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizationOidcDeviceAuth:
		return this.isEqualTo(&v)
	case *AuthorizationOidcDeviceAuth:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationOidcDeviceAuth) isEqualTo(other *AuthorizationOidcDeviceAuth) bool {
	return isEqual(&this.Issuer, &other.Issuer) &&
		isEqual(&this.ClientId, &other.ClientId) &&
		isEqual(&this.ClientSecret, &other.ClientSecret) &&
		isEqual(&this.Scopes, &other.Scopes) &&
		this.RetrieveIdToken == other.RetrieveIdToken &&
		this.RetrieveUserInfo == other.RetrieveUserInfo
}

func (this AuthorizationOidcDeviceAuth) Types() []string {
	return []string{"oidcDeviceAuth", "oidc-device-auth", "oidc_device_auth"}
}

func (this AuthorizationOidcDeviceAuth) FeatureFlags() []string {
	return []string{"oidcDeviceAuth"}
}
