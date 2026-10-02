package configuration

import (
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultAuthorizationOidcDefaultIssuer                       = template.MustNewUrl("")
	DefaultAuthorizationOidcDefaultClientId                     = template.MustNewString("")
	DefaultAuthorizationOidcDefaultClientSecret                 = template.MustNewString("")
	DefaultAuthorizationOidcScopes                              = template.MustNewStrings(oidc.ScopeOpenID, "profile", "email")
	DefaultAuthorizationOidcRetrieveIdToken                     = true
	DefaultAuthorizationOidcRetrieveUserInfo                    = false
	DefaultAuthorizationOidcForceDisposeSessionOn               = "lostAccess"
	DefaultAuthorizationOidcRefreshTokenMode                    = "proactive"
	DefaultAuthorizationOidcRefreshTokenAtLifetimePercent uint8 = 70
	DefaultAuthorizationOidcRefreshTokenFallbackEvery           = common.DurationOf(15 * time.Minute)
	DefaultAuthorizationOidcRefreshTokenMaxUnverifiedFor        = common.DurationOf(30 * time.Minute)

	_ = RegisterAuthorizationV(func() AuthorizationV {
		return &AuthorizationOidcDeviceAuth{}
	})
)

type AuthorizationOidcDeviceAuth struct {
	Issuer       template.Url     `yaml:"issuer"`
	ClientId     template.String  `yaml:"clientId"`
	ClientSecret template.String  `yaml:"clientSecret"`
	Scopes       template.Strings `yaml:"scopes"`

	RetrieveIdToken       bool                          `yaml:"retrieveIdToken,omitempty"`
	RetrieveUserInfo      bool                          `yaml:"retrieveUserInfo,omitempty"`
	ForceDisposeSessionOn string                        `yaml:"forceDisposeSessionOn,omitempty"`
	RefreshToken          AuthorizationOidcRefreshToken `yaml:"refreshToken,omitempty"`
}

func (this *AuthorizationOidcDeviceAuth) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("issuer", func(v *AuthorizationOidcDeviceAuth) *template.Url { return &v.Issuer }, DefaultAuthorizationOidcDefaultIssuer),
		fixedDefault("clientId", func(v *AuthorizationOidcDeviceAuth) *template.String { return &v.ClientId }, DefaultAuthorizationOidcDefaultClientId),
		fixedDefault("clientSecret", func(v *AuthorizationOidcDeviceAuth) *template.String { return &v.ClientSecret }, DefaultAuthorizationOidcDefaultClientSecret),
		fixedDefault("scopes", func(v *AuthorizationOidcDeviceAuth) *template.Strings { return &v.Scopes }, DefaultAuthorizationOidcScopes),

		fixedDefault("retrieveIdToken", func(v *AuthorizationOidcDeviceAuth) *bool { return &v.RetrieveIdToken }, DefaultAuthorizationOidcRetrieveIdToken),
		fixedDefault("retrieveUserInfo", func(v *AuthorizationOidcDeviceAuth) *bool { return &v.RetrieveUserInfo }, DefaultAuthorizationOidcRetrieveUserInfo),
		fixedDefault("forceDisposeSessionOn", func(v *AuthorizationOidcDeviceAuth) *string { return &v.ForceDisposeSessionOn }, DefaultAuthorizationOidcForceDisposeSessionOn),
		func(v *AuthorizationOidcDeviceAuth) (string, defaulter) { return "refreshToken", &v.RefreshToken },
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
		func(v *AuthorizationOidcDeviceAuth) (string, trimmer) {
			return "forceDisposeSessionOn", &stringTrimmer{&v.ForceDisposeSessionOn}
		},
		func(v *AuthorizationOidcDeviceAuth) (string, trimmer) { return "refreshToken", &v.RefreshToken },
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
		func(v *AuthorizationOidcDeviceAuth) (string, validator) {
			return "forceDisposeSessionOn", validatorFunc(func() error {
				if v.ForceDisposeSessionOn != "never" && v.ForceDisposeSessionOn != "lostAccess" {
					return fmt.Errorf("must be never or lostAccess")
				}
				return nil
			})
		},
		func(v *AuthorizationOidcDeviceAuth) (string, validator) { return "refreshToken", &v.RefreshToken },
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
	forceDisposeSessionOn := this.ForceDisposeSessionOn
	if forceDisposeSessionOn == "" {
		forceDisposeSessionOn = DefaultAuthorizationOidcForceDisposeSessionOn
	}
	otherForceDisposeSessionOn := other.ForceDisposeSessionOn
	if otherForceDisposeSessionOn == "" {
		otherForceDisposeSessionOn = DefaultAuthorizationOidcForceDisposeSessionOn
	}
	return isEqual(&this.Issuer, &other.Issuer) &&
		isEqual(&this.ClientId, &other.ClientId) &&
		isEqual(&this.ClientSecret, &other.ClientSecret) &&
		isEqual(&this.Scopes, &other.Scopes) &&
		this.RetrieveIdToken == other.RetrieveIdToken &&
		this.RetrieveUserInfo == other.RetrieveUserInfo &&
		forceDisposeSessionOn == otherForceDisposeSessionOn &&
		this.RefreshToken.IsEqualTo(other.RefreshToken)
}

func (this AuthorizationOidcDeviceAuth) RefreshEnabled() bool {
	return this.ForceDisposeSessionOn != "never" || this.RefreshToken.Mode != "never"
}

type AuthorizationOidcRefreshToken struct {
	Mode              string          `yaml:"mode,omitempty"`
	AtLifetimePercent uint8           `yaml:"atLifetimePercent,omitempty"`
	FallbackEvery     common.Duration `yaml:"fallbackEvery,omitempty"`
	MaxUnverifiedFor  common.Duration `yaml:"maxUnverifiedFor,omitempty"`
}

func (this *AuthorizationOidcRefreshToken) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("mode", func(v *AuthorizationOidcRefreshToken) *string { return &v.Mode }, DefaultAuthorizationOidcRefreshTokenMode),
		fixedDefault("atLifetimePercent", func(v *AuthorizationOidcRefreshToken) *uint8 { return &v.AtLifetimePercent }, DefaultAuthorizationOidcRefreshTokenAtLifetimePercent),
		fixedDefault("fallbackEvery", func(v *AuthorizationOidcRefreshToken) *common.Duration { return &v.FallbackEvery }, DefaultAuthorizationOidcRefreshTokenFallbackEvery),
		fixedDefault("maxUnverifiedFor", func(v *AuthorizationOidcRefreshToken) *common.Duration { return &v.MaxUnverifiedFor }, DefaultAuthorizationOidcRefreshTokenMaxUnverifiedFor),
	)
}

func (this *AuthorizationOidcRefreshToken) Trim() error {
	return trim(this,
		func(v *AuthorizationOidcRefreshToken) (string, trimmer) { return "mode", &stringTrimmer{&v.Mode} },
		noopTrim[AuthorizationOidcRefreshToken]("atLifetimePercent"),
		noopTrim[AuthorizationOidcRefreshToken]("fallbackEvery"),
		noopTrim[AuthorizationOidcRefreshToken]("maxUnverifiedFor"),
	)
}

func (this *AuthorizationOidcRefreshToken) Validate() error {
	return validate(this,
		func(v *AuthorizationOidcRefreshToken) (string, validator) {
			return "mode", validatorFunc(func() error {
				if v.Mode != "never" && v.Mode != "proactive" {
					return fmt.Errorf("must be never or proactive")
				}
				return nil
			})
		},
		func(v *AuthorizationOidcRefreshToken) (string, validator) {
			return "atLifetimePercent", validatorFunc(func() error {
				if v.AtLifetimePercent < 1 || v.AtLifetimePercent > 99 {
					return fmt.Errorf("must be between 1 and 99")
				}
				return nil
			})
		},
		func(v *AuthorizationOidcRefreshToken) (string, validator) {
			return "fallbackEvery", validatorFunc(func() error {
				if v.FallbackEvery.Native() <= 0 {
					return fmt.Errorf("has to be positive")
				}
				return nil
			})
		},
		func(v *AuthorizationOidcRefreshToken) (string, validator) {
			return "maxUnverifiedFor", validatorFunc(func() error {
				if v.MaxUnverifiedFor.Native() <= 0 {
					return fmt.Errorf("has to be positive")
				}
				return nil
			})
		},
	)
}

func (this *AuthorizationOidcRefreshToken) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationOidcRefreshToken, node *yaml.Node) error {
		type raw AuthorizationOidcRefreshToken
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationOidcRefreshToken) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case AuthorizationOidcRefreshToken:
		return this.isEqualTo(&v)
	case *AuthorizationOidcRefreshToken:
		return v != nil && this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationOidcRefreshToken) isEqualTo(other *AuthorizationOidcRefreshToken) bool {
	left, right := this, *other
	if left.Mode == "" {
		left.Mode = DefaultAuthorizationOidcRefreshTokenMode
	}
	if right.Mode == "" {
		right.Mode = DefaultAuthorizationOidcRefreshTokenMode
	}
	if left.AtLifetimePercent == 0 {
		left.AtLifetimePercent = DefaultAuthorizationOidcRefreshTokenAtLifetimePercent
	}
	if right.AtLifetimePercent == 0 {
		right.AtLifetimePercent = DefaultAuthorizationOidcRefreshTokenAtLifetimePercent
	}
	if left.FallbackEvery.IsZero() {
		left.FallbackEvery = DefaultAuthorizationOidcRefreshTokenFallbackEvery
	}
	if right.FallbackEvery.IsZero() {
		right.FallbackEvery = DefaultAuthorizationOidcRefreshTokenFallbackEvery
	}
	if left.MaxUnverifiedFor.IsZero() {
		left.MaxUnverifiedFor = DefaultAuthorizationOidcRefreshTokenMaxUnverifiedFor
	}
	if right.MaxUnverifiedFor.IsZero() {
		right.MaxUnverifiedFor = DefaultAuthorizationOidcRefreshTokenMaxUnverifiedFor
	}
	return left.Mode == right.Mode &&
		left.AtLifetimePercent == right.AtLifetimePercent &&
		isEqual(&left.FallbackEvery, &right.FallbackEvery) &&
		isEqual(&left.MaxUnverifiedFor, &right.MaxUnverifiedFor)
}

func (this AuthorizationOidcDeviceAuth) Types() []string {
	return []string{"oidcDeviceAuth", "oidc-device-auth", "oidc_device_auth"}
}

func (this AuthorizationOidcDeviceAuth) FeatureFlags() []string {
	return []string{"oidcDeviceAuth"}
}
