package configuration

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
)

var (
	_ = RegisterAuthorizationV(func() AuthorizationV {
		return &AuthorizationBifroest{}
	})

	DefaultAuthorizationBifroestMaxCertificateValidity = common.DurationOf(15 * time.Minute)
)

type AuthorizationBifroest struct {
	UserCertificateAuthorityProperties `yaml:",inline"`
	Audiences                          BifroestAudiences `yaml:"audiences,omitempty"`
	MaxCertificateValidity             common.Duration   `yaml:"maxCertificateValidity,omitempty"`
}

func (this *AuthorizationBifroest) SetDefaults() error {
	return setDefaults(this,
		func(v *AuthorizationBifroest) (string, defaulter) { return "", &v.UserCertificateAuthorityProperties },
		func(v *AuthorizationBifroest) (string, defaulter) { return "audiences", &v.Audiences },
		fixedDefault("maxCertificateValidity", func(v *AuthorizationBifroest) *common.Duration { return &v.MaxCertificateValidity }, DefaultAuthorizationBifroestMaxCertificateValidity),
	)
}

func (this *AuthorizationBifroest) Trim() error {
	return trim(this,
		func(v *AuthorizationBifroest) (string, trimmer) { return "", &v.UserCertificateAuthorityProperties },
		func(v *AuthorizationBifroest) (string, trimmer) { return "audiences", &v.Audiences },
		noopTrim[AuthorizationBifroest]("maxCertificateValidity"),
	)
}

func (this *AuthorizationBifroest) Validate() error {
	if this.TrustedUserCAs.IsZero() && this.TrustedUserCAsFile.IsZero() {
		return fmt.Errorf("[trustedUserCAs] or [trustedUserCAsFile] required")
	}
	if this.MaxCertificateValidity.Native() <= 0 {
		return fmt.Errorf("[maxCertificateValidity] has to be positive")
	}
	return validate(this,
		func(v *AuthorizationBifroest) (string, validator) { return "", &v.UserCertificateAuthorityProperties },
		func(v *AuthorizationBifroest) (string, validator) { return "audiences", &v.Audiences },
		func(v *AuthorizationBifroest) (string, validator) {
			return "maxCertificateValidity", &v.MaxCertificateValidity
		},
	)
}

func (this *AuthorizationBifroest) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *AuthorizationBifroest, node *yaml.Node) error {
		type raw AuthorizationBifroest
		return node.Decode((*raw)(target))
	})
}

func (this AuthorizationBifroest) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case AuthorizationBifroest:
		return this.isEqualTo(&v)
	case *AuthorizationBifroest:
		return v != nil && this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizationBifroest) isEqualTo(other *AuthorizationBifroest) bool {
	return isEqual(&this.UserCertificateAuthorityProperties, &other.UserCertificateAuthorityProperties) &&
		isEqual(&this.Audiences, &other.Audiences) &&
		isEqual(&this.MaxCertificateValidity, &other.MaxCertificateValidity)
}

func (AuthorizationBifroest) Types() []string        { return []string{"bifroest"} }
func (AuthorizationBifroest) FeatureFlags() []string { return []string{"bifroest"} }

type BifroestAudiences []string

func (this *BifroestAudiences) SetDefaults() error {
	return nil
}

func (this *BifroestAudiences) Trim() error {
	for i := range *this {
		(*this)[i] = strings.TrimSpace((*this)[i])
	}
	return this.Validate()
}

func (this BifroestAudiences) Validate() error {
	if this != nil && len(this) == 0 {
		return fmt.Errorf("must not be explicitly empty")
	}
	seen := make(map[string]int, len(this))
	for i, value := range this {
		if value == "" || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("[%d] required but absent or illegal", i)
		}
		if previous, exists := seen[value]; exists {
			return fmt.Errorf("[%d] duplicates [%d] %q", i, previous, value)
		}
		seen[value] = i
	}
	return nil
}

func (this *BifroestAudiences) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *BifroestAudiences, node *yaml.Node) error {
		type raw BifroestAudiences
		return node.Decode((*raw)(target))
	})
}

func (this BifroestAudiences) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case BifroestAudiences:
		return slices.Equal(this, v)
	case *BifroestAudiences:
		return v != nil && slices.Equal(this, *v)
	default:
		return false
	}
}
