package configuration

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultEnvironmentSshCertificateValidity       = template.DurationOf(15 * time.Minute)
	DefaultEnvironmentSshCertificateValidAfterSkew = template.DurationOf(30 * time.Second)
)

type EnvironmentSshCertificate struct {
	IdentityFile          template.String                     `yaml:"identityFile,omitempty"`
	AuthorityIdentityFile template.String                     `yaml:"authorityIdentityFile,omitempty"`
	Validity              template.Duration                   `yaml:"validity"`
	ValidAfterSkew        template.Duration                   `yaml:"validAfterSkew,omitempty"`
	Audience              template.String                     `yaml:"audience,omitempty"`
	Principals            template.Strings                    `yaml:"principals,omitempty"`
	Extensions            EnvironmentSshCertificateExtensions `yaml:"extensions,omitempty"`
}

func (this *EnvironmentSshCertificate) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("identityFile", func(v *EnvironmentSshCertificate) *template.String { return &v.IdentityFile }, DefaultCertificateIdentityFile),
		fixedDefault("authorityIdentityFile", func(v *EnvironmentSshCertificate) *template.String { return &v.AuthorityIdentityFile }, DefaultCertificateAuthorityFile),
		fixedDefault("validity", func(v *EnvironmentSshCertificate) *template.Duration { return &v.Validity }, DefaultEnvironmentSshCertificateValidity),
		fixedDefault("validAfterSkew", func(v *EnvironmentSshCertificate) *template.Duration { return &v.ValidAfterSkew }, DefaultEnvironmentSshCertificateValidAfterSkew),
		noopSetDefault[EnvironmentSshCertificate]("audience"),
		noopSetDefault[EnvironmentSshCertificate]("principals"),
		noopSetDefault[EnvironmentSshCertificate]("extensions"),
	)
}

func (this *EnvironmentSshCertificate) Trim() error {
	return trim(this,
		noopTrim[EnvironmentSshCertificate]("identityFile"),
		noopTrim[EnvironmentSshCertificate]("authorityIdentityFile"),
		noopTrim[EnvironmentSshCertificate]("validity"),
		noopTrim[EnvironmentSshCertificate]("validAfterSkew"),
		noopTrim[EnvironmentSshCertificate]("audience"),
		noopTrim[EnvironmentSshCertificate]("principals"),
		noopTrim[EnvironmentSshCertificate]("extensions"),
	)
}

func (this *EnvironmentSshCertificate) Validate() error {
	if this.IdentityFile.IsZero() || !this.IdentityFile.IsHardCoded() {
		return fmt.Errorf("[identityFile] has to be a static non-empty path")
	}
	if this.AuthorityIdentityFile.IsZero() || !this.AuthorityIdentityFile.IsHardCoded() {
		return fmt.Errorf("[authorityIdentityFile] has to be a static non-empty path")
	}
	if this.Validity.IsHardCoded() {
		value, _ := this.Validity.Render(nil)
		if value <= 0 {
			return fmt.Errorf("[validity] has to be positive")
		}
	}
	if this.ValidAfterSkew.IsHardCoded() {
		value, _ := this.ValidAfterSkew.Render(nil)
		if value < 0 {
			return fmt.Errorf("[validAfterSkew] cannot be negative")
		}
	}
	for i, principal := range this.Principals {
		if principal.IsZero() {
			return fmt.Errorf("[principals][%d] required but absent", i)
		}
	}
	return validate(this,
		func(v *EnvironmentSshCertificate) (string, validator) { return "identityFile", &v.IdentityFile },
		func(v *EnvironmentSshCertificate) (string, validator) {
			return "authorityIdentityFile", &v.AuthorityIdentityFile
		},
		func(v *EnvironmentSshCertificate) (string, validator) { return "validity", &v.Validity },
		func(v *EnvironmentSshCertificate) (string, validator) { return "validAfterSkew", &v.ValidAfterSkew },
		func(v *EnvironmentSshCertificate) (string, validator) { return "audience", &v.Audience },
		func(v *EnvironmentSshCertificate) (string, validator) { return "principals", &v.Principals },
		func(v *EnvironmentSshCertificate) (string, validator) { return "extensions", &v.Extensions },
	)
}

func (this *EnvironmentSshCertificate) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentSshCertificate, node *yaml.Node) error {
		type raw EnvironmentSshCertificate
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentSshCertificate) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case EnvironmentSshCertificate:
		return this.isEqualTo(&v)
	case *EnvironmentSshCertificate:
		return v != nil && this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentSshCertificate) isEqualTo(other *EnvironmentSshCertificate) bool {
	return isEqual(&this.IdentityFile, &other.IdentityFile) &&
		isEqual(&this.AuthorityIdentityFile, &other.AuthorityIdentityFile) &&
		isEqual(&this.Validity, &other.Validity) &&
		isEqual(&this.ValidAfterSkew, &other.ValidAfterSkew) &&
		isEqual(&this.Audience, &other.Audience) &&
		isEqual(&this.Principals, &other.Principals) &&
		isEqual(&this.Extensions, &other.Extensions)
}

type EnvironmentSshCertificateExtensions map[string]template.String

func (this *EnvironmentSshCertificateExtensions) SetDefaults() error {
	*this = EnvironmentSshCertificateExtensions{}
	return nil
}

func (this *EnvironmentSshCertificateExtensions) Trim() error { return this.Validate() }

func (this EnvironmentSshCertificateExtensions) Validate() error {
	keys := make([]string, 0, len(this))
	for key := range this {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if strings.TrimSpace(key) == "" || strings.IndexByte(key, 0) >= 0 || strings.ContainsAny(key, "=,") {
			return fmt.Errorf("[%s] illegal SSH certificate extension name", key)
		}
		if strings.HasSuffix(key, "@bifroest.engity.org") {
			return fmt.Errorf("[%s] reserved SSH certificate extension name", key)
		}
		value := this[key]
		if err := value.Validate(); err != nil {
			return fmt.Errorf("[%s] %w", key, err)
		}
	}
	return nil
}

func (this EnvironmentSshCertificateExtensions) IsZero() bool { return len(this) == 0 }

func (this EnvironmentSshCertificateExtensions) IsEqualTo(other any) bool {
	var candidate EnvironmentSshCertificateExtensions
	switch v := other.(type) {
	case EnvironmentSshCertificateExtensions:
		candidate = v
	case *EnvironmentSshCertificateExtensions:
		if v == nil {
			return false
		}
		candidate = *v
	default:
		return false
	}
	if len(this) != len(candidate) {
		return false
	}
	for key, value := range this {
		otherValue, ok := candidate[key]
		if !ok || !value.IsEqualTo(otherValue) {
			return false
		}
	}
	return true
}

func (this EnvironmentSshCertificateExtensions) Render(data any) (map[string]string, error) {
	result := make(map[string]string, len(this))
	for key, value := range this {
		rendered, err := value.Render(data)
		if err != nil {
			return nil, fmt.Errorf("[%s] %w", key, err)
		}
		if strings.IndexByte(rendered, 0) >= 0 {
			return nil, fmt.Errorf("[%s] SSH certificate extension value contains NUL", key)
		}
		result[key] = rendered
	}
	return result, nil
}
