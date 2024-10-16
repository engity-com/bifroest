package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultHostKeyLocations       = template.MustNewStrings(DefaultHostKeyLocation)
	DefaultRememberMeNotification = template.MustNewString("\nIf you return until {{.session.validUntil | format `dateTimeT`}} with the same public key ({{.key | fingerprint}}), you can seamlessly login again.\n\n")
)

type Keys struct {
	HostKeys               template.Strings          `yaml:"hostKeys"`
	RsaRestriction         crypto.RsaRestriction     `yaml:"rsaRestriction"`
	DsaRestriction         crypto.DsaRestriction     `yaml:"dsaRestriction"`
	EcdsaRestriction       crypto.EcdsaRestriction   `yaml:"ecdsaRestriction"`
	Ed25519Restriction     crypto.Ed25519Restriction `yaml:"ed25519Restriction"`
	RememberMeNotification template.String           `yaml:"rememberMeNotification"`
}

func (this *Keys) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("hostKeys", func(v *Keys) *template.Strings { return &v.HostKeys }, DefaultHostKeyLocations),
		fixedDefault("rsaRestriction", func(v *Keys) *crypto.RsaRestriction { return &v.RsaRestriction }, crypto.DefaultRsaRestriction),
		fixedDefault("dsaRestriction", func(v *Keys) *crypto.DsaRestriction { return &v.DsaRestriction }, crypto.DefaultDsaRestriction),
		fixedDefault("ecdsaRestriction", func(v *Keys) *crypto.EcdsaRestriction { return &v.EcdsaRestriction }, crypto.DefaultEcdsaRestriction),
		fixedDefault("ed25519Restriction", func(v *Keys) *crypto.Ed25519Restriction { return &v.Ed25519Restriction }, crypto.DefaultEd25519Restriction),
		fixedDefault("rememberMeNotification", func(v *Keys) *template.String { return &v.RememberMeNotification }, DefaultRememberMeNotification),
	)
}

func (this *Keys) Trim() error {
	return trim(this,
		noopTrim[Keys]("hostKeys"),
		noopTrim[Keys]("rsaRestriction"),
		noopTrim[Keys]("dsaRestriction"),
		noopTrim[Keys]("ecdsaRestriction"),
		noopTrim[Keys]("ed25519Restriction"),
		noopTrim[Keys]("rememberMeNotification"),
	)
}

func (this *Keys) Validate() error {
	return validate(this,
		func(v *Keys) (string, validator) { return "hostKeys", &v.HostKeys },
		notZeroValidate("hostKeys", func(v *Keys) *template.Strings { return &v.HostKeys }),
		func(v *Keys) (string, validator) { return "rsaRestriction", &v.RsaRestriction },
		func(v *Keys) (string, validator) { return "dsaRestriction", &v.DsaRestriction },
		func(v *Keys) (string, validator) { return "ecdsaRestriction", &v.EcdsaRestriction },
		func(v *Keys) (string, validator) { return "ed25519Restriction", &v.Ed25519Restriction },
		func(v *Keys) (string, validator) { return "rememberMeNotification", &v.RememberMeNotification },
	)
}

func (this *Keys) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Keys, node *yaml.Node) error {
		type raw Keys
		return node.Decode((*raw)(target))
	})
}

func (this Keys) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Keys:
		return this.isEqualTo(&v)
	case *Keys:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Keys) isEqualTo(other *Keys) bool {
	return isEqual(&this.HostKeys, &other.HostKeys) &&
		isEqual(&this.RsaRestriction, &other.RsaRestriction) &&
		isEqual(&this.DsaRestriction, &other.DsaRestriction) &&
		isEqual(&this.EcdsaRestriction, &other.EcdsaRestriction) &&
		isEqual(&this.Ed25519Restriction, &other.Ed25519Restriction) &&
		isEqual(&this.RememberMeNotification, &other.RememberMeNotification)
}

func (this Keys) KeyAllowed(in any) (bool, error) {
	if ok, err := this.RsaRestriction.KeyAllowed(in); err != nil || ok {
		return ok, err
	}
	if ok, err := this.DsaRestriction.KeyAllowed(in); err != nil || ok {
		return ok, err
	}
	if ok, err := this.EcdsaRestriction.KeyAllowed(in); err != nil || ok {
		return ok, err
	}
	if ok, err := this.Ed25519Restriction.KeyAllowed(in); err != nil || ok {
		return ok, err
	}
	return false, nil
}
