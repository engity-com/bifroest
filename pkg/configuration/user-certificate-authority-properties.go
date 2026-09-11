package configuration

import "github.com/engity-com/bifroest/pkg/crypto"

type UserCertificateAuthorityProperties struct {
	TrustedUserCAs     crypto.PublicKeys     `yaml:"trustedUserCAs,omitempty"`
	TrustedUserCAsFile crypto.PublicKeysFile `yaml:"trustedUserCAsFile,omitempty"`
}

func (this *UserCertificateAuthorityProperties) SetDefaults() error {
	return setDefaults(this,
		noopSetDefault[UserCertificateAuthorityProperties]("trustedUserCAs"),
		noopSetDefault[UserCertificateAuthorityProperties]("trustedUserCAsFile"),
	)
}

func (this *UserCertificateAuthorityProperties) Trim() error {
	return trim(this,
		func(v *UserCertificateAuthorityProperties) (string, trimmer) {
			return "trustedUserCAs", &v.TrustedUserCAs
		},
		func(v *UserCertificateAuthorityProperties) (string, trimmer) {
			return "trustedUserCAsFile", &v.TrustedUserCAsFile
		},
	)
}

func (this *UserCertificateAuthorityProperties) Validate() error {
	return validate(this,
		func(v *UserCertificateAuthorityProperties) (string, validator) {
			return "trustedUserCAs", &v.TrustedUserCAs
		},
		func(v *UserCertificateAuthorityProperties) (string, validator) {
			return "trustedUserCAsFile", &v.TrustedUserCAsFile
		},
	)
}

func (this UserCertificateAuthorityProperties) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case UserCertificateAuthorityProperties:
		return this.isEqualTo(&v)
	case *UserCertificateAuthorityProperties:
		return v != nil && this.isEqualTo(v)
	default:
		return false
	}
}

func (this UserCertificateAuthorityProperties) isEqualTo(other *UserCertificateAuthorityProperties) bool {
	return isEqual(&this.TrustedUserCAs, &other.TrustedUserCAs) &&
		isEqual(&this.TrustedUserCAsFile, &other.TrustedUserCAsFile)
}
