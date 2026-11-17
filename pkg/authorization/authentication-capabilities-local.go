//go:build unix || windows

package authorization

import (
	"github.com/engity-com/bifroest/pkg/template"
)

func (this *LocalAuthorizer) AuthenticationCapabilities(input DiscoveryInput) AuthenticationCapabilities {
	if !input.supported() || this == nil || this.conf == nil {
		return AuthenticationCapabilities{}
	}
	ca := hasConfiguredUserCA(&this.conf.UserCertificateAuthorityProperties)
	keySource := len(this.conf.AuthorizedKeys) > 0
	key := input.RequestingName && (keySource || ca)
	pam := this.conf.PamService != "" && localPamAuthenticationAvailable
	passwordBackend := this.conf.PamService == "" || pam
	return AuthenticationCapabilities{
		Password:                     passwordBackend && input.RequestingName && discoveryBoolPossible(this.conf.Password.Allowed),
		KeyboardInteractive:          passwordBackend && (input.RequestingName || pam) && discoveryBoolPossible(this.conf.Password.InteractiveAllowed),
		PublicKey:                    key,
		SessionPublicKey:             key,
		PublicKeyCertificateRequired: key && ca && !keySource,
	}
}

func discoveryBoolPossible(value template.Bool) bool {
	enabled, known := value.StaticValue()
	return !known || enabled
}
