//go:build unix || windows

package authorization

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func (this *LocalAuthorizer) AuthenticationCapabilities(input DiscoveryInput) AuthenticationCapabilities {
	if this == nil {
		return AuthenticationCapabilities{}
	}
	return LocalAuthenticationCapabilities(this.conf, input)
}

// LocalAuthenticationCapabilities shares configuration/build-level hints without
// creating a native account repository or invoking a password/PAM provider.
func LocalAuthenticationCapabilities(conf *configuration.AuthorizationLocal, input DiscoveryInput) AuthenticationCapabilities {
	if !input.supported() || conf == nil {
		return AuthenticationCapabilities{}
	}
	ca := hasConfiguredUserCA(&conf.UserCertificateAuthorityProperties)
	keySource := len(conf.AuthorizedKeys) > 0
	key := input.RequestingName && (keySource || ca)
	pam := conf.PamService != "" && localPamAuthenticationAvailable
	passwordBackend := conf.PamService == "" || pam
	return AuthenticationCapabilities{
		Password:                     passwordBackend && input.RequestingName && discoveryBoolPossible(conf.Password.Allowed),
		KeyboardInteractive:          passwordBackend && (input.RequestingName || pam) && discoveryBoolPossible(conf.Password.InteractiveAllowed),
		PublicKey:                    key,
		SessionPublicKey:             key,
		PublicKeyCertificateRequired: key && ca && !keySource,
	}
}

func discoveryBoolPossible(value template.Bool) bool {
	enabled, known := value.StaticValue()
	return !known || enabled
}
