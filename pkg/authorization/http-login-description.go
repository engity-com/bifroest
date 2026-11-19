package authorization

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
)

// LoginMethod is a discovery/UI choice, separate from authentication audit values.
// In particular, a secretless action does not add a new authentication adapter.
type LoginMethod string

const (
	LoginMethodPassword            LoginMethod = "password"
	LoginMethodKeyboardInteractive LoginMethod = "keyboard-interactive"
	LoginMethodPublicKey           LoginMethod = "public-key"
	LoginMethodNone                LoginMethod = "none"
	LoginMethodOidc                LoginMethod = "oidc"
)

type LoginOption struct {
	Method              LoginMethod              `json:"method"`
	RequestUser         bool                     `json:"requestUser"`
	CertificateRequired bool                     `json:"certificateRequired"`
	RememberMe          configuration.RememberMe `json:"rememberMe,omitempty"`
}

type HttpLoginDescription struct {
	Available bool
	Options   []LoginOption
}

type HttpLoginDescriber interface {
	// authority includes the port, if any; flow requirements use only its host.
	DescribeHttpLogin(authority, slug string) (HttpLoginDescription, error)
}

var _ HttpLoginDescriber = (*AuthorizerFacade)(nil)

// Discovery and the HTTP adapter must agree before invoking an OIDC candidate.
// A foreign code origin is ineligible, not a failed login that stops fallback.
// Other methods (including remembered-key access) retain their own capabilities.
func (this *facaded) httpLoginCapabilities(origin string, named bool) AuthenticationCapabilities {
	capabilities := this.capabilityProvider.AuthenticationCapabilities(DiscoveryInput{Transport: connection.TransportHttp, RequestingName: named})
	if oidc, ok := this.CloseableAuthorizer.(*OidcDeviceAuthAuthorizer); ok && oidc.code != nil {
		capabilities.OidcAuthorizationCode = capabilities.OidcAuthorizationCode && oidc.matchesCodeOrigin(origin)
	}
	return capabilities
}

// DescribeHttpLogin shares the authoritative facade's canonical selection and
// published-slug pinning, but never attempts authentication. Unknown remote names
// must not eliminate named flows; nameless flows still check the concrete empty
// name. Capabilities are unioned by input mode, not across incompatible username
// prompts. Availability depends on requirements, not on credentials or methods.
func (this *AuthorizerFacade) DescribeHttpLogin(authority, slug string) (HttpLoginDescription, error) {
	origin, err := net.CanonicalHttpsOrigin(authority)
	if err != nil {
		return HttpLoginDescription{}, err
	}
	selection, err := (connection.Selection{Transport: connection.TransportHttp, Host: authority, Slug: slug}).Canonical()
	if err != nil {
		return HttpLoginDescription{}, err
	}
	candidates, err := this.candidatesForSelection(selection)
	if err != nil {
		return HttpLoginDescription{}, err
	}
	type optionKey struct {
		method LoginMethod
		named  bool
	}
	options := make(map[optionKey]LoginOption)
	result := HttpLoginDescription{Options: make([]LoginOption, 0)}
	for _, candidate := range candidates {
		if !candidate.http.IsEnabled() || !candidate.requirement.Http.MatchesHost(selection.Host) || !candidate.requirement.Http.MatchesSlug(selection.Slug) {
			continue
		}
		named := candidate.http.RequestUserEnabled()
		if !named && !candidate.requirement.MatchesHttp("", selection.Host, selection.Slug) {
			continue
		}
		result.Available = true
		if candidate.capabilityProvider == nil {
			return HttpLoginDescription{}, errors.System.Newf("authorization flow %q does not provide authentication capabilities", candidate.flow)
		}
		capabilities := candidate.httpLoginCapabilities(origin, named)
		add := func(method LoginMethod, possible bool) {
			if !possible {
				return
			}
			key := optionKey{method, named}
			certificate := method == LoginMethodPublicKey && capabilities.PublicKeyCertificateRequired
			remember := candidate.rememberMe
			if previous, exists := options[key]; exists {
				certificate = certificate && previous.CertificateRequired
				if previous.RememberMe.String() != remember.String() {
					if previous.RememberMe.EnabledByDefault() && remember.EnabledByDefault() {
						remember = configuration.RememberMeAllowedAndEnabledByDefault
					} else if previous.RememberMe.Allowed() || remember.Allowed() {
						remember = configuration.RememberMeAllowed
					} else {
						remember = configuration.RememberMeForbidden
					}
				}
			}
			options[key] = LoginOption{Method: method, RequestUser: named, CertificateRequired: certificate, RememberMe: remember}
		}
		add(LoginMethodPassword, capabilities.Password)
		add(LoginMethodKeyboardInteractive, capabilities.KeyboardInteractive)
		add(LoginMethodOidc, capabilities.OidcAuthorizationCode)
		add(LoginMethodPublicKey, capabilities.PublicKey)
		add(LoginMethodNone, capabilities.Secretless)
	}
	for _, named := range []bool{true, false} {
		for _, method := range []LoginMethod{LoginMethodPassword, LoginMethodKeyboardInteractive, LoginMethodOidc, LoginMethodPublicKey, LoginMethodNone} {
			if option, exists := options[optionKey{method, named}]; exists {
				result.Options = append(result.Options, option)
			}
		}
	}
	return result, nil
}
