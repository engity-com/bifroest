package authorization

import (
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
)

// LoginMethod is a discovery/UI choice, separate from authentication audit values.
// In particular, a secretless action does not add a new authentication adapter.
type LoginMethod string

const (
	LoginMethodPassword            LoginMethod = "password"
	LoginMethodKeyboardInteractive LoginMethod = "keyboard-interactive"
	LoginMethodPublicKey           LoginMethod = "public-key"
	LoginMethodNone                LoginMethod = "none"
)

type LoginOption struct {
	Method              LoginMethod `json:"method"`
	RequestUser         bool        `json:"requestUser"`
	CertificateRequired bool        `json:"certificateRequired"`
}

type HttpLoginDescription struct {
	Available bool
	Options   []LoginOption
}

type HttpLoginDescriber interface {
	DescribeHttpLogin(host, slug string) (HttpLoginDescription, error)
}

var _ HttpLoginDescriber = (*AuthorizerFacade)(nil)

// DescribeHttpLogin shares the authoritative facade's canonical selection and
// published-slug pinning, but never attempts authentication. Unknown remote names
// must not eliminate named flows; nameless flows still check the concrete empty
// name. Capabilities are unioned by input mode, not across incompatible username
// prompts. Availability depends on requirements, not on credentials or methods.
func (this *AuthorizerFacade) DescribeHttpLogin(host, slug string) (HttpLoginDescription, error) {
	selection, err := (connection.Selection{Transport: connection.TransportHttp, Host: host, Slug: slug}).Canonical()
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
		capabilities := candidate.capabilityProvider.AuthenticationCapabilities(DiscoveryInput{Transport: connection.TransportHttp, RequestingName: named})
		add := func(method LoginMethod, possible bool) {
			if !possible {
				return
			}
			key := optionKey{method, named}
			certificate := method == LoginMethodPublicKey && capabilities.PublicKeyCertificateRequired
			if previous, exists := options[key]; exists {
				certificate = certificate && previous.CertificateRequired
			}
			options[key] = LoginOption{Method: method, RequestUser: named, CertificateRequired: certificate}
		}
		add(LoginMethodPassword, capabilities.Password)
		add(LoginMethodKeyboardInteractive, capabilities.KeyboardInteractive)
		add(LoginMethodPublicKey, capabilities.PublicKey)
		add(LoginMethodNone, capabilities.Secretless)
	}
	for _, named := range []bool{true, false} {
		for _, method := range []LoginMethod{LoginMethodPassword, LoginMethodKeyboardInteractive, LoginMethodPublicKey, LoginMethodNone} {
			if option, exists := options[optionKey{method, named}]; exists {
				result.Options = append(result.Options, option)
			}
		}
	}
	return result, nil
}
