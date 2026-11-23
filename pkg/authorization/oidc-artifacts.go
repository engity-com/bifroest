package authorization

import (
	"fmt"

	coidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func oidcIdentity(issuer, subject string) authentication.Identity {
	return authentication.Identity{Principal: subject, Issuer: issuer, Subject: subject}
}

// Retrieval is supplied by the caller. This shared publication boundary owns
// artifact visibility and identity consistency, not transport or verification.
type oidcArtifactSource struct {
	hasIDToken      bool
	expectedIssuer  string
	expectedSubject string
	providerIssuer  string
	idToken         func() (*coidc.IDToken, error)
	userInfo        func() (*coidc.UserInfo, error)
	onVerified      func(string)
}

func (this *oidc) publishArtifacts(conf *configuration.AuthorizationOidcDeviceAuth, allowed bool, source oidcArtifactSource) error {
	verified := func(message string) {
		if source.onVerified != nil {
			source.onVerified(message)
		}
	}
	if allowed && conf.RetrieveIdToken && source.hasIDToken {
		idToken, err := source.idToken()
		if err != nil {
			return err
		}
		if source.expectedSubject != "" && (idToken.Subject != source.expectedSubject || idToken.Issuer != source.expectedIssuer) {
			return fmt.Errorf("OIDC ID token identity differs from session identity")
		}
		this.idToken.IDToken = idToken
		this.identity = oidcIdentity(idToken.Issuer, idToken.Subject)
		verified("ID token verified")
	} else if allowed && conf.RetrieveIdToken && !conf.RefreshEnabled() {
		return fmt.Errorf("token does not contain id_token")
	}
	if allowed && conf.RetrieveUserInfo {
		userInfo, err := source.userInfo()
		if err != nil {
			return err
		}
		this.userInfo.UserInfo = userInfo
		if this.identity.IsAuthenticated() && userInfo.Subject != this.identity.Subject {
			return fmt.Errorf("OIDC UserInfo subject differs from authenticated identity")
		}
		if !this.identity.IsAuthenticated() && source.providerIssuer != "" && userInfo.Subject != "" {
			this.identity = oidcIdentity(source.providerIssuer, userInfo.Subject)
		}
		verified("UserInfo verified")
	}
	return nil
}
