package authorization

import (
	"errors"
	"fmt"

	"github.com/engity-com/bifroest/pkg/authentication"
)

var ErrAuthenticationUnavailable = errors.New("verified authentication identity is unavailable")

// AuthenticationOf does not turn the unverified requesting name into an
// authenticated principal. Third-party authorizations and decorators can expose
// a normalized identity by implementing authentication.Provider.
func AuthenticationOf(auth Authorization) (authentication.Identity, error) {
	if auth == nil || !auth.IsAuthorized() {
		return authentication.Anonymous(), nil
	}
	provider, ok := auth.(authentication.Provider)
	if !ok {
		return authentication.Identity{}, ErrAuthenticationUnavailable
	}
	identity, err := provider.Authentication()
	if err != nil {
		return authentication.Identity{}, err
	}
	if err := identity.Validate(); err != nil {
		return authentication.Identity{}, fmt.Errorf("%w: %w", ErrAuthenticationUnavailable, err)
	}
	return identity, nil
}

func (this *simple) Authentication() (authentication.Identity, error) {
	if this.entry == nil {
		return authentication.Identity{}, ErrAuthenticationUnavailable
	}
	return authentication.Identity{Principal: this.entry.Name, Issuer: "simple", Subject: this.entry.Name}, nil
}

func (this *htpasswd) Authentication() (authentication.Identity, error) {
	if this.principal == "" {
		return authentication.Identity{}, ErrAuthenticationUnavailable
	}
	return authentication.Identity{Principal: this.principal, Issuer: "htpasswd", Subject: this.principal}, nil
}

func (*none) Authentication() (authentication.Identity, error) {
	return authentication.Anonymous(), nil
}

func (this *oidc) Authentication() (authentication.Identity, error) {
	if !this.identity.IsAuthenticated() {
		return authentication.Identity{}, ErrAuthenticationUnavailable
	}
	return this.identity, nil
}

func (this *BifroestAuthorization) Authentication() (authentication.Identity, error) {
	if this.evidence == nil || len(this.evidence.Hops) == 0 {
		return authentication.Identity{}, ErrAuthenticationUnavailable
	}
	if this.evidence.Origin.AuthorizationKind == "none" {
		return authentication.Anonymous(), nil
	}
	// Evidence v1 carries an original user, not an OIDC issuer/subject pair.
	// Scope that attested name to its originating CA and authorization kind;
	// never merge names attested by unrelated authorities.
	return authentication.Identity{
		Principal: this.evidence.Origin.User,
		Issuer:    "bifroest:" + this.evidence.Hops[0].CaFingerprint + ":" + this.evidence.Origin.AuthorizationKind,
		Subject:   this.evidence.Origin.User,
	}, nil
}
