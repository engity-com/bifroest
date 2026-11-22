package authorization

import "github.com/engity-com/bifroest/pkg/authentication"

// localAuthenticationIdentity is shared by observed local authentication and
// explicitly assumed test results. Callers determine account provenance and
// validate facts separately; this mapping is not authentication evidence.
func localAuthenticationIdentity(name, subject string) authentication.Identity {
	return authentication.Identity{Principal: name, Issuer: "local", Subject: subject}
}
