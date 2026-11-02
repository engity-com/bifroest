package service

import (
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestBrowserSlugRouterAndLoginOptionsKeepWorkspacesAndInputModes(t *testing.T) {
	key := ssh.MarshalAuthorizedKey(webLoginTestSigner(t).PublicKey())
	testBrowserLoginUi(t, true, "login-options", func(conf *configuration.Configuration) {
		oidc := conf.Flows[0]
		oidc.Name, oidc.DiscoverAsSlug = "oidc", ""
		oidc.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Mixed$")
		password := oidc
		password.Name, password.DiscoverAsSlug = "password", "Work"
		password.Http.RequestUser = commonBool(true)
		password.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Work$")
		password.Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}}}
		mixed := password
		mixed.Name, mixed.DiscoverAsSlug = "mixed-password", ""
		mixed.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Mixed$")
		keys := password
		keys.Name, keys.DiscoverAsSlug = "keys", "Keys"
		keys.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Keys$")
		keys.Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", AuthorizedKeys: crypto.AuthorizedKeys(key)}}}
		certificates := keys
		certificates.Name, certificates.DiscoverAsSlug = "certificates", "Certificates"
		certificates.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Certificates$")
		certificates.Authorization.V = &configuration.AuthorizationSimple{UserCertificateAuthorityProperties: configuration.UserCertificateAuthorityProperties{TrustedUserCAs: crypto.PublicKeys(key)}, Entries: configuration.AuthorizationSimpleEntries{{Name: "alice"}}}
		public := password
		public.Name, public.DiscoverAsSlug = "public", "Public"
		public.Http.RequestUser = commonBool(false)
		public.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Public$")
		public.Authorization.V = &configuration.AuthorizationNone{}
		empty := password
		empty.Name, empty.DiscoverAsSlug = "empty", "Empty"
		empty.Requirement.Http.IncludedSlug = common.MustNewRegexp("^Empty$")
		empty.Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice"}}}
		conf.Flows = configuration.Flows{mixed, oidc, password, keys, certificates, public, empty}
	})
}
