package service

import (
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestBrowserUiPreferencesRequireNamesAndRememberOnlySuccessfulOriginalNames(t *testing.T) {
	testBrowserLoginUi(t, true, "preferences", func(conf *configuration.Configuration) {
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = bfcrypto.AuthorizedKeys(ssh.MarshalAuthorizedKey(webLoginTestSigner(t).PublicKey()))
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries = append(
			conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries,
			configuration.AuthorizationSimpleEntry{Name: "bob", Password: bfcrypto.Password("plain:correct")},
		)
		other := conf.Flows[0]
		other.Name, other.DiscoverAsSlug = "other", "Other"
		nameFree := conf.Flows[0]
		nameFree.Name, nameFree.DiscoverAsSlug = "namefree", "NameFree"
		nameFree.Http.RequestUser = commonBool(false)
		conf.Flows = append(conf.Flows, other, nameFree)
	})
}
