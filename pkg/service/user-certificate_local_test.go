//go:build unix

package service

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
	buser "github.com/engity-com/bifroest/pkg/user"
)

func TestLocalAuthorizationAcceptsUserCertificates(t *testing.T) {
	const username = "certificate-local-user"
	current, err := osuser.Current()
	require.NoError(t, err)
	userDirectory := t.TempDir()
	passwdFile := filepath.Join(userDirectory, "passwd")
	groupFile := filepath.Join(userDirectory, "group")
	shadowFile := filepath.Join(userDirectory, "shadow")
	require.NoError(t, os.WriteFile(passwdFile, []byte(username+":x:"+current.Uid+":"+current.Gid+"::"+current.HomeDir+":/bin/sh\n"), 0600))
	require.NoError(t, os.WriteFile(groupFile, []byte(username+":x:"+current.Gid+":"+username+"\n"), 0600))
	require.NoError(t, os.WriteFile(shadowFile, []byte(username+":!:19722:0:99999:7:::\n"), 0600))
	previousRepositoryProvider := buser.DefaultRepositoryProvider
	buser.DefaultRepositoryProvider = &buser.SharedRepositoryProvider[*buser.EtcColonRepository]{V: &buser.EtcColonRepository{
		PasswdFilename: passwdFile,
		GroupFilename:  groupFile,
		ShadowFilename: shadowFile,
	}}
	t.Cleanup(func() { buser.DefaultRepositoryProvider = previousRepositoryProvider })

	authority := newIncomingCertificateTestSigner(t)
	plainAuthority := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey())))

	for _, trustPath := range []string{"trusted-user-cas", "trusted-user-cas-file", "authorized-keys-cert-authority"} {
		t.Run(trustPath, func(t *testing.T) {
			directory := t.TempDir()
			caFile := filepath.Join(directory, "ca")
			authorizedKeysFile := filepath.Join(directory, "authorized_keys")
			require.NoError(t, os.WriteFile(caFile, []byte(plainAuthority+"\n"), 0600))
			require.NoError(t, os.WriteFile(authorizedKeysFile, []byte(`cert-authority,principals="`+username+`" `+plainAuthority+"\n"), 0600))

			server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, username, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
				local := &configuration.AuthorizationLocal{}
				require.NoError(t, local.SetDefaults())
				switch trustPath {
				case "trusted-user-cas":
					local.AuthorizedKeys = template.Strings{}
					local.TrustedUserCAs = crypto.PublicKeys(plainAuthority)
				case "trusted-user-cas-file":
					local.AuthorizedKeys = template.Strings{}
					local.TrustedUserCAsFile = crypto.PublicKeysFile(caFile)
				case "authorized-keys-cert-authority":
					local.AuthorizedKeys = template.Strings{template.MustNewString(authorizedKeysFile)}
				}
				conf.Flows[0].Authorization.V = local
			})
			certificateSigner := newIncomingCertificateSigner(t, authority, server.signer, username, nil)

			client, err := dialAuthorizedKeysTestServer(server, certificateSigner)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			require.NoError(t, sshSession.Run("true"))
		})
	}
}
