package service

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestHtpasswdRememberedSSHKeyRequiresCurrentAccount(t *testing.T) {
	for _, source := range []string{"entries", "file", "missing file"} {
		t.Run(source, func(t *testing.T) {
			var settings *configuration.AuthorizationHtpasswd
			path := filepath.Join(t.TempDir(), "owned-htpasswd")
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
				settings = &configuration.AuthorizationHtpasswd{}
				hash := sha1.Sum([]byte("correct"))
				entry := fmt.Sprintf("restricted-key-user:{SHA}%s\n", base64.StdEncoding.EncodeToString(hash[:]))
				if source == "entries" {
					require.NoError(t, settings.Entries.Set(entry))
				} else {
					require.NoError(t, os.WriteFile(path, []byte(entry), 0600))
					require.NoError(t, settings.File.Set(path))
				}
				conf.Flows[0].Authorization.V = settings
				conf.Flows[0].Authorization.RememberMe = configuration.RememberMeAllowedAndEnabledByDefault
			})
			client, err := dialSdkMigrationServerWithClientConfig(server, func(conf *ssh.ClientConfig) {
				conf.Auth = []ssh.AuthMethod{ssh.PublicKeys(server.signer), ssh.Password("correct")}
			})
			require.NoError(t, err)
			channel, err := client.NewSession()
			require.NoError(t, err)
			_, err = channel.Output("register owned test key")
			require.NoError(t, err)
			_ = channel.Close()
			require.NoError(t, client.Close())
			returning, err := server.dial()
			require.NoError(t, err, "existing account can use its registered key")
			require.NoError(t, returning.Close())
			switch source {
			case "entries":
				settings.Entries = crypto.Htpasswd{}
			case "file":
				require.NoError(t, os.WriteFile(path, []byte("other:{SHA}irrelevant\n"), 0600))
			case "missing file":
				require.NoError(t, os.Remove(path))
			}
			denied, err := server.dial()
			if denied != nil {
				_ = denied.Close()
			}
			require.Error(t, err, "removed accounts and unavailable sources must not authorize remembered keys")
		})
	}
}
