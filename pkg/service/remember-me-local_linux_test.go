//go:build linux

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestLocalSSHRememberMeUsesNativePolicyWithoutAuthorizedKeys(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "interactive"}[interactive], func(t *testing.T) {
			repository, originalShadow := prepareLocalRememberTestRepository(t)
			server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, "alice", "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
				localRememberTestConfiguration(t)(conf)
				conf.Flows[0].DiscoverAsSlug = ""
				conf.Flows[0].Authorization.V.(*configuration.AuthorizationLocal).AuthorizedKeys = nil
				conf.Flows[0].Authorization.RememberMe = configuration.RememberMeAllowedAndEnabledByDefault
			})
			client, err := dialSdkMigrationServerWithClientConfig(server, func(conf *ssh.ClientConfig) {
				primary := ssh.Password("correct")
				if interactive {
					primary = ssh.KeyboardInteractive(func(_ string, _ string, questions []string, _ []bool) ([]string, error) {
						answers := make([]string, len(questions))
						for i := range answers {
							answers[i] = "correct"
						}
						return answers, nil
					})
				}
				conf.Auth = []ssh.AuthMethod{ssh.PublicKeys(server.signer), primary}
			})
			require.NoError(t, err)
			channel, err := client.NewSession()
			require.NoError(t, err)
			_, err = channel.Output("remember")
			require.NoError(t, err)
			_ = channel.Close()
			require.NoError(t, client.Close())
			returning, err := server.dial()
			require.NoError(t, err)
			require.NoError(t, returning.Close())
			require.NoError(t, os.WriteFile(repository.ShadowFilename, []byte(strings.Replace(originalShadow, "alice:", "alice:!", 1)), 0600))
			denied, err := server.dial()
			require.Error(t, err, "a remembered key cannot bypass a current password-account lock")
			if denied != nil {
				_ = denied.Close()
			}
			require.NoError(t, os.WriteFile(repository.ShadowFilename, []byte(originalShadow), 0600))
			returning, err = server.dial()
			require.NoError(t, err)
			channel, err = returning.NewSession()
			require.NoError(t, err)
			require.NoError(t, channel.Setenv("REMEMBER_ME", "false"))
			_, err = channel.Output("forget key")
			require.NoError(t, err)
			_ = channel.Close()
			require.NoError(t, returning.Close())
			denied, err = server.dial()
			require.Error(t, err, "explicit opt-out must revoke future access, not merely skip renewal")
			if denied != nil {
				_ = denied.Close()
			}
		})
	}
}

func TestLocalSSHRememberMeCannotBypassConfiguredKeyRestrictions(t *testing.T) {
	prepareLocalRememberTestRepository(t)
	keyFile := filepath.Join(t.TempDir(), "authorized_keys")
	server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, "alice", "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		public := string(conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys)
		require.NoError(t, os.WriteFile(keyFile, []byte(`from="192.0.2.0/24" `+public+"\n"), 0600))
		localRememberTestConfiguration(t)(conf)
		conf.Flows[0].DiscoverAsSlug = ""
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationLocal).AuthorizedKeys = template.MustNewStrings(keyFile)
		conf.Flows[0].Authorization.RememberMe = configuration.RememberMeAllowedAndEnabledByDefault
	})
	client, err := dialSdkMigrationServerWithClientConfig(server, func(conf *ssh.ClientConfig) {
		conf.Auth = []ssh.AuthMethod{ssh.PublicKeys(server.signer), ssh.Password("correct")}
	})
	require.NoError(t, err)
	channel, err := client.NewSession()
	require.NoError(t, err)
	_, err = channel.Output("remember")
	require.NoError(t, err)
	_ = channel.Close()
	require.NoError(t, client.Close())
	denied, err := server.dial()
	require.Error(t, err, "a password-derived remembered key cannot bypass its configured from restriction")
	if denied != nil {
		_ = denied.Close()
	}
}
