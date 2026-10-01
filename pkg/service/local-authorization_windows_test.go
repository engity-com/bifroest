//go:build windows

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func TestWindowsLocalSSHAuthorization(t *testing.T) {
	username := os.Getenv("BIFROEST_WINDOWSLOCAL_TEST_USER")
	if username == "" {
		t.Skip("set BIFROEST_WINDOWSLOCAL_TEST_USER to an enabled local SAM user")
	}
	u, err := windowslocal.Lookup(username)
	require.NoError(t, err)
	disabled, err := windowslocal.Disabled(u)
	require.NoError(t, err)
	require.False(t, disabled)

	authority := newIncomingCertificateTestSigner(t)
	keyFile := filepath.Join(t.TempDir(), "authorized_keys")
	server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, username, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		local := &configuration.AuthorizationLocal{}
		require.NoError(t, local.SetDefaults())
		local.AuthorizedKeys = template.Strings{template.MustNewString(keyFile)}
		local.TrustedUserCAs = crypto.PublicKeys(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(authority.PublicKey()))))
		conf.Flows[0].Authorization.V = local
	})
	require.NoError(t, os.WriteFile(keyFile, gossh.MarshalAuthorizedKey(server.signer.PublicKey()), 0600))

	for name, signer := range map[string]gossh.Signer{
		"authorized_keys": server.signer,
		"certificate":     newIncomingCertificateSigner(t, authority, server.signer, username, nil),
	} {
		t.Run(name, func(t *testing.T) {
			client, err := dialAuthorizedKeysTestServer(server, signer)
			require.NoError(t, err)
			defer client.Close()
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			require.NoError(t, sshSession.Run("allowed"))
		})
	}
	other := newIncomingCertificateTestSigner(t)
	client, err := dialAuthorizedKeysTestServer(server, other)
	if client != nil {
		_ = client.Close()
	}
	require.Error(t, err)

	if password := os.Getenv("BIFROEST_WINDOWSLOCAL_TEST_PASSWORD"); password != "" {
		for name, auth := range map[string]gossh.AuthMethod{
			"password": gossh.Password(password),
			"interactive": gossh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				require.Len(t, questions, 1)
				return []string{password}, nil
			}),
		} {
			t.Run(name, func(t *testing.T) {
				client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
					User: username, Auth: []gossh.AuthMethod{auth},
					HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // Test-local server.
					Timeout:         5 * time.Second,
				})
				require.NoError(t, err)
				defer client.Close()
			})
		}
		client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
			User: username, Auth: []gossh.AuthMethod{gossh.Password(password + "-wrong")},
			HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // Test-local server.
			Timeout:         5 * time.Second,
		})
		if client != nil {
			_ = client.Close()
		}
		require.Error(t, err)
	}
}
