package common

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestConfiguredSSHFilesAreProtectedWithoutReadingKeys(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{}
	file := func(name string) string {
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, []byte("preserve "+name), 0600))
		files[name] = path
		return path
	}
	conf := &configuration.Configuration{}
	conf.Ssh.Keys.HostKeys = template.MustNewStrings(file("host-1"), file("host-2"))
	conf.Flows = configuration.Flows{
		{Name: "plain", Environment: configuration.Environment{V: &configuration.EnvironmentSsh{
			IdentityFiles:  template.MustNewStrings(file("login-1"), file("login-2")),
			KnownHostsFile: bfcrypto.KnownHostsFile(file("known-hosts")),
		}}, Authorization: configuration.Authorization{V: &configuration.AuthorizationSimple{
			UserCertificateAuthorityProperties: configuration.UserCertificateAuthorityProperties{TrustedUserCAsFile: bfcrypto.PublicKeysFile(file("simple-ca-trust"))},
			Entries:                            configuration.AuthorizationSimpleEntries{{Name: "alice", AuthorizedKeysFile: bfcrypto.AuthorizedKeysFile(file("simple-authorized-keys"))}},
		}}},
		{Name: "certificate", Environment: configuration.Environment{V: &configuration.EnvironmentSsh{
			Certificate: &configuration.EnvironmentSshCertificate{
				IdentityFile: template.MustNewString(file("certificate-subject")), AuthorityIdentityFile: template.MustNewString(file("certificate-ca")),
			},
		}}},
		{Name: "local", Authorization: configuration.Authorization{V: &configuration.AuthorizationLocal{
			UserCertificateAuthorityProperties: configuration.UserCertificateAuthorityProperties{TrustedUserCAsFile: bfcrypto.PublicKeysFile(file("local-ca-trust"))},
			AuthorizedKeys:                     template.MustNewStrings(file("local-authorized-keys")),
		}}},
		{Name: "delegated", Authorization: configuration.Authorization{V: &configuration.AuthorizationBifroest{
			UserCertificateAuthorityProperties: configuration.UserCertificateAuthorityProperties{TrustedUserCAsFile: bfcrypto.PublicKeysFile(file("delegated-ca-trust"))},
		}}},
	}
	var control bytes.Buffer
	require.NoError(t, EnsureConfiguredSSHOutputSafe(t.Context(), "-", &control, conf))
	safe := filepath.Join(root, "safe-output")
	require.NoError(t, EnsureConfiguredSSHOutputSafe(t.Context(), safe, nil, conf))
	require.NoFileExists(t, safe, "checking a destination must not create it or parse the deliberately non-key fixture contents")
	for name, path := range files {
		for _, alias := range []string{"direct", "hardlink", "symlink"} {
			t.Run(name+"/"+alias, func(t *testing.T) {
				destination := path
				if alias != "direct" {
					destination = filepath.Join(t.TempDir(), "output-alias")
					var err error
					if alias == "hardlink" {
						err = os.Link(path, destination)
					} else {
						err = os.Symlink(path, destination)
					}
					if err != nil {
						t.Skipf("%s unavailable: %v", alias, err)
					}
				}
				before, err := os.ReadFile(path)
				require.NoError(t, err)
				require.ErrorContains(t, EnsureConfiguredSSHOutputSafe(t.Context(), destination, nil, conf), "must not replace")
				output, err := os.OpenFile(destination, os.O_WRONLY|os.O_APPEND, 0)
				require.NoError(t, err)
				require.ErrorContains(t, EnsureStandardOutputSafe(t.Context(), output, "", conf, nil), "must not replace")
				require.NoError(t, output.Close())
				after, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, before, after)
			})
		}
	}
}

func TestSSHOutputChecksDoNotGenerateKeysOrRenderSessionTemplates(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing-host-key")
	conf := &configuration.Configuration{}
	conf.Ssh.Keys.HostKeys = template.MustNewStrings(missing, "{{ .session.id }}")
	conf.Flows = configuration.Flows{{Environment: configuration.Environment{V: &configuration.EnvironmentSsh{
		IdentityFiles: template.MustNewStrings(filepath.Join(root, "missing-login-key"), "{{ .session.id }}"),
	}}}}
	output, err := os.Create(filepath.Join(root, "safe-output"))
	require.NoError(t, err)
	defer output.Close()
	require.NoError(t, EnsureStandardOutputSafe(t.Context(), output, "", conf, nil))
	require.NoFileExists(t, missing)
	require.NoFileExists(t, filepath.Join(root, "missing-login-key"))
	require.ErrorContains(t, EnsureConfiguredSSHOutputSafe(t.Context(), missing, nil, conf), "must not replace")
	require.NoFileExists(t, missing)
	alias := filepath.Join(t.TempDir(), "keys")
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	require.ErrorContains(t, EnsureConfiguredSSHOutputSafe(t.Context(), filepath.Join(alias, "missing-host-key"), nil, conf), "must not replace")
	require.NoFileExists(t, missing)
}
