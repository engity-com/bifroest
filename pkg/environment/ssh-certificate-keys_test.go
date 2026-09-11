package environment

import (
	goos "os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestEnsureSshCertificateAuthorityCreatesAndReusesKeyWithoutPublicFile(t *testing.T) {
	directory := t.TempDir()
	authorityFile := filepath.Join(directory, "ca")
	flow := newSshCertificateKeyTestFlow(t, authorityFile)

	first, firstPath, err := EnsureSshCertificateAuthority(flow)
	require.NoError(t, err)
	second, secondPath, err := EnsureSshCertificateAuthority(flow)
	require.NoError(t, err)
	require.Equal(t, authorityFile, firstPath)
	require.Equal(t, firstPath, secondPath)
	require.Equal(t, gossh.FingerprintSHA256(first.ToSsh().PublicKey()), gossh.FingerprintSHA256(second.ToSsh().PublicKey()))
	require.FileExists(t, authorityFile)
	require.NoFileExists(t, authorityFile+".pub")
}

func TestEnsureSshCertificateAuthorityDoesNotReplaceInvalidKey(t *testing.T) {
	authorityFile := filepath.Join(t.TempDir(), "ca")
	require.NoError(t, goos.WriteFile(authorityFile, []byte("invalid"), 0400))
	flow := newSshCertificateKeyTestFlow(t, authorityFile)

	_, _, err := EnsureSshCertificateAuthority(flow)
	require.Error(t, err)
	actual, readErr := goos.ReadFile(authorityFile)
	require.NoError(t, readErr)
	require.Equal(t, []byte("invalid"), actual)
}

func newSshCertificateKeyTestFlow(t *testing.T, authorityFile string) *configuration.Flow {
	t.Helper()
	certificate := &configuration.EnvironmentSshCertificate{}
	require.NoError(t, certificate.SetDefaults())
	certificate.IdentityFile = template.MustNewString(filepath.Join(filepath.Dir(authorityFile), "client-key"))
	certificate.AuthorityIdentityFile = template.MustNewString(authorityFile)
	return &configuration.Flow{
		Name: "entry",
		Environment: configuration.Environment{V: &configuration.EnvironmentSsh{
			Certificate: certificate,
		}},
	}
}
