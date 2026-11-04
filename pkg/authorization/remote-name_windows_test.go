//go:build windows

package authorization

import (
	"crypto/rand"
	"os/user"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func TestWindowsLocalRemoteNameUsesCurrentAccountAndMappedCertificatePrincipal(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)
	account, err := windowslocal.LookupBySID(current.Uid)
	require.NoError(t, err)
	conf := &configuration.AuthorizationLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.RemoteName = template.MustNewString(stripRemoteSuffix)
	conf.AuthorizedKeys = nil
	authority := newEvidenceTestSigner(t)
	auth := &LocalAuthorizer{flow: "selected", conf: conf, trustedUserCAs: []ssh.PublicKey{authority.PublicKey()}}
	for _, principal := range []string{account.Name, account.Name + "@node-a"} {
		cert := newUserCertificateTestCertificate(t, authority, newEvidenceTestSigner(t).PublicKey(), time.Now())
		cert.ValidPrincipals = []string{principal}
		require.NoError(t, cert.SignCert(rand.Reader, authority))
		base := newFacadeSelectionRequest(t, account.Name+"@node-a")
		base.key = cert
		result, err := auth.AuthorizePublicKey(base)
		require.NoError(t, err)
		if principal == account.Name {
			require.True(t, result.IsAuthorized())
			require.Equal(t, account.SID, result.(*local).user.SID)
			require.Equal(t, base.name, result.Remote().User())
			require.Nil(t, result.FindSession())
		} else {
			require.False(t, result.IsAuthorized())
		}
		require.Zero(t, sessionCount(t, base.repository), "eligibility probes cannot allocate sessions")
	}
	base := newFacadeSelectionRequest(t, account.Name+"@node-a")
	sess, err := base.repository.Create(t.Context(), "selected", base.Connection().Remote(), []byte(`{}`))
	require.NoError(t, err)
	name, err := auth.resumeRemoteName(base, sess, account)
	require.NoError(t, err)
	require.Equal(t, account.Name, name)
	wrong := account
	wrong.SID += "-1"
	_, err = auth.resumeRemoteName(base, sess, wrong)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	base.name = account.Name + "@node-b"
	_, err = auth.resumeRemoteName(base, sess, account)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
}
