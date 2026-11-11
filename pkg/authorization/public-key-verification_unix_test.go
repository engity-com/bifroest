//go:build unix

package authorization

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

type verificationTestUsers struct{ user.CloseableRepository }

func (verificationTestUsers) LookupByName(context.Context, string) (*user.User, error) {
	return &user.User{Name: "user", Uid: 1234}, nil
}

func TestLocalRawPublicKeyProbeAllocatesOnlyAfterProof(t *testing.T) {
	repository := newVerificationTestRepository(t)
	key := newUserCertificateTestSigner(t).PublicKey()
	file := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(file, ssh.MarshalAuthorizedKey(key), 0600))
	authorizer := &LocalAuthorizer{flow: "flow", conf: &configuration.AuthorizationLocal{AuthorizedKeys: template.MustNewStrings(file)}, userRepository: verificationTestUsers{}}
	req := &verificationTestRequest{ctx: t.Context(), repository: repository, key: key}
	auth, err := authorizer.AuthorizePublicKey(req)
	require.NoError(t, err)
	require.True(t, auth.IsAuthorized())
	require.Nil(t, auth.FindSession())
	count := 0
	require.NoError(t, repository.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	require.Zero(t, count)
	req.verified = true
	auth, err = authorizer.AuthorizePublicKey(req)
	require.NoError(t, err)
	require.True(t, auth.IsAuthorized())
	require.NotNil(t, auth.FindSession())
}
