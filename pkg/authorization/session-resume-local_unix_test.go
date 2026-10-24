//go:build unix

package authorization

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

type resumeLocalUserRepository struct {
	user.CloseableRepository
	current *user.User
}

func (this *resumeLocalUserRepository) LookupByName(context.Context, string) (*user.User, error) {
	if this.current == nil {
		return nil, user.ErrNoSuchUser
	}
	copy := *this.current
	return &copy, nil
}

func TestLocalSessionResumeUsesCurrentUidAndCurrentKeyPolicy(t *testing.T) {
	base := newFacadeSelectionRequest(t, "alice")
	sess, err := base.repository.Create(t.Context(), "selected", authenticationTestRemote("alice"), []byte(`{"user":{"name":"alice","uid":"1001"}}`))
	require.NoError(t, err)
	conf := &configuration.AuthorizationLocal{}
	require.NoError(t, conf.SetDefaults())
	key := newEvidenceTestSigner(t).PublicKey()
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0600))
	conf.AuthorizedKeys = template.Strings{template.MustNewString(path)}
	repo := &resumeLocalUserRepository{current: &user.User{Name: "alice", Uid: 1001}}
	authorizer := &LocalAuthorizer{flow: "selected", conf: conf, userRepository: repo}
	request := &resumeTestRequest{Request: base, sess: sess, identity: authentication.Identity{Principal: "alice", Issuer: "local", Subject: "1001"}, credential: authentication.SessionCredential{Kind: "local", Method: "public-key", PublicKey: base64.StdEncoding.EncodeToString(key.Marshal())}, verified: true, selection: connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "Work"}}
	auth, err := authorizer.ResumeSession(request)
	require.NoError(t, err)
	require.Equal(t, sess.Id(), auth.FindSession().Id())
	require.NoError(t, os.WriteFile(path, nil, 0600))
	_, err = authorizer.ResumeSession(request)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	require.NoError(t, os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0600))
	repo.current.Uid = 2002
	_, err = authorizer.ResumeSession(request)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	repo.current = nil
	_, err = authorizer.ResumeSession(request)
	require.ErrorIs(t, err, ErrUnusableAuthorizationToken)
	for _, method := range []string{"password", "keyboard-interactive"} {
		request.credential = authentication.SessionCredential{Kind: "local", Method: method}
		_, err = authorizer.ResumeSession(request)
		require.ErrorIs(t, err, ErrSessionResumeUnavailable, "UID lookup alone cannot bypass current native account policy")
	}
}
