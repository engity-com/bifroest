//go:build unix

package authorization

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

type remoteNameUnixRepository struct {
	user.CloseableRepository
	users                  map[string]*user.User
	lookups, passwordNames []string
	policyCalls            int
	denyPolicy             bool
}

func (r *remoteNameUnixRepository) LookupByName(_ context.Context, name string) (*user.User, error) {
	r.lookups = append(r.lookups, name)
	if value := r.users[name]; value != nil {
		copy := *value
		return &copy, nil
	}
	return nil, user.ErrNoSuchUser
}
func (r *remoteNameUnixRepository) ValidatePasswordByName(_ context.Context, name, password string) (bool, error) {
	r.passwordNames = append(r.passwordNames, name)
	return r.users[name] != nil && password == "correct", nil
}
func (r *remoteNameUnixRepository) CheckPasswordAccount(ctx context.Context, name string, id user.Id, _ user.PasswordAccountPolicy) (*user.User, error) {
	r.policyCalls++
	if r.denyPolicy {
		return nil, user.ErrPasswordAccountPolicyDenied
	}
	value, err := r.LookupByName(ctx, name)
	if err != nil || value.Uid != id {
		return nil, user.ErrPasswordAccountPolicyDenied
	}
	return value, nil
}

func mappedUnixAuthorizer(t *testing.T) (*LocalAuthorizer, *remoteNameUnixRepository) {
	t.Helper()
	conf := &configuration.AuthorizationLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.PamService = ""
	conf.RemoteName = template.MustNewString(stripRemoteSuffix)
	repo := &remoteNameUnixRepository{users: map[string]*user.User{"alice": {Name: "alice", Uid: 1001}, "bob": {Name: "bob", Uid: 2002}}}
	return &LocalAuthorizer{flow: "selected", conf: conf, userRepository: repo}, repo
}

func TestLocalRemoteNameCertificateSelectsMappedAccountAndRetainsPolicies(t *testing.T) {
	for _, principal := range []string{"alice", "alice@node-a", "bob"} {
		t.Run(principal, func(t *testing.T) {
			auth, repo := mappedUnixAuthorizer(t)
			authority := newEvidenceTestSigner(t)
			cert := newUserCertificateTestCertificate(t, authority, newEvidenceTestSigner(t).PublicKey(), time.Now())
			cert.ValidPrincipals = []string{principal}
			require.NoError(t, cert.SignCert(rand.Reader, authority))
			auth.conf.AuthorizedKeys = nil
			auth.trustedUserCAs = []ssh.PublicKey{authority.PublicKey()}
			base := newFacadeSelectionRequest(t, "alice@node-a")
			base.key = cert
			result, err := auth.AuthorizePublicKey(&mappingTestRequest{facadeSelectionRequest: base})
			require.NoError(t, err)
			require.Equal(t, []string{"alice"}, repo.lookups)
			if principal == "alice" {
				require.True(t, result.IsAuthorized())
				require.Equal(t, "alice@node-a", result.Remote().User())
				identity, err := AuthenticationOf(result)
				require.NoError(t, err)
				require.Equal(t, "1001", identity.Subject)
				require.False(t, AuthorizedKeyPolicyOf(result).PortForwardingAllowed)
			} else {
				require.False(t, result.IsAuthorized())
				require.Zero(t, sessionCount(t, base.repository))
			}
		})
	}
}

func TestNativeAuthorizedKeysTemplateInheritsIncomingConnectionMetadata(t *testing.T) {
	base := newFacadeSelectionRequest(t, "alice@bar")
	req := &mappingTestRequest{facadeSelectionRequest: base, selection: connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "docker"}}
	for _, request := range []Request{req, resumePublicKeyRequest{Request: req, key: base.key}} {
		ctx := &userEnabledRequest{Request: request, user: &user.User{Name: "alice", Uid: 1001}}
		actual, err := template.MustNewString(`{{.connection.transport}}|{{.connection.http.slug}}|{{.remote.user}}|{{.user.name}}`).Render(ctx)
		require.NoError(t, err)
		require.Equal(t, "http|docker|alice@bar|alice", actual)
	}
}

func TestLocalRemoteNameResumeAndRememberedKeyCannotFollowMappingOrUidChanges(t *testing.T) {
	auth, repo := mappedUnixAuthorizer(t)
	base := newFacadeSelectionRequest(t, "alice@node-a")
	key := newEvidenceTestSigner(t).PublicKey()
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0600))
	auth.conf.AuthorizedKeys = template.Strings{template.MustNewString(path)}
	base.key = key
	r := &mappingTestRequest{facadeSelectionRequest: base, selection: connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "Work"}}
	initial, err := auth.AuthorizePublicKey(r)
	require.NoError(t, err)
	require.True(t, initial.IsAuthorized())
	require.NoError(t, initial.FindSession().AddPublicKey(t.Context(), key))
	identity, err := AuthenticationOf(initial)
	require.NoError(t, err)
	resume := &resumeTestRequest{Request: r, sess: initial.FindSession(), identity: identity, credential: authentication.SessionCredential{Kind: "local", Method: "public-key", PublicKey: base64.StdEncoding.EncodeToString(key.Marshal())}, verified: true, selection: r.selection}
	resumed, err := auth.ResumeSession(resume)
	require.NoError(t, err)
	require.Equal(t, initial.FindSession().Id(), resumed.FindSession().Id())
	auth.conf.RemoteName = configuration.DefaultAuthorizationRemoteName
	_, err = auth.ResumeSession(resume)
	require.ErrorIs(t, err, ErrSessionResumeDenied, "removing the mapping cannot retain access through its old account selector")
	auth.conf.RemoteName = template.MustNewString("bob")
	_, err = auth.ResumeSession(resume)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	auth.conf.RemoteName = template.MustNewString(stripRemoteSuffix)
	repo.users["alice"].Uid = 2002
	_, err = auth.ResumeSession(resume)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	repo.users["alice"].Uid = 1001
	base.name = "alice@node-b"
	_, err = auth.ResumeSession(resume)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	require.Equal(t, 1, sessionCount(t, base.repository))
}
