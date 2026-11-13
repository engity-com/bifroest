//go:build unix && !darwin

package authorization

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

func newLocalRepositoryResumeFixture(t *testing.T, method string) (*LocalAuthorizer, *resumeTestRequest, *user.EtcColonRepository) {
	t.Helper()
	base := newFacadeSelectionRequest(t, "alice")
	sess, err := base.repository.Create(t.Context(), "selected", authenticationTestRemote("alice"), []byte(`{"user":{"name":"alice","uid":"1001"},"envVars":{"STALE":"not-current"}}`))
	require.NoError(t, err)
	root := t.TempDir()
	today := time.Now().Unix() / (24 * 60 * 60)
	for file, value := range map[string]string{
		"passwd": "alice:x:1001:1001:Alice:/home/alice:/bin/sh\n",
		"group":  "primary:x:1001:\nextra:x:1002:alice\n",
		"shadow": fmt.Sprintf("alice:$6$fixture$%s:%d:0:99999::::\n", strings.Repeat("A", 86), today-10),
	} {
		require.NoError(t, os.WriteFile(filepath.Join(root, file), []byte(value), 0600))
	}
	repository := &user.EtcColonRepository{PasswdFilename: filepath.Join(root, "passwd"), GroupFilename: filepath.Join(root, "group"), ShadowFilename: filepath.Join(root, "shadow"), FileSystemSyncThreshold: time.Hour}
	require.NoError(t, repository.Init(t.Context()))
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	conf := &configuration.AuthorizationLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.PamService = "" // The native PAM adapter is a separate capability.
	conf.Password.Allowed = template.BoolOf(true)
	conf.Password.InteractiveAllowed = template.BoolOf(true)
	conf.Password.EmptyAllowed = template.BoolOf(false)
	authorizer := &LocalAuthorizer{flow: "selected", conf: conf, userRepository: repository}
	request := &resumeTestRequest{Request: base, sess: sess, identity: authentication.Identity{Principal: "alice", Issuer: "local", Subject: "1001"}, credential: authentication.SessionCredential{Kind: "local", Method: method}, verified: true, selection: connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "Work"}}
	return authorizer, request, repository
}

func TestLocalRepositorySessionResumeUsesFreshNativePolicyWithoutPrimarySecret(t *testing.T) {
	for _, method := range []string{"password", "keyboard-interactive"} {
		t.Run(method, func(t *testing.T) {
			authorizer, request, repository := newLocalRepositoryResumeFixture(t, method)
			auth, err := authorizer.ResumeSession(request)
			require.NoError(t, err)
			require.Equal(t, request.sess.Id(), auth.FindSession().Id())
			require.Nil(t, auth.(*local).EnvVars(), "historical connection environment must not be resumed")
			require.Nil(t, AuthorizedKeyPolicyOf(auth))
			require.Zero(t, request.Request.(*facadeSelectionRequest).prompts)
			require.NoError(t, os.WriteFile(repository.GroupFilename, []byte("fresh:x:1001:\nfresh-extra:x:2002:alice\n"), 0600))
			auth, err = authorizer.ResumeSession(request)
			require.NoError(t, err)
			require.Equal(t, "fresh", auth.(*local).user.Group.Name)
			require.Equal(t, user.Groups{{Gid: 2002, Name: "fresh-extra"}}, auth.(*local).user.Groups)
			require.Equal(t, "wrong", request.Request.(*facadeSelectionRequest).password, "no primary password was replayed")
			shadow, err := os.ReadFile(repository.ShadowFilename)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(repository.ShadowFilename, []byte(strings.Replace(string(shadow), "alice:$6$", "alice:!$6$", 1)), 0600))
			auth, err = authorizer.ResumeSession(request)
			require.Nil(t, auth)
			require.ErrorIs(t, err, ErrSessionResumeDenied)
		})
	}
}

func TestLocalRepositorySessionResumeRetainsMethodIdentityAndPamBoundaries(t *testing.T) {
	for _, name := range []string{"password disabled", "interactive disabled", "unverified", "different identity", "different UID", "PAM configured", "missing native state", "missing pinned name", "missing pinned UID"} {
		t.Run(name, func(t *testing.T) {
			method := "password"
			if name == "interactive disabled" {
				method = "keyboard-interactive"
			}
			authorizer, request, repository := newLocalRepositoryResumeFixture(t, method)
			var expected error = ErrSessionResumeDenied
			switch name {
			case "password disabled":
				authorizer.conf.Password.Allowed = template.BoolOf(false)
			case "interactive disabled":
				authorizer.conf.Password.InteractiveAllowed = template.BoolOf(false)
			case "unverified":
				request.verified = false
			case "different identity":
				request.identity.Subject = "other"
			case "different UID":
				require.NoError(t, os.WriteFile(repository.PasswdFilename, []byte("alice:x:2002:1001:Alice:/home/alice:/bin/sh\n"), 0600))
			case "PAM configured":
				authorizer.conf.PamService = "native-account-policy-needed"
				expected = ErrSessionResumeUnavailable
			case "missing native state":
				require.NoError(t, os.Remove(repository.ShadowFilename))
				expected = ErrSessionResumeUnavailable
			case "missing pinned name":
				require.NoError(t, request.sess.SetAuthorizationToken(t.Context(), []byte(`{"user":{"uid":"1001"}}`)))
			case "missing pinned UID":
				require.NoError(t, request.sess.SetAuthorizationToken(t.Context(), []byte(`{"user":{"name":"alice"}}`)))
			}
			before, err := request.sess.AuthorizationToken(t.Context())
			require.NoError(t, err)
			auth, err := authorizer.ResumeSession(request)
			require.Nil(t, auth)
			require.ErrorIs(t, err, expected)
			after, err := request.sess.AuthorizationToken(t.Context())
			require.NoError(t, err)
			require.Equal(t, before, after, "denial must not repair or remove retained authorization state")
		})
	}
}

func TestLocalRepositorySessionResumeRechecksEmptyPasswordPolicy(t *testing.T) {
	authorizer, request, repository := newLocalRepositoryResumeFixture(t, "password")
	require.NoError(t, os.WriteFile(repository.PasswdFilename, []byte("alice::1001:1001:Alice:/home/alice:/bin/sh\n"), 0600))
	require.NoError(t, os.WriteFile(repository.ShadowFilename, nil, 0600))
	auth, err := authorizer.ResumeSession(request)
	require.Nil(t, auth)
	require.ErrorIs(t, err, ErrSessionResumeDenied)
	authorizer.conf.Password.EmptyAllowed = template.BoolOf(true)
	auth, err = authorizer.ResumeSession(request)
	require.NoError(t, err)
	require.Equal(t, request.sess.Id(), auth.FindSession().Id())
}

type localPolicyValidationRequest struct {
	*resumeTestRequest
	validate func(Authorization) (bool, error)
}

func (this localPolicyValidationRequest) Validate(auth Authorization) (bool, error) {
	return this.validate(auth)
}

func TestLocalRepositorySessionResumeRechecksNativeStateAfterValidation(t *testing.T) {
	for _, allowEmpty := range []bool{false, true} {
		for _, change := range []string{"lock", "groups"} {
			t.Run(fmt.Sprintf("empty=%v/%s", allowEmpty, change), func(t *testing.T) {
				authorizer, request, repository := newLocalRepositoryResumeFixture(t, "password")
				authorizer.conf.Password.EmptyAllowed = template.BoolOf(allowEmpty)
				wrapped := localPolicyValidationRequest{request, func(Authorization) (bool, error) {
					if change == "lock" {
						shadow, err := os.ReadFile(repository.ShadowFilename)
						require.NoError(t, err)
						require.NoError(t, os.WriteFile(repository.ShadowFilename, []byte(strings.Replace(string(shadow), "alice:", "alice:!", 1)), 0600))
					} else {
						require.NoError(t, os.WriteFile(repository.GroupFilename, []byte("primary:x:1001:\nchanged:x:2002:alice\n"), 0600))
					}
					return true, nil
				}}
				auth, err := authorizer.ResumeSession(wrapped)
				require.Nil(t, auth)
				require.ErrorIs(t, err, ErrSessionResumeDenied)
			})
		}
	}
}

type nativeOnlyResumeRepository struct {
	user.CloseableRepository
	current *user.User
}

func (this nativeOnlyResumeRepository) CheckPasswordAccount(context.Context, string, user.Id, user.PasswordAccountPolicy) (*user.User, error) {
	return this.current.Clone()
}

func TestLocalRepositorySessionResumeNeedsNoCachedLookupOrStoredEnvironment(t *testing.T) {
	authorizer, request, _ := newLocalRepositoryResumeFixture(t, "password")
	authorizer.userRepository = nativeOnlyResumeRepository{current: &user.User{Name: "alice", Uid: 1001}}
	auth, err := authorizer.ResumeSession(request)
	require.NoError(t, err, "unimplemented lookup and primary-password methods must never be called")
	require.Nil(t, auth.EnvVars())
}
