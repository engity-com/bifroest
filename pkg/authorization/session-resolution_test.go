package authorization

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
)

type resolutionTestRequest struct {
	*verificationTestRequest
	password string
	calls    int
	selected session.Session
	err      error
}

func (this *resolutionTestRequest) RemotePassword() string              { return this.password }
func (this *resolutionTestRequest) Prompt(string, bool) (string, error) { return this.password, nil }
func (*resolutionTestRequest) SendInfo(string) error                    { return nil }
func (*resolutionTestRequest) SendError(string) error                   { return nil }
func (this *resolutionTestRequest) ResolveAuthenticatedSession(auth Authorization, token []byte) (session.Session, bool, error) {
	this.calls++
	if this.err != nil {
		return nil, true, this.err
	}
	if this.selected != nil {
		return this.selected, true, nil
	}
	sess, err := this.repository.Create(this.ctx, auth.Flow(), this.Connection().Remote(), token)
	return sess, true, err
}

func TestPrimarySessionResolutionOnlyAfterCredentialsAndKeyProof(t *testing.T) {
	for _, kind := range []string{"simple", "htpasswd"} {
		t.Run(kind, func(t *testing.T) {
			repo := newVerificationTestRepository(t)
			key := newUserCertificateTestSigner(t).PublicKey()
			var authorizer CloseableAuthorizer
			if kind == "simple" {
				conf := &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "user", Password: crypto.Password("plain:correct"), AuthorizedKeys: crypto.AuthorizedKeys(ssh.MarshalAuthorizedKey(key))}}}
				var err error
				authorizer, err = NewSimple(t.Context(), "flow", conf)
				require.NoError(t, err)
			} else {
				hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
				require.NoError(t, err)
				conf := &configuration.AuthorizationHtpasswd{}
				require.NoError(t, conf.Entries.Set("user:"+string(hash)))
				authorizer, err = NewHtpasswd(t.Context(), "flow", conf)
				require.NoError(t, err)
			}
			defer authorizer.Close()
			req := &resolutionTestRequest{verificationTestRequest: &verificationTestRequest{ctx: t.Context(), repository: repo, key: key}, password: "wrong"}
			auth, err := authorizer.AuthorizePassword(req)
			require.NoError(t, err)
			require.False(t, auth.IsAuthorized())
			require.Zero(t, req.calls)
			req.password = "correct"
			auth, err = authorizer.AuthorizePassword(req)
			require.NoError(t, err)
			require.True(t, auth.IsAuthorized())
			require.Equal(t, 1, req.calls)
			req.selected = auth.FindSession()
			auth, err = authorizer.AuthorizeInteractive(req)
			require.NoError(t, err)
			require.True(t, auth.IsAuthorized())
			require.Equal(t, 2, req.calls)
			require.Equal(t, req.selected.Id(), auth.FindSession().Id())
			if kind == "simple" {
				_, err = authorizer.AuthorizePublicKey(req)
				require.NoError(t, err)
				require.Equal(t, 2, req.calls, "unsigned probe cannot allocate")
				req.verified = true
				_, err = authorizer.AuthorizePublicKey(req)
				require.NoError(t, err)
				require.Equal(t, 3, req.calls)
			}
			req.err = fmt.Errorf("selection unavailable")
			_, err = authorizer.AuthorizePassword(req)
			require.ErrorContains(t, err, "selection unavailable")
		})
	}
}
