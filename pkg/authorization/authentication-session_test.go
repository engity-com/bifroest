package authorization

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

type principalKeyRequest struct {
	PublicKeyRequest
	ctx        context.Context
	repository session.Repository
	key        ssh.PublicKey
	resolved   Authorization
}

func (this *principalKeyRequest) Context() context.Context                   { return this.ctx }
func (this *principalKeyRequest) Sessions() session.Repository               { return this.repository }
func (this *principalKeyRequest) RemotePublicKey() ssh.PublicKey             { return this.key }
func (*principalKeyRequest) Connection() connection.Connection               { return principalKeyConnection{} }
func (this *principalKeyRequest) SetAuthorizationContext(auth Authorization) { this.resolved = auth }
func (*principalKeyRequest) Validate(auth Authorization) (bool, error) {
	identity, err := AuthenticationOf(auth)
	return identity.Principal == "user", err
}

type principalKeyConnection struct{ connection.Connection }

func (principalKeyConnection) Remote() net.Remote { return authenticationTestRemote("user") }

type principalCompatibilityRepository struct {
	session.Repository
	request *principalKeyRequest
	checked bool
}

func (this *principalCompatibilityRepository) FindByPublicKey(ctx context.Context, key ssh.PublicKey, opts *session.FindOpts) (session.Session, error) {
	// Like the service repository, evaluate environment compatibility after the
	// authorizer's predicates, before accepting its selected session.
	opts.Predicates = append(opts.Predicates, func(context.Context, session.Session) (bool, error) {
		this.checked = true
		identity, err := AuthenticationOf(this.request.resolved)
		return identity.Principal == "user", err
	})
	return this.Repository.FindByPublicKey(ctx, key, opts)
}

func TestHtpasswdSessionPrincipalAvailableBeforeCompatibilityCheck(t *testing.T) {
	for _, storedName := range []string{"user", "other-user", ""} {
		t.Run("stored-"+storedName, func(t *testing.T) {
			ctx := context.Background()
			var conf configuration.SessionFs
			require.NoError(t, conf.SetDefaults())
			conf.Storage = t.TempDir()
			repository, err := session.NewFacadeRepository(ctx, &configuration.Session{V: &conf})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, repository.Close()) })
			token, err := json.Marshal(htpasswdToken{User: htpasswdTokenUser{Name: storedName}})
			require.NoError(t, err)
			sess, err := repository.Create(ctx, "flow", authenticationTestRemote("user"), token)
			require.NoError(t, err)
			publicKey, _, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			key, err := ssh.NewPublicKey(publicKey)
			require.NoError(t, err)
			require.NoError(t, sess.AddPublicKey(ctx, key))
			request := &principalKeyRequest{ctx: ctx, key: key}
			compatible := &principalCompatibilityRepository{Repository: repository, request: request}
			request.repository = compatible
			authorizer := &HtpasswdAuthorizer{flow: "flow"}
			auth, err := authorizer.AuthorizePublicKey(request)
			require.NoError(t, err)
			if storedName == "user" {
				require.True(t, compatible.checked)
				require.True(t, auth.IsAuthorized())
				identity, err := AuthenticationOf(auth)
				require.NoError(t, err)
				require.Equal(t, storedName, identity.Principal)
			} else {
				require.False(t, compatible.checked)
				require.False(t, auth.IsAuthorized())
			}
		})
	}
}
