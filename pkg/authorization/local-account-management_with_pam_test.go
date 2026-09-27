//go:build cgo && (linux || darwin) && !without_pam

package authorization

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"
	"github.com/msteinert/pam/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalPublicKeyAccountCheckRunsOnlyAfterVerification(t *testing.T) {
	signer := newUserCertificateTestSigner(t)
	path := filepath.Join(newSecureLocalAuthorizedKeysTestDirectory(t), "authorized_keys")
	require.NoError(t, os.WriteFile(path, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0600))

	for _, verified := range []bool{false, true} {
		t.Run(map[bool]string{false: "candidate", true: "verified"}[verified], func(t *testing.T) {
			tx := &pamTestTransaction{}
			repository := &pamAccountTestSessionRepository{}
			authorizer := newPamAccountTestLocalAuthorizer(&configuration.AuthorizationLocal{
				AuthorizedKeys: template.MustNewStrings(path),
			}, func(username, remoteHost string) (bool, error) {
				require.Equal(t, "alice", username)
				require.Equal(t, "203.0.113.20", remoteHost)
				return pamAccountForPamHandlerFunc(pamTestFactory(tx), "sshd", username, remoteHost)
			})
			req := newPamAccountTestPublicKeyRequest(signer.PublicKey(), verified, repository)

			auth, err := authorizer.AuthorizePublicKey(req)

			require.NoError(t, err)
			require.True(t, auth.IsAuthorized())
			if verified {
				require.Equal(t, []string{"set-item", "acct-mgmt", "end"}, tx.calls)
				require.Equal(t, 1, repository.createCalls)
				require.NotNil(t, auth.FindSession())
			} else {
				require.Empty(t, tx.calls)
				require.Zero(t, repository.createCalls)
				require.Nil(t, auth.FindSession())
			}
		})
	}
}

func TestLocalPublicKeyAccountDenialForbidsVerifiedKey(t *testing.T) {
	signer := newUserCertificateTestSigner(t)
	path := filepath.Join(newSecureLocalAuthorizedKeysTestDirectory(t), "authorized_keys")
	require.NoError(t, os.WriteFile(path, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0600))
	tx := &pamTestTransaction{acctMgmtErr: pam.ErrPermDenied}
	repository := &pamAccountTestSessionRepository{}
	authorizer := newPamAccountTestLocalAuthorizer(&configuration.AuthorizationLocal{
		AuthorizedKeys: template.MustNewStrings(path),
	}, func(username, remoteHost string) (bool, error) {
		return pamAccountForPamHandlerFunc(pamTestFactory(tx), "sshd", username, remoteHost)
	})

	auth, err := authorizer.AuthorizePublicKey(newPamAccountTestPublicKeyRequest(signer.PublicKey(), true, repository))

	require.NoError(t, err)
	require.False(t, auth.IsAuthorized())
	require.Equal(t, []string{"set-item", "acct-mgmt", "end"}, tx.calls)
	require.Zero(t, repository.createCalls)
}

func TestLocalUserCertificateChecksPamAccountAfterVerification(t *testing.T) {
	authority := newUserCertificateTestSigner(t)
	certificate := newUserCertificateTestCertificate(t, authority, newUserCertificateTestSigner(t).PublicKey(), time.Now())
	tx := &pamTestTransaction{}
	repository := &pamAccountTestSessionRepository{}
	authorizer := newPamAccountTestLocalAuthorizer(&configuration.AuthorizationLocal{}, func(username, remoteHost string) (bool, error) {
		return pamAccountForPamHandlerFunc(pamTestFactory(tx), "sshd", username, remoteHost)
	})
	authorizer.trustedUserCAs = []ssh.PublicKey{authority.PublicKey()}

	auth, err := authorizer.AuthorizePublicKey(newPamAccountTestPublicKeyRequest(certificate, true, repository))

	require.NoError(t, err)
	require.True(t, auth.IsAuthorized())
	require.NotNil(t, auth.FindSession())
	require.True(t, AuthorizedKeyPolicyOf(auth).PtyAllowed)
	require.Equal(t, []string{"set-item", "acct-mgmt", "end"}, tx.calls)
	require.Equal(t, 1, repository.createCalls)
}

func TestLocalRestoreRechecksPamAccount(t *testing.T) {
	for _, test := range []struct {
		name          string
		acctMgmtErr   error
		endErr        error
		expectedError error
		systemError   bool
	}{
		{name: "success"},
		{name: "denial", acctMgmtErr: pam.ErrAcctExpired, expectedError: ErrUnusableAuthorizationToken},
		{name: "unexpected error", acctMgmtErr: pam.ErrSystem, systemError: true},
		{name: "end error", endErr: fmt.Errorf("cannot end PAM"), systemError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &pamTestTransaction{acctMgmtErr: test.acctMgmtErr, endErr: test.endErr}
			authorizer := newPamAccountTestLocalAuthorizer(&configuration.AuthorizationLocal{}, func(username, remoteHost string) (bool, error) {
				require.Equal(t, "alice", username)
				require.Equal(t, "198.51.100.8", remoteHost)
				return pamAccountForPamHandlerFunc(pamTestFactory(tx), "sshd", username, remoteHost)
			})
			sess := &pamAccountTestRestoreSession{
				authorizationRestoreTestSession: authorizationRestoreTestSession{
					flow:  "flow",
					token: []byte(`{"user":{"name":"alice","uid":"501"}}`),
				},
				remote: pamAccountTestRemote{user: "alice", host: bnet.MustNewHost("198.51.100.8")},
			}

			auth, err := authorizer.RestoreFromSession(context.Background(), sess, &RestoreOpts{})

			require.Equal(t, []string{"set-item", "acct-mgmt", "end"}, tx.calls, "restore error: %v", err)
			if test.expectedError != nil {
				require.ErrorIs(t, err, test.expectedError)
				require.Nil(t, auth)
				require.Zero(t, sess.setTokenCalls)
			} else if test.systemError {
				require.Error(t, err)
				require.True(t, berrors.IsType(err, berrors.System))
				require.Nil(t, auth)
				require.Zero(t, sess.setTokenCalls)
			} else {
				require.NoError(t, err)
				require.True(t, auth.IsAuthorized())
				require.Equal(t, "198.51.100.8", auth.Remote().Host().String())
			}
		})
	}
}

func newPamAccountTestLocalAuthorizer(conf *configuration.AuthorizationLocal, checker func(string, string) (bool, error)) *LocalAuthorizer {
	u := &user.User{Name: "alice", Uid: 501}
	return &LocalAuthorizer{
		flow:           "flow",
		conf:           conf,
		userRepository: &pamAccountTestUserRepository{user: u},
		accountChecker: checker,
	}
}

type pamAccountTestUserRepository struct {
	user.CloseableRepository
	user *user.User
}

func (this *pamAccountTestUserRepository) LookupByName(context.Context, string) (*user.User, error) {
	return this.user, nil
}

func (this *pamAccountTestUserRepository) LookupById(context.Context, user.Id) (*user.User, error) {
	return this.user, nil
}

type pamAccountTestRemote struct {
	user string
	host bnet.Host
}

func (this pamAccountTestRemote) User() string    { return this.user }
func (this pamAccountTestRemote) Host() bnet.Host { return this.host }
func (this pamAccountTestRemote) String() string  { return this.user + "@" + this.host.String() }

type pamAccountTestConnection struct {
	remote bnet.Remote
}

func (pamAccountTestConnection) Id() connection.Id        { return connection.Id{} }
func (this pamAccountTestConnection) Remote() bnet.Remote { return this.remote }
func (pamAccountTestConnection) Logger() log.Logger       { return log.GetRootLogger() }

type pamAccountTestPublicKeyRequest struct {
	key        ssh.PublicKey
	verified   bool
	sessions   session.Repository
	connection connection.Connection
}

func newPamAccountTestPublicKeyRequest(key ssh.PublicKey, verified bool, sessions session.Repository) *pamAccountTestPublicKeyRequest {
	remote := pamAccountTestRemote{user: "alice", host: bnet.MustNewHost("203.0.113.20")}
	return &pamAccountTestPublicKeyRequest{
		key:        key,
		verified:   verified,
		sessions:   sessions,
		connection: pamAccountTestConnection{remote: remote},
	}
}

func (this *pamAccountTestPublicKeyRequest) Sessions() session.Repository { return this.sessions }
func (this *pamAccountTestPublicKeyRequest) Connection() connection.Connection {
	return this.connection
}
func (*pamAccountTestPublicKeyRequest) Context() essh.Context                { return nil }
func (*pamAccountTestPublicKeyRequest) Validate(Authorization) (bool, error) { return true, nil }
func (this *pamAccountTestPublicKeyRequest) RemotePublicKey() ssh.PublicKey  { return this.key }
func (this *pamAccountTestPublicKeyRequest) PublicKeyVerified() bool         { return this.verified }

type pamAccountTestSessionRepository struct {
	session.Repository
	createCalls int
}

func (*pamAccountTestSessionRepository) FindByPublicKey(context.Context, ssh.PublicKey, *session.FindOpts) (session.Session, error) {
	return nil, session.ErrNoSuchSession
}

func (*pamAccountTestSessionRepository) FindByAccessToken(context.Context, []byte, *session.FindOpts) (session.Session, error) {
	return nil, session.ErrNoSuchSession
}

func (this *pamAccountTestSessionRepository) Create(_ context.Context, flow configuration.FlowName, _ bnet.Remote, token []byte) (session.Session, error) {
	this.createCalls++
	return &authorizationRestoreTestSession{flow: flow, token: token}, nil
}

type pamAccountTestRestoreSession struct {
	authorizationRestoreTestSession
	remote bnet.Remote
}

func (this *pamAccountTestRestoreSession) Info(context.Context) (session.Info, error) {
	return pamAccountTestInfo{remote: this.remote}, nil
}

type pamAccountTestInfo struct {
	session.Info
	remote bnet.Remote
}

func (this pamAccountTestInfo) LastAccessed(context.Context) (session.InfoLastAccessed, error) {
	return pamAccountTestLastAccessed{remote: this.remote}, nil
}

type pamAccountTestLastAccessed struct {
	session.InfoLastAccessed
	remote bnet.Remote
}

func (this pamAccountTestLastAccessed) Remote() bnet.Remote { return this.remote }
