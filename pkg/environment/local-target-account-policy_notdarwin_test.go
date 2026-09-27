//go:build unix && !darwin

package environment

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestUnixTargetAccountPolicyIsAppliedOutsideDarwin(t *testing.T) {
	repository := newUnixTargetAccountTestRepository()
	target := newUnixTargetAccountTestUser("alice", 1000)

	accepted, err := repository.isTargetAccountAccepted(target)
	require.NoError(t, err)
	require.True(t, accepted)

	target.Uid = 0
	accepted, err = repository.isTargetAccountAccepted(target)
	require.NoError(t, err)
	require.False(t, accepted)

	target = newUnixTargetAccountTestUser("alice", 1000)
	repository.conf.TargetAccountPolicy.DeniedNames = []string{"alice"}
	accepted, err = repository.isTargetAccountAccepted(target)
	require.NoError(t, err)
	require.False(t, accepted)
}

func TestUnixTargetAccountPolicyChecksShellOutsideDarwin(t *testing.T) {
	repository := newUnixTargetAccountTestRepository()
	repository.conf.TargetAccountPolicy.AllowNonLoginShell = false
	checked := false
	repository.targetAccountShellValidator = func(string) error {
		checked = true
		return errors.Newf(errors.Permission, "denied test shell")
	}

	accepted, err := repository.isTargetAccountAccepted(newUnixTargetAccountTestUser("alice", 1000))
	require.NoError(t, err)
	require.False(t, accepted)
	require.True(t, checked)
}

func TestUnixEnvironmentTokensStoreAuthorizationKindAndAcceptLegacyTokens(t *testing.T) {
	repository := newUnixTargetAccountTestRepository()
	target := newUnixTargetAccountTestUser("alice", 1000)
	repository.userRepository = &unixTargetAccountTestUserRepository{
		lookupByName: func(context.Context, string) (*user.User, error) { return target, nil },
		lookupById:   func(context.Context, user.Id) (*user.User, error) { return target, nil },
	}
	request, closeRequest := newUnixTargetAccountTestRequest(t)
	defer closeRequest()
	request.authorization.(*sshTestAuthorization).kind = "simple"

	token, err := repository.newLocalToken(target, request, false)
	require.NoError(t, err)
	require.Equal(t, "simple", token.AuthorizationKind)

	legacy, err := json.Marshal(localToken{User: localTokenUser{Name: target.Name, Uid: &target.Uid}})
	require.NoError(t, err)
	sess := &sshTestStoredSession{id: session.MustNewId(), environmentToken: legacy}
	restored, err := repository.FindBySession(context.Background(), sess, nil)
	require.NoError(t, err)
	require.NotNil(t, restored)
}

func TestUnixNoneAuthorizationFailsClosedDuringEnsure(t *testing.T) {
	repository := newUnixTargetAccountTestRepository()
	request, closeRequest := newUnixTargetAccountTestRequest(t)
	defer closeRequest()
	request.authorization.(*sshTestAuthorization).kind = "none"

	actual, err := repository.Ensure(request)
	require.Nil(t, actual)
	require.ErrorIs(t, err, ErrNotAcceptable)
}

func TestUnixExistingEnvironmentMappingMismatchIsRejected(t *testing.T) {
	repository := newUnixTargetAccountTestRepository()
	alice := newUnixTargetAccountTestUser("alice", 1000)
	bob := newUnixTargetAccountTestUser("bob", 1001)
	repository.conf.User.Name = template.MustNewString("bob")
	repository.userRepository = &unixTargetAccountTestUserRepository{
		lookupByName: func(_ context.Context, name string) (*user.User, error) {
			if name == "alice" {
				return alice, nil
			}
			return bob, nil
		},
		lookupById: func(context.Context, user.Id) (*user.User, error) { return alice, nil },
	}
	stored, err := json.Marshal(localToken{
		User:              localTokenUser{Name: alice.Name, Uid: &alice.Uid},
		AuthorizationKind: "simple",
	})
	require.NoError(t, err)
	request, closeRequest := newUnixTargetAccountTestRequest(t)
	defer closeRequest()
	request.authorization.(*sshTestAuthorization).kind = "simple"
	request.authorization.FindSession().(*sshTestStoredSession).environmentToken = stored

	actual, err := repository.Ensure(request)
	require.Nil(t, actual)
	require.ErrorIs(t, err, ErrNotAcceptable)
}

type unixTargetAccountTestUserRepository struct {
	user.CloseableRepository
	lookupByName func(context.Context, string) (*user.User, error)
	lookupById   func(context.Context, user.Id) (*user.User, error)
}

func (this *unixTargetAccountTestUserRepository) LookupByName(ctx context.Context, name string) (*user.User, error) {
	return this.lookupByName(ctx, name)
}

func (this *unixTargetAccountTestUserRepository) LookupById(ctx context.Context, id user.Id) (*user.User, error) {
	return this.lookupById(ctx, id)
}

func newUnixTargetAccountTestRepository() *LocalRepository {
	conf := &configuration.EnvironmentLocal{}
	conf.User.Name = template.MustNewString("alice")
	_ = conf.SetDefaults()
	conf.TargetAccountPolicy.AllowNonLoginShell = true
	return &LocalRepository{
		conf:                        conf,
		targetAccountShellValidator: func(string) error { return nil },
	}
}

func newUnixTargetAccountTestUser(name string, id user.Id) *user.User {
	return &user.User{
		Name:    name,
		Uid:     id,
		Group:   user.Group{Name: "users", Gid: 100},
		Shell:   "/bin/sh",
		HomeDir: "/home/" + name,
	}
}

func newUnixTargetAccountTestRequest(t *testing.T) (*sshTestTask, context.CancelFunc) {
	t.Helper()
	ctx, cancel := newSshTestContext()
	storedSession := &sshTestStoredSession{id: session.MustNewId()}
	return &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: storedSession},
	}, cancel
}
