//go:build unix

package environment

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

type targetTestUsers struct {
	user.CloseableRepository
	account *user.User
}

func (this *targetTestUsers) LookupByName(context.Context, string) (*user.User, error) {
	if this.account == nil {
		return nil, user.ErrNoSuchUser
	}
	return this.account, nil
}
func (this *targetTestUsers) LookupById(context.Context, user.Id) (*user.User, error) {
	if this.account == nil {
		return nil, user.ErrNoSuchUser
	}
	return this.account, nil
}

type targetTestSession struct {
	session.Session
	raw []byte
}

func (this targetTestSession) EnvironmentToken(context.Context) ([]byte, error) { return this.raw, nil }

func TestLocalTargetIsStableAcrossDeferredCreationButRejectsReplacedUid(t *testing.T) {
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.User.Name = template.MustNewString("{{.authentication.principal}}")
	users := &targetTestUsers{}
	repo := &LocalRepository{conf: conf, userRepository: users}
	ctx := targetTestContext{ctx: t.Context(), principal: "alice"}
	before, err := repo.ResolveSessionTarget(ctx)
	require.NoError(t, err)
	users.account = &user.User{Name: "alice", Uid: 1234}
	after, err := repo.ResolveSessionTarget(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after)
	uid := user.Id(1234)
	raw, err := json.Marshal(localToken{User: localTokenUser{Name: "alice", Uid: &uid}})
	require.NoError(t, err)
	compatible, err := repo.IsSessionCompatibleWith(ctx, targetTestSession{raw: raw})
	require.NoError(t, err)
	require.True(t, compatible)
	legacy, err := json.Marshal(localToken{User: localTokenUser{Name: "alice"}})
	require.NoError(t, err)
	compatible, err = repo.IsSessionCompatibleWith(ctx, targetTestSession{raw: legacy})
	require.NoError(t, err)
	require.True(t, compatible, "unbound name-only legacy metadata retains lookup semantics")
	users.account = &user.User{Name: "alice", Uid: 5678}
	compatible, err = repo.IsSessionCompatibleWith(ctx, targetTestSession{raw: raw})
	require.NoError(t, err)
	require.False(t, compatible)
	users.account = nil
	compatible, err = repo.IsSessionCompatibleWith(ctx, targetTestSession{raw: raw})
	require.NoError(t, err)
	require.False(t, compatible)
}
