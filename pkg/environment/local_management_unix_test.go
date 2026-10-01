//go:build unix

package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

type localManagementTestUsers struct {
	user.CloseableRepository
	account        *user.User
	group          *user.Group
	deleted        bool
	kills          int
	absentHomes    int
	absentHomeFail bool
}

type localManagementTestRequest struct{ Request }

func (localManagementTestRequest) GetField(name string) (any, bool, error) {
	if name == "authorization" {
		return map[string]any{"name": "remote-user"}, true, nil
	}
	return nil, false, nil
}

func (this *localManagementTestUsers) LookupByName(_ context.Context, name string) (*user.User, error) {
	if this.account == nil || this.account.Name != name {
		return nil, user.ErrNoSuchUser
	}
	return this.account, nil
}

func (this *localManagementTestUsers) LookupGroupByName(_ context.Context, name string) (*user.Group, error) {
	if this.group == nil || this.group.Name != name {
		return nil, user.ErrNoSuchGroup
	}
	return this.group, nil
}

func (this *localManagementTestUsers) LookupById(_ context.Context, id user.Id) (*user.User, error) {
	if this.account == nil || this.account.Uid != id {
		return nil, user.ErrNoSuchUser
	}
	return this.account, nil
}

func (this *localManagementTestUsers) DeleteByIdentity(_ context.Context, id user.Id, name, _ string, _ *user.DeleteOpts) error {
	if this.account == nil || this.account.Uid != id || this.account.Name != name {
		return user.ErrNoSuchUser
	}
	this.deleted = true
	this.account = nil
	return nil
}

func (this *localManagementTestUsers) KillProcessesByIdentity(_ context.Context, id user.Id, name string) error {
	if this.account == nil || this.account.Uid != id || this.account.Name != name {
		return user.ErrNoSuchUser
	}
	this.kills++
	return nil
}

func (this *localManagementTestUsers) DeleteHomeByAbsentIdentity(_ context.Context, id user.Id, name, home string) error {
	if this.account != nil || id == 0 || name == "" || home == "" {
		return fmt.Errorf("identity is not safely absent")
	}
	if this.absentHomeFail {
		return fmt.Errorf("injected absent home cleanup failure")
	}
	this.absentHomes++
	return nil
}

func TestLocalUnixGetEnsureOptsOfManagedUserAndAuthorization(t *testing.T) {
	conf := &configuration.EnvironmentLocal{
		EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{
			CreateIfAbsent:    template.BoolOf(true),
			UpdateIfDifferent: template.MustNewBool(`{{ if eq .authorization.name "remote-user" }}{{ .user.managed }}{{ else }}true{{ end }}`),
		},
	}
	repository := &LocalRepository{conf: conf}
	account := &user.User{Name: "local-user", Uid: 1234}

	for _, test := range []struct {
		name    string
		managed bool
	}{
		{name: "managed", managed: true},
		{name: "unmanaged", managed: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts, err := repository.getEnsureOptsOf(localManagementTestRequest{}, account, test.managed)
			require.NoError(t, err)
			require.True(t, opts.createIfAbsent)
			require.Equal(t, test.managed, opts.updateIfDifferent)
		})
	}
}

func TestLocalUnixUIDOnlyDoesNotUpdateExistingAccount(t *testing.T) {
	for _, test := range []struct {
		name   string
		uid    user.Id
		create bool
		update bool
	}{
		{name: "lookup only", uid: 2_000_000_000},
		{name: "update only", uid: 2_000_000_000, update: true},
		{name: "create and update", uid: 2_000_000_000, create: true, update: true},
		{name: "protected UID lookup", uid: 0, update: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := newSshTestContext()
			defer cancel()
			conf := &configuration.EnvironmentLocal{}
			require.NoError(t, conf.SetDefaults())
			uid := template.MustNewTextMarshaller[user.Id, *user.Id](fmt.Sprint(test.uid))
			conf.User.Uid = &uid
			conf.CreateIfAbsent = template.BoolOf(test.create)
			conf.UpdateIfDifferent = template.BoolOf(test.update)
			account := &user.User{
				Name: "alice", Uid: test.uid, DisplayName: "Alice", Shell: "/bin/sh",
				HomeDir: "/home/existing-alice", Group: user.Group{Name: "existing-team", Gid: 2001},
			}
			stored := &sshTestStoredSession{id: session.MustNewId()}
			repository := &LocalRepository{conf: conf, userRepository: &localManagementTestUsers{account: account}}
			request := &sshTestTask{context: ctx, authorization: &sshTestAuthorization{session: stored}}
			resolved, err := repository.Ensure(request)
			if test.update && test.uid != 0 {
				require.ErrorContains(t, err, "cannot update existing local account by UID alone")
				require.True(t, bferrors.Config.IsErr(err))
				require.Nil(t, resolved)
			} else {
				require.NoError(t, err)
				require.Equal(t, account, resolved.(*local).user)
			}
			encoded, err := stored.EnvironmentToken(ctx)
			require.NoError(t, err)
			if test.update && test.uid != 0 {
				require.Empty(t, encoded)
			} else {
				require.NotEmpty(t, encoded)
			}
			require.Equal(t, "alice", account.Name)
			require.Equal(t, "/home/existing-alice", account.HomeDir)
		})
	}
}

func TestLocalUnixUnmanagedCleanupSnapshot(t *testing.T) {
	conf := &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{
		PortForwardingAllowed:      template.BoolOf(true),
		DeleteOnDispose:            template.MustNewBool("{{ not .user.managed }}"),
		DeleteHomeTogetherWithUser: template.BoolOf(true),
		KillProcessesOnDispose:     template.BoolOf(true),
	}}
	repository := &LocalRepository{conf: conf}
	account := &user.User{Name: "ordinary", Uid: 1234, HomeDir: "/home/ordinary"}
	token, err := repository.newLocalToken(account, localTemplateTestRequest{}, false, false)
	require.NoError(t, err)
	require.False(t, token.User.Managed)
	require.True(t, token.User.DeleteOnDispose)
	require.True(t, token.User.DeleteHomeTogetherWithUser)
	require.True(t, token.User.KillProcessesOnDispose)

	conf.DeleteOnDispose = template.BoolOf(false)
	token, err = repository.newLocalToken(account, localTemplateTestRequest{}, false, false)
	require.NoError(t, err)
	require.False(t, token.User.DeleteOnDispose)
	require.False(t, token.User.DeleteHomeTogetherWithUser)
	require.True(t, token.User.KillProcessesOnDispose)
}

func TestLocalUnixManagedDefaultAndUnavailableUserField(t *testing.T) {
	account := &user.User{Name: "alice", Uid: 1234}
	value, exists, err := account.GetField("managed")
	require.NoError(t, err)
	require.True(t, exists)
	require.Nil(t, value)
	rendered, err := template.MustNewString("{{ if .user.managed }}true{{ else }}null{{ end }}").Render(map[string]any{"user": account})
	require.NoError(t, err)
	require.Equal(t, "null", rendered)
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	repository := &LocalRepository{conf: conf}
	for _, managed := range []bool{false, true} {
		token, err := repository.newLocalToken(account, localTemplateTestRequest{}, managed, false)
		require.NoError(t, err)
		require.Equal(t, managed, token.User.KillProcessesOnDispose)
		require.False(t, token.User.DeleteOnDispose)
	}
}

func TestLocalUnixIsManagedUserMatchesGroupGID(t *testing.T) {
	const managedGroup = "bifroest-managed"
	for _, test := range []struct {
		name    string
		account *user.User
		group   *user.Group
		want    bool
	}{
		{name: "primary group by GID", account: &user.User{Group: user.Group{Gid: 42, Name: "renamed"}}, group: &user.Group{Gid: 42, Name: managedGroup}, want: true},
		{name: "supplemental group by GID", account: &user.User{Group: user.Group{Gid: 10}, Groups: user.Groups{{Gid: 42, Name: "renamed"}}}, group: &user.Group{Gid: 42, Name: managedGroup}, want: true},
		{name: "different GID", account: &user.User{Group: user.Group{Gid: 10, Name: managedGroup}, Groups: user.Groups{{Gid: 11, Name: managedGroup}}}, group: &user.Group{Gid: 42, Name: managedGroup}},
		{name: "managed group absent", account: &user.User{Group: user.Group{Gid: 42}}, group: nil},
		{name: "user absent", account: nil, group: &user.Group{Gid: 42, Name: managedGroup}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &LocalRepository{
				conf:           &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{ManagedGroup: managedGroup}},
				userRepository: &localManagementTestUsers{group: test.group},
			}
			managed, err := repository.isManagedUser(context.Background(), test.account)
			require.NoError(t, err)
			require.Equal(t, test.want, managed)
		})
	}
}

func TestLocalUnixFindBySessionLegacyTokenDoesNotDeleteUser(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	account := &user.User{Name: "local-user", Uid: uid}
	stored := &sshTestStoredSession{id: session.MustNewId()}
	encoded, err := json.Marshal(localToken{
		User: localTokenUser{
			Name: "local-user", Uid: &uid, DeleteOnDispose: true,
			DeleteHomeTogetherWithUser: true, KillProcessesOnDispose: true,
		},
	})
	require.NoError(t, err)
	require.NoError(t, stored.SetEnvironmentToken(ctx, encoded))
	repository := &LocalRepository{userRepository: &localManagementTestUsers{account: account}}

	resolved, err := repository.FindBySession(ctx, stored, nil)
	require.NoError(t, err)
	localEnv, ok := resolved.(*local)
	require.True(t, ok)
	require.Same(t, account, localEnv.user)
	require.False(t, localEnv.deleteUserOnDispose)
	require.False(t, localEnv.deleteHomeTogetherWithUser)
	require.False(t, localEnv.killProcessesOnDispose)

	account.Uid = uid + 1
	resolved, err = repository.FindBySession(ctx, stored, nil)
	require.Nil(t, resolved)
	require.Error(t, err)
	require.Equal(t, encoded, stored.environmentToken, "UID mismatch must not clear the token without explicit cleanup")
}

func TestLocalUnixSkipsUnverifiableAccountProcessCleanup(t *testing.T) {
	uid := user.Id(2_000_000_000)
	for _, test := range []struct {
		name    string
		account *user.User
		delete  bool
	}{
		{name: "account removed"},
		{name: "account removed with pending deletion", delete: true},
		{name: "account renamed", account: &user.User{Name: "renamed", Uid: uid}},
		{name: "name reused with different UID", account: &user.User{Name: "removed", Uid: uid + 1}, delete: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			token := localToken{Version: 2, User: localTokenUser{Name: "removed", Uid: &uid, KillProcessesOnDispose: true, DeleteOnDispose: test.delete}}
			encoded, err := json.Marshal(token)
			require.NoError(t, err)
			stored := &localCoordinatorTestSession{flow: "test", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
			other := &localCoordinatorTestSession{flow: "other", id: session.MustNewId(), state: session.StateAuthorized, token: encoded}
			users := &localManagementTestUsers{account: test.account}
			coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{stored, other}}}
			repository := &LocalRepository{userRepository: users, coordinator: coordinator}
			clean := true
			env, err := repository.FindBySession(ctx, stored, &FindOpts{AutoCleanUpAllowed: &clean})
			require.NoError(t, err)
			require.True(t, env.(*local).accountMissing)
			_, err = env.Dispose(ctx)
			require.NoError(t, err)
			require.Zero(t, users.kills)
			require.Equal(t, encoded, stored.token)
			other.state = session.StateDisposed
			changed, err := env.Dispose(ctx)
			require.NoError(t, err)
			require.True(t, changed)
			require.Zero(t, users.kills)
			require.False(t, users.deleted)
			require.Equal(t, test.account, users.account)
			require.Empty(t, stored.token)
			_, err = repository.FindBySession(ctx, stored, &FindOpts{AutoCleanUpAllowed: &clean})
			require.ErrorIs(t, err, ErrNoSuchEnvironment)
		})
	}
}

func TestLocalUnixRetriesHomeCleanupAfterAccountDeletion(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(2_000_000_000)
	token := localToken{Version: 2, User: localTokenUser{
		Name: "removed", Uid: &uid, HomeDir: "/Users/removed",
		DeleteOnDispose: true, DeleteHomeTogetherWithUser: true,
	}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	stored := &localCoordinatorTestSession{flow: "test", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	users := &localManagementTestUsers{absentHomeFail: true}
	repository := &LocalRepository{
		userRepository: users,
		coordinator:    &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{stored}}},
	}
	clean := true
	env, err := repository.FindBySession(ctx, stored, &FindOpts{AutoCleanUpAllowed: &clean})
	require.NoError(t, err)
	require.True(t, env.(*local).accountMissing)

	changed, err := env.Dispose(ctx)
	require.False(t, changed)
	require.ErrorContains(t, err, "injected absent home cleanup failure")
	require.Equal(t, encoded, stored.token)
	require.Zero(t, users.absentHomes)

	users.absentHomeFail = false
	changed, err = env.Dispose(ctx)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 1, users.absentHomes)
	require.Empty(t, stored.token)
}

func TestLocalUnixSkipsIdentityChangedAfterTokenRestore(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(2_000_000_000)
	token := localToken{Version: 2, User: localTokenUser{Name: "original", Uid: &uid, DeleteOnDispose: true, KillProcessesOnDispose: true}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	stored := &localCoordinatorTestSession{flow: "test", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	users := &localManagementTestUsers{account: &user.User{Name: "original", Uid: uid}}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{stored}}}
	repository := &LocalRepository{userRepository: users, coordinator: coordinator}
	env, err := repository.FindBySession(ctx, stored, nil)
	require.NoError(t, err)
	users.account = &user.User{Name: "renamed", Uid: uid}

	changed, err := env.Dispose(ctx)
	require.NoError(t, err)
	require.True(t, changed)
	require.Zero(t, users.kills)
	require.False(t, users.deleted)
	require.Equal(t, "renamed", users.account.Name)
	require.Empty(t, stored.token)
}

func TestLocalUnixChangedIdentityDefersPendingDeletion(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(2_000_000_000)
	token := localToken{Version: 2, User: localTokenUser{Name: "original", Uid: &uid, DeleteOnDispose: true}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	stored := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	other := &localCoordinatorTestSession{flow: "second", id: session.MustNewId(), state: session.StateAuthorized, token: encoded}
	users := &localManagementTestUsers{account: &user.User{Name: "original", Uid: uid}}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{stored, other}}}
	repository := &LocalRepository{userRepository: users, coordinator: coordinator}
	env, err := repository.FindBySession(ctx, stored, nil)
	require.NoError(t, err)
	users.account = &user.User{Name: "renamed", Uid: uid}

	changed, err := env.Dispose(ctx)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, encoded, stored.token)
	other.state = session.StateDisposed
	changed, err = env.Dispose(ctx)
	require.NoError(t, err)
	require.True(t, changed)
	require.False(t, users.deleted)
	require.Zero(t, users.kills)
	require.Empty(t, stored.token)
}

func TestLocalUnixEnsureDoesNotOverwriteUnrestorableToken(t *testing.T) {
	ctx, cancel := newSshTestContext()
	defer cancel()
	stored := &sshTestStoredSession{id: session.MustNewId()}
	broken := []byte(`{"user":`)
	require.NoError(t, stored.SetEnvironmentToken(ctx, broken))
	repository := &LocalRepository{
		conf:           &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{LoginAllowed: template.BoolOf(true)}},
		userRepository: &localManagementTestUsers{},
	}
	req := &sshTestTask{context: ctx, authorization: &sshTestAuthorization{session: stored}}
	_, err := repository.Ensure(req)
	require.ErrorContains(t, err, "cannot decode environment token")
	unchanged, err := stored.EnvironmentToken(ctx)
	require.NoError(t, err)
	require.Equal(t, broken, unchanged)
}

func TestLocalUnixDeleteWaitsForLastSession(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	groupID := user.GroupId(4321)
	account := &user.User{Name: "local-user", Uid: uid, Groups: user.Groups{{Gid: groupID, Name: "bifroest-managed"}}}
	users := &localManagementTestUsers{account: account, group: &user.Group{Gid: groupID, Name: "bifroest-managed"}}
	token := localToken{Version: 2, User: localTokenUser{
		Name: "local-user", Uid: &uid, Managed: true,
		DeleteOnDispose: true,
	}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	first := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	second := &localCoordinatorTestSession{flow: "second", id: session.MustNewId(), state: session.StateAuthorized, token: encoded}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{first, second}}}
	repository := &LocalRepository{conf: &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{ManagedGroup: "bifroest-managed"}}, userRepository: users, coordinator: coordinator}

	removed, err := repository.new(account, first, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.False(t, removed)
	require.False(t, users.deleted)
	require.NotEmpty(t, first.token, "pending deletion must survive until the final session")

	second.state = session.StateDisposed
	removed, err = repository.new(account, second, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.True(t, removed)
	require.True(t, users.deleted)
	require.Empty(t, second.token)
}

func TestLocalUnixEarlierDeleteRequestSurvivesLastSessionsOptOut(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	groupID := user.GroupId(4321)
	account := &user.User{Name: "local-user", Uid: uid, Groups: user.Groups{{Gid: groupID, Name: "bifroest-managed"}}}
	users := &localManagementTestUsers{account: account, group: &user.Group{Gid: groupID, Name: "bifroest-managed"}}
	token := localToken{Version: 2, User: localTokenUser{
		Name: "local-user", Uid: &uid, Managed: true,
		DeleteOnDispose: true,
	}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	first := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	second := &localCoordinatorTestSession{flow: "second", id: session.MustNewId(), state: session.StateAuthorized, token: encoded}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{first, second}}}
	repository := &LocalRepository{conf: &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{ManagedGroup: "bifroest-managed"}}, userRepository: users, coordinator: coordinator}

	removed, err := repository.new(account, first, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.False(t, removed)
	second.state = session.StateDisposed
	token.User.DeleteOnDispose = false
	removed, err = repository.new(account, second, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.False(t, removed)
	require.Empty(t, second.token)
	require.False(t, users.deleted)

	token.User.DeleteOnDispose = true
	removed, err = repository.new(account, first, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.True(t, removed)
	require.True(t, users.deleted)
}

func TestLocalUnixDisposePreservesTokenWhileConnectionActive(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	account := &user.User{Name: "local-user", Uid: uid}
	users := &localManagementTestUsers{account: account}
	token := localToken{Version: 2, User: localTokenUser{Name: account.Name, Uid: &uid}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	stored := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), state: session.StateDisposed, token: encoded, connections: true}
	repository := &LocalRepository{userRepository: users, coordinator: &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{stored}}}}

	removed, err := repository.new(account, stored, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.False(t, removed)
	require.Equal(t, encoded, stored.token)
	stored.connections = false
	_, err = repository.new(account, stored, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.Empty(t, stored.token)
}

func TestLocalUnixDeletesUnmanagedAccountWhenExplicitlyRequested(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	account := &user.User{Name: "ordinary", Uid: uid}
	users := &localManagementTestUsers{account: account}
	token := localToken{Version: 2, User: localTokenUser{Name: account.Name, Uid: &uid, DeleteOnDispose: true}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	stored := &localCoordinatorTestSession{flow: "test", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{stored}}}
	repository := &LocalRepository{userRepository: users, coordinator: coordinator}

	removed, err := repository.new(account, stored, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.True(t, removed)
	require.True(t, users.deleted)
	require.Empty(t, stored.token)
}

func TestLocalUnixKillOnlyWaitsForLastSession(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	account := &user.User{Name: "ordinary", Uid: uid}
	users := &localManagementTestUsers{account: account}
	token := localToken{Version: 2, User: localTokenUser{Name: account.Name, Uid: &uid, KillProcessesOnDispose: true}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	first := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	second := &localCoordinatorTestSession{flow: "second", id: session.MustNewId(), state: session.StateAuthorized, token: encoded}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{first, second}}}
	repository := &LocalRepository{userRepository: users, coordinator: coordinator}

	changed, err := repository.new(account, first, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.False(t, changed)
	require.Zero(t, users.kills)
	require.False(t, users.deleted)
	require.NotNil(t, users.account)
	require.Equal(t, encoded, first.token, "deferred kill must keep its session token")
	require.NotEmpty(t, second.token)
	second.state = session.StateDisposed
	changed, err = repository.new(account, first, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, 1, users.kills)
	require.Empty(t, first.token)
	require.False(t, users.deleted, "kill-only must not delete the account")
}

func TestLocalUnixKillOnlyRequiresCoordinator(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	account := &user.User{Name: "ordinary", Uid: uid}
	users := &localManagementTestUsers{account: account}
	token := localToken{Version: 2, User: localTokenUser{Name: account.Name, Uid: &uid, KillProcessesOnDispose: true}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	stored := &localCoordinatorTestSession{flow: "test", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	repository := &LocalRepository{userRepository: users}

	_, err = repository.new(account, stored, false, &token).Dispose(ctx)
	require.ErrorContains(t, err, "without a session coordinator")
	require.Zero(t, users.kills)
	require.Equal(t, encoded, stored.token)
}

func TestLocalUnixCompletedKillOnlyDoesNotRequireCoordinator(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	account := &user.User{Name: "ordinary", Uid: uid}
	users := &localManagementTestUsers{account: account}
	token := localToken{Version: 2, User: localTokenUser{
		Name: account.Name, Uid: &uid, KillProcessesOnDispose: true, ProcessesKilledOnDispose: true,
	}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	stored := &localCoordinatorTestSession{flow: "test", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	repository := &LocalRepository{userRepository: users}

	_, err = repository.new(account, stored, false, &token).Dispose(ctx)
	require.NoError(t, err)
	require.Zero(t, users.kills)
	require.Empty(t, stored.token)
}

func TestLocalUnixDeferredDeletionDoesNotRepeatProcessKill(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	account := &user.User{Name: "ordinary", Uid: uid}
	users := &localManagementTestUsers{account: account}
	token := localToken{Version: 2, User: localTokenUser{
		Name: account.Name, Uid: &uid, DeleteOnDispose: true, KillProcessesOnDispose: true,
	}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	first := &localCoordinatorTestSession{flow: "first", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	second := &localCoordinatorTestSession{flow: "second", id: session.MustNewId(), state: session.StateAuthorized, token: encoded}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{first, second}}}
	repository := &LocalRepository{userRepository: users, coordinator: coordinator}
	env := repository.new(account, first, false, &token)
	staleToken := token
	staleEnv := repository.new(account, first, false, &staleToken)

	changed, err := env.Dispose(ctx)
	require.NoError(t, err)
	require.False(t, changed)
	require.Zero(t, users.kills)
	require.NotEmpty(t, first.token)
	var stored localToken
	require.NoError(t, json.Unmarshal(first.token, &stored))
	require.False(t, stored.User.ProcessesKilledOnDispose)
	_, err = env.Dispose(ctx)
	require.NoError(t, err)
	require.Zero(t, users.kills)
	_, err = staleEnv.Dispose(ctx)
	require.NoError(t, err)
	require.Zero(t, users.kills)
	second.state = session.StateDisposed
	_, err = env.Dispose(ctx)
	require.NoError(t, err)
	require.True(t, users.deleted)
	require.Equal(t, 1, users.kills)
}

func TestLocalUnixKillWaitsForActiveConnection(t *testing.T) {
	ctx := context.Background()
	uid := user.Id(1234)
	account := &user.User{Name: "ordinary", Uid: uid}
	users := &localManagementTestUsers{account: account}
	token := localToken{Version: 2, User: localTokenUser{Name: account.Name, Uid: &uid, KillProcessesOnDispose: true}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	stored := &localCoordinatorTestSession{flow: "test", id: session.MustNewId(), state: session.StateDisposed, connections: true, token: encoded}
	coordinator := &localAccountCoordinator{sessions: &localCoordinatorTestRepository{sessions: []session.Session{stored}}}
	repository := &LocalRepository{userRepository: users, coordinator: coordinator}
	env := repository.new(account, stored, false, &token)

	changed, err := env.Dispose(ctx)
	require.NoError(t, err)
	require.False(t, changed)
	require.Zero(t, users.kills)
	require.Equal(t, encoded, stored.token)
	stored.connections = false
	_, err = env.Dispose(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, users.kills)
	require.Empty(t, stored.token)
}

func TestLocalUnixRetainsPendingKillInDisposedFsSession(t *testing.T) {
	ctx := t.Context()
	conf := &configuration.SessionFs{}
	require.NoError(t, conf.SetDefaults())
	conf.Storage = t.TempDir()
	sessions, err := session.NewFsRepository(ctx, conf)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sessions.Close()) })
	first, err := sessions.Create(ctx, "first", sshTestRemote{}, []byte("authorization"))
	require.NoError(t, err)
	second, err := sessions.Create(ctx, "second", sshTestRemote{}, []byte("authorization"))
	require.NoError(t, err)
	uid := user.Id(1234)
	account := &user.User{Name: "ordinary", Uid: uid}
	users := &localManagementTestUsers{account: account}
	token := localToken{Version: 2, User: localTokenUser{
		Name: account.Name, Uid: &uid, DeleteOnDispose: true, KillProcessesOnDispose: true,
	}}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	require.NoError(t, first.SetEnvironmentToken(ctx, encoded))
	require.NoError(t, second.SetEnvironmentToken(ctx, encoded))
	coordinator := &localAccountCoordinator{sessions: sessions}
	repository := &LocalRepository{userRepository: users, coordinator: coordinator}
	env := repository.new(account, first, false, &token)
	_, err = first.Dispose(ctx)
	require.NoError(t, err)
	changed, err := env.Dispose(ctx)
	require.NoError(t, err)
	require.False(t, changed)
	require.Zero(t, users.kills)
	require.False(t, users.deleted)
	actual, err := first.EnvironmentToken(ctx)
	require.NoError(t, err)
	var pending localToken
	require.NoError(t, json.Unmarshal(actual, &pending))
	require.False(t, pending.User.ProcessesKilledOnDispose)
	_, err = env.Dispose(ctx)
	require.NoError(t, err)
	require.Zero(t, users.kills)
	_, err = second.Dispose(ctx)
	require.NoError(t, err)
	_, err = env.Dispose(ctx)
	require.NoError(t, err)
	require.True(t, users.deleted)
	require.Equal(t, 1, users.kills)
}
