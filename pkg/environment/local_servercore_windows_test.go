//go:build windows && nanoserver_integration

package environment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

const serverCoreContainerMarker = `C:\smoke\servercore-container.marker`

func TestLocalServerCoreAccountFixtureAPIs(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_SERVERCORE_IN_CONTAINER") != "1" {
		t.Skip("only run inside the Server Core local account integration image")
	}
	require.NoError(t, windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserAdd").Find())
}

type serverCoreLifecycleSession struct {
	*sshTestStoredSession
	state session.State
}

func (s *serverCoreLifecycleSession) Info(context.Context) (session.Info, error) {
	return localCoordinatorTestInfo{state: s.state}, nil
}

func (*serverCoreLifecycleSession) HasActiveConnections() bool { return false }

func TestLocalServerCoreProviderAccountLifecycle(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_SERVERCORE_IN_CONTAINER") != "1" {
		t.Skip("only run inside the disposable Server Core integration container")
	}
	marker, err := os.ReadFile(serverCoreContainerMarker)
	require.NoError(t, err, "Server Core container marker is missing")
	require.Equal(t, "bifroest-servercore-integration", strings.TrimSpace(string(marker)))
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	require.NotNil(t, self)
	require.NotNil(t, self.User.Sid)
	sid := self.User.Sid.String()
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err)
	require.True(t, sid == "S-1-5-93-2-1" || self.User.Sid.Equals(system), "requires ContainerAdministrator or container LocalSystem, got %s", sid)

	var nonce [8]byte
	_, err = rand.Read(nonce[:])
	require.NoError(t, err)
	suffix := hex.EncodeToString(nonce[:])
	name, group := "bsc"+suffix, "bsg"+suffix
	extraGroup := "bsg2" + suffix
	_, err = lookupLocalWindowsAccount(name)
	require.ErrorIs(t, err, errLocalWindowsAccountNotFound)
	_, err = localSAMGroupSID(group)
	require.Error(t, err, "random managed group already exists")

	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.Name = template.MustNewString(name)
	conf.ManagedGroup = group
	conf.CreateIfAbsent = template.BoolOf(true)
	conf.UpdateIfDifferent = template.BoolOf(true)
	conf.DisplayName = template.MustNewString("Server Core initial")
	conf.Groups = configuration.WindowsUserGroupRequirementTemplates{{Name: template.MustNewString(extraGroup)}}
	if self.User.Sid.Equals(system) {
		source := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(source, "welcome.txt"), []byte("Server Core template"), 0600))
		conf.Skel = template.MustNewString(source)
	}
	conf.DeleteOnDispose = template.BoolOf(true)
	conf.DeleteHomeTogetherWithUser = template.BoolOf(self.User.Sid.Equals(system))
	conf.KillProcessesOnDispose = template.BoolOf(false)

	first := &serverCoreLifecycleSession{sshTestStoredSession: &sshTestStoredSession{id: session.MustNewId()}, state: session.StateAuthorized}
	second := &serverCoreLifecycleSession{sshTestStoredSession: &sshTestStoredSession{id: session.MustNewId()}, state: session.StateAuthorized}
	sessions := &localCoordinatorTestRepository{sessions: []session.Session{first, second}}
	ctx := context.WithValue(context.Background(), repositoryDependenciesContextKey{}, repositoryDependencies{
		localAccounts: &localAccountCoordinator{sessions: sessions},
	})
	repository, err := NewLocalRepository(ctx, "test", conf, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	request := func(stored *serverCoreLifecycleSession) *sshTestTask {
		req := localWindowsTestRequest(t, stored.sshTestStoredSession)
		req.authorization = &sshTestAuthorization{session: stored}
		return req
	}

	createdSID := ""
	t.Cleanup(func() {
		if createdSID != "" {
			if account, err := lookupLocalWindowsAccount(name); err == nil && account.SID == createdSID {
				if err := DeleteLocalWindowsAccount(name, createdSID); err != nil {
					t.Logf("best-effort disposable container account cleanup: %v", err)
				}
			}
		}
	})
	initial, err := repository.Ensure(request(first))
	require.NoError(t, err)
	createdSID = initial.(*local).user.SID
	require.NotEmpty(t, createdSID)
	account, err := lookupLocalWindowsAccount(name)
	require.NoError(t, err)
	require.Equal(t, createdSID, account.SID)
	member, err := IsLocalWindowsAccountInGroup(name, createdSID, group)
	require.NoError(t, err)
	require.True(t, member)
	extraSID, err := localSAMGroupSID(extraGroup)
	require.NoError(t, err)
	extraMember, err := windowsLocalGroupHasMember(extraGroup, createdSID)
	require.NoError(t, err)
	require.True(t, extraMember)
	display, err := localSAMDisplayName(name)
	require.NoError(t, err)
	require.Equal(t, "Server Core initial", display)

	stored, err := first.EnvironmentToken(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, stored)
	var token localToken
	require.NoError(t, json.Unmarshal(stored, &token))
	require.Equal(t, uint8(2), token.Version)
	require.Equal(t, createdSID, token.User.SID)
	require.Equal(t, name, token.User.Name)
	require.True(t, token.Managed)
	require.Equal(t, group, token.ManagedGroup)
	require.NotEmpty(t, token.ManagedGroupSID)
	require.True(t, token.DeleteOnDispose)
	require.Equal(t, self.User.Sid.Equals(system), token.DeleteProfileOnDispose)
	require.False(t, token.KillProcessesOnDispose)

	var profileDir string
	if self.User.Sid.Equals(system) {
		loggedOn, release, err := account.logon()
		require.NoError(t, err, "S4U logon of newly provisioned container account")
		loggedOnUser, lookupErr := loggedOn.GetTokenUser()
		profile, profileErr := loggedOn.GetUserProfileDirectory()
		profileDir = profile
		if profileErr == nil {
			var copied []byte
			copied, profileErr = os.ReadFile(filepath.Join(profile, "welcome.txt"))
			if profileErr == nil {
				require.Equal(t, "Server Core template", string(copied))
			}
		}
		release() // Unload the newly created profile before any account disposal.
		require.NoError(t, lookupErr)
		require.NoError(t, profileErr)
		require.Equal(t, createdSID, loggedOnUser.User.Sid.String())
		fromTemplate, templateErr := template.MustNewString("{{ .user.homeDir }}").Render(localTemplateContext{
			Request: localTemplateTestRequest{}, user: account,
		})
		require.NoError(t, templateErr)
		require.Equal(t, profileDir, fromTemplate)
	} else {
		t.Log("ContainerAdministrator: S4U requires LocalSystem; only SAM and provider token lifecycle verified")
	}

	conf.DisplayName = template.MustNewString("Server Core updated")
	conf.Groups = configuration.WindowsUserGroupRequirementTemplates{{Gid: template.MustNewString(extraSID)}}
	other, err := repository.Ensure(request(second))
	require.NoError(t, err)
	require.Equal(t, createdSID, other.(*local).user.SID)
	member, err = IsLocalWindowsAccountInGroup(name, createdSID, group)
	require.NoError(t, err)
	require.True(t, member)
	display, err = localSAMDisplayName(name)
	require.NoError(t, err)
	require.Equal(t, "Server Core updated", display)
	secondToken, err := second.EnvironmentToken(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, secondToken)
	require.NoError(t, json.Unmarshal(secondToken, &token))
	require.Equal(t, createdSID, token.User.SID)
	require.True(t, token.DeleteOnDispose)
	require.Equal(t, self.User.Sid.Equals(system), token.DeleteProfileOnDispose)
	require.False(t, token.KillProcessesOnDispose)
	restored, err := repository.FindBySession(ctx, second, nil)
	require.NoError(t, err)
	require.Equal(t, createdSID, restored.(*local).user.SID)

	disposed, err := initial.Dispose(ctx)
	require.NoError(t, err)
	require.False(t, disposed, "other session still uses the account")
	_, err = lookupLocalWindowsAccount(name)
	require.NoError(t, err)
	firstToken, err := first.EnvironmentToken(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, firstToken, "deferred disposal must preserve its token")
	first.state = session.StateDisposed
	disposed, err = other.Dispose(ctx)
	require.NoError(t, err)
	require.True(t, disposed)
	_, err = lookupLocalWindowsAccount(name)
	require.True(t, errors.Is(err, errLocalWindowsAccountNotFound), "account must be deleted after final session: %v", err)
	secondToken, err = second.EnvironmentToken(ctx)
	require.NoError(t, err)
	require.Empty(t, secondToken)
	if profileDir != "" {
		_, err = os.Stat(profileDir)
		require.True(t, os.IsNotExist(err), "deleted account profile must be removed: %v", err)
	}
}

func TestLocalServerCoreFailedSkelDisablesNewAccount(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_SERVERCORE_IN_CONTAINER") != "1" {
		t.Skip("only run inside the disposable Server Core integration container")
	}
	marker, err := os.ReadFile(serverCoreContainerMarker)
	require.NoError(t, err)
	require.Equal(t, "bifroest-servercore-integration", strings.TrimSpace(string(marker)))
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err)
	if !self.User.Sid.Equals(system) {
		t.Skip("profile bootstrap requires the container's LocalSystem service")
	}
	var nonce [8]byte
	_, err = rand.Read(nonce[:])
	require.NoError(t, err)
	suffix := hex.EncodeToString(nonce[:])
	name, group := "bpc"+suffix, "bpg"+suffix
	sk := t.TempDir()
	// LoadUserProfile creates NTUSER.DAT before the copy; it must not be overwritten.
	require.NoError(t, os.WriteFile(filepath.Join(sk, "NTUSER.DAT"), []byte("conflict"), 0600))
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.Name = template.MustNewString(name)
	conf.ManagedGroup = group
	conf.CreateIfAbsent = template.BoolOf(true)
	conf.Skel = template.MustNewString(sk)
	repo, err := NewLocalRepository(context.Background(), "test", conf, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repo.Close()) })
	stored := &sshTestStoredSession{id: session.MustNewId()}
	_, err = repo.Ensure(localWindowsTestRequest(t, stored))
	require.ErrorContains(t, err, "profile")
	account, err := lookupLocalWindowsAccount(name)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := DeleteLocalWindowsAccount(name, account.SID); err != nil {
			t.Logf("best-effort container account cleanup: %v", err)
		}
	})
	disabled, err := localWindowsAccountDisabled(name, account.SID)
	require.NoError(t, err)
	require.True(t, disabled)
	_, err = repo.Ensure(localWindowsTestRequest(t, &sshTestStoredSession{id: session.MustNewId()}))
	require.ErrorContains(t, err, "disabled")
}
