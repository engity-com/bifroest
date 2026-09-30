//go:build windows

package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestLocalWindowsCandidateTemplateFields(t *testing.T) {
	unavailable, exists, err := (windowsLocalAccount{Name: "alice"}).GetField("managed")
	require.NoError(t, err)
	require.True(t, exists)
	require.Nil(t, unavailable)
	for _, managed := range []bool{false, true} {
		value, err := configuration.DefaultEnvironmentLocalKillProcessesOnDispose.Render(localTemplateContext{
			Request: localTemplateTestRequest{}, user: windowsLocalAccount{Name: "alice"}, managed: managed,
		})
		require.NoError(t, err)
		require.Equal(t, managed, value)
	}
	ctx := localTemplateContext{
		Request: localTemplateTestRequest{},
		user:    windowsLocalAccount{Name: "alice", SID: "S-1-5-21-1-2-3-1001"},
		managed: true,
	}
	value, err := template.MustNewString("{{ .user.name }}/{{ .user.uid }}/{{ .user.managed }}").Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "alice/S-1-5-21-1-2-3-1001/true", value)
	ctx.user = windowsLocalAccount{Name: "alice", Groups: []windowsLocalGroupRequirement{{Name: "builders", SID: "S-1-5-21-1-2-3-2001"}}}
	value, err = template.MustNewString("{{ (index .user.groups 0).name }}/{{ (index .user.groups 0).gid }}").Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "builders/S-1-5-21-1-2-3-2001", value)
	value, err = template.MustNewString("{{ .user.shell }}/{{ index .user.gids 0 }}").Render(ctx)
	require.NoError(t, err)
	require.Equal(t, configuration.DefaultShell+"/S-1-5-21-1-2-3-2001", value)
	value, err = template.MustNewString("{{ .user.displayName }}").Render(localTemplateContext{Request: localTemplateTestRequest{}, user: windowsLocalAccount{DisplayName: "Alice"}})
	require.NoError(t, err)
	require.Equal(t, "Alice", value)
}

func TestLocalWindowsDisposeFlags(t *testing.T) {
	repository := &LocalRepository{}
	account := windowsLocalAccount{Name: "alice", SID: "S-1-5-21-1-2-3-1001"}
	for _, version := range []uint8{0, 1, 2} {
		token := &localToken{Version: version, User: account, DeleteOnDispose: true, DeleteProfileOnDispose: true, KillProcessesOnDispose: true}
		env := repository.new(account, nil, false, token)
		require.Equal(t, version == 2, env.deleteOnDispose)
		require.Equal(t, version == 2, env.deleteProfileOnDispose)
		require.Equal(t, version == 2, env.killProcessesOnDispose)
		if version != 2 {
			disposed, err := env.dispose(context.Background())
			require.NoError(t, err)
			require.True(t, disposed)
		}
	}
	withoutMarker := repository.new(account, nil, false, &localToken{Version: 2, DeleteOnDispose: true})
	require.True(t, withoutMarker.deleteOnDispose)
	protected := windowsLocalAccount{Name: "renamed", SID: "S-1-5-21-1-2-3-500"}
	require.False(t, localWindowsCleanupAllowed(protected, false, true))
	require.True(t, localWindowsCleanupAllowed(protected, true, true))
	require.True(t, localWindowsCleanupAllowed(account, false, true))
	require.False(t, localWindowsCleanupAllowed(account, true, false))
	require.False(t, repository.new(protected, nil, false, &localToken{Version: 2, User: protected, Managed: true, DeleteOnDispose: true}).deleteOnDispose)
}

func TestLocalWindowsUnmanagedCleanupSnapshot(t *testing.T) {
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.DeleteOnDispose = template.MustNewBool("{{ not .user.managed }}")
	conf.DeleteHomeTogetherWithUser = template.BoolOf(true)
	conf.KillProcessesOnDispose = template.BoolOf(true)
	repository := &LocalRepository{conf: conf}
	account := windowsLocalAccount{Name: "alice", SID: "S-1-5-21-1-2-3-1001"}
	token, err := repository.newLocalToken(localTemplateTestRequest{}, account, false, false)
	require.NoError(t, err)
	require.False(t, token.Managed)
	require.True(t, token.DeleteOnDispose)
	require.True(t, token.DeleteProfileOnDispose)
	require.True(t, token.KillProcessesOnDispose)

	conf.DeleteOnDispose = template.BoolOf(false)
	conf.KillProcessesOnDispose = template.MustNewBool("{{ not .user.managed }}")
	token, err = repository.newLocalToken(localTemplateTestRequest{}, account, false, false)
	require.NoError(t, err)
	require.False(t, token.DeleteOnDispose)
	require.False(t, token.DeleteProfileOnDispose)
	require.True(t, token.KillProcessesOnDispose)
	restored := repository.new(account, nil, false, token)
	require.False(t, restored.deleteOnDispose)
	require.True(t, restored.killProcessesOnDispose)
}

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "local-windows-identity-child" {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(user.User.Sid.String())
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "local-windows-exit-one-child" {
		os.Exit(1)
	}
	if len(os.Args) == 2 && os.Args[1] == "local-windows-exit-255-child" {
		os.Exit(255)
	}
	if len(os.Args) == 2 && os.Args[1] == "local-windows-cleanup-child" {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(user.User.Sid.String())
		for {
			time.Sleep(time.Second)
		}
	}
	if len(os.Args) == 4 && os.Args[1] == "local-conpty-relay" {
		cols, colErr := strconv.Atoi(os.Args[2])
		rows, rowErr := strconv.Atoi(os.Args[3])
		if colErr != nil || rowErr != nil {
			fmt.Fprintln(os.Stderr, "invalid ConPTY test relay arguments")
			os.Exit(1)
		}
		argv, err := ReadLocalConPTYCommand(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		code, err := RunLocalConPTYRelay(cols, rows, argv)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := WriteLocalConPTYRelayExitStatus(os.Stderr, code); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func localWindowsTestAccount(t *testing.T) windowsLocalAccount {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	name, domain, kind, err := user.User.Sid.LookupAccount("")
	require.NoError(t, err)
	host, err := os.Hostname()
	require.NoError(t, err)
	if kind != windows.SidTypeUser || !strings.EqualFold(domain, host) {
		t.Skip("current process does not run as a local SAM user")
	}
	account, err := lookupLocalWindowsAccount(name)
	require.NoError(t, err)
	require.Equal(t, user.User.Sid.String(), account.SID)
	return account
}

func localWindowsTestRepository(t *testing.T, name string) *LocalRepository {
	t.Helper()
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.Name = template.MustNewString(name)
	repository, err := NewLocalRepository(context.Background(), "test", conf, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	return repository
}

func localWindowsTestRequest(t *testing.T, stored *sshTestStoredSession) *sshTestTask {
	t.Helper()
	ctx, cancel := newSshTestContext()
	t.Cleanup(cancel)
	return &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: stored},
		session:       newSshTestSession(ctx, "", nil),
		taskType:      TaskTypeShell,
	}
}

func setLocalWindowsTestToken(t *testing.T, stored *sshTestStoredSession, token localToken) {
	t.Helper()
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	require.NoError(t, stored.SetEnvironmentToken(context.Background(), encoded))
}

func TestLocalWindowsTokenRestoresWithoutProvisioning(t *testing.T) {
	account := localWindowsTestAccount(t)
	stored := &sshTestStoredSession{id: session.MustNewId()}
	repository := localWindowsTestRepository(t, account.Name)
	repository.conf.PortForwardingAllowed = template.BoolOf(false)
	req := localWindowsTestRequest(t, stored)

	created, err := repository.Ensure(req)
	require.NoError(t, err)
	require.Equal(t, account.SID, created.(*local).user.SID)
	require.Equal(t, account.Name, created.(*local).user.Name)
	require.Equal(t, int32(1), stored.environmentTokenWrites.Load())
	encoded, err := stored.EnvironmentToken(context.Background())
	require.NoError(t, err)
	var token localToken
	require.NoError(t, json.Unmarshal(encoded, &token))
	require.Equal(t, account.SID, token.User.SID)
	require.Equal(t, account.Name, token.User.Name)
	require.Equal(t, uint8(2), token.Version)
	require.False(t, token.DeleteOnDispose)
	require.False(t, token.PortForwardingAllowed)

	restarted := localWindowsTestRepository(t, strings.ToUpper(account.Name))
	restored, err := restarted.FindBySession(context.Background(), stored, nil)
	require.NoError(t, err)
	require.Equal(t, account.SID, restored.(*local).user.SID)
	require.Equal(t, account.Name, restored.(*local).user.Name)
	allowed, err := restored.IsPortForwardingAllowed(bnet.HostPort{})
	require.NoError(t, err)
	require.False(t, allowed)
	compatible, err := restarted.IsSessionCompatible(context.Background(), stored)
	require.NoError(t, err)
	require.True(t, compatible)
	compatible, err = restarted.IsSessionCompatibleWith(req, stored)
	require.NoError(t, err)
	require.True(t, compatible)
	again, err := restarted.Ensure(req)
	require.NoError(t, err)
	require.Equal(t, account.SID, again.(*local).user.SID)
	require.Equal(t, account.Name, again.(*local).user.Name)
	require.Equal(t, int32(1), stored.environmentTokenWrites.Load())

	disposed, err := restored.Dispose(context.Background())
	require.NoError(t, err)
	require.True(t, disposed)
	encoded, err = stored.EnvironmentToken(context.Background())
	require.NoError(t, err)
	require.Empty(t, encoded)
	require.NoError(t, restarted.Cleanup(context.Background(), nil))
	remaining, err := lookupLocalWindowsAccount(account.Name)
	require.NoError(t, err)
	require.Equal(t, account, remaining)
}

func TestLocalWindowsAcceptsUIDOnlyAndRejectsMismatchedIdentity(t *testing.T) {
	account := localWindowsTestAccount(t)
	repository := localWindowsTestRepository(t, account.Name)
	repository.conf.Name = template.String{}
	repository.conf.Uid = template.MustNewString(account.SID)
	stored := &sshTestStoredSession{id: session.MustNewId()}
	created, err := repository.Ensure(localWindowsTestRequest(t, stored))
	require.NoError(t, err)
	require.Equal(t, account.SID, created.(*local).user.SID)

	repository.conf.Name = template.MustNewString(account.Name)
	repository.conf.Uid = template.MustNewString("S-1-5-21-1-2-3-1001")
	if account.SID == "S-1-5-21-1-2-3-1001" {
		repository.conf.Uid = template.MustNewString("S-1-5-21-1-2-3-1002")
	}
	_, err = repository.Ensure(localWindowsTestRequest(t, &sshTestStoredSession{id: session.MustNewId()}))
	require.ErrorContains(t, err, "does not match UID")
}

func TestLocalWindowsRejectsLegacyMissingAndChangedIdentity(t *testing.T) {
	account := localWindowsTestAccount(t)
	repository := localWindowsTestRepository(t, account.Name)
	const missingName = "BifroestNoSuchUser_987654321"
	_, err := lookupLocalWindowsAccount(missingName)
	if err == nil {
		t.Skip("test account name unexpectedly exists")
	}
	changedSID := "S-1-5-21-1-2-3-1000"
	if account.SID == changedSID {
		changedSID = "S-1-5-21-1-2-3-1001"
	}
	for _, test := range []struct {
		name string
		user windowsLocalAccount
	}{
		{name: "legacy name without SID", user: windowsLocalAccount{Name: account.Name}},
		{name: "missing user", user: windowsLocalAccount{Name: missingName, SID: changedSID}},
		{name: "changed SID", user: windowsLocalAccount{Name: account.Name, SID: changedSID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stored := &sshTestStoredSession{id: session.MustNewId()}
			setLocalWindowsTestToken(t, stored, localToken{User: test.user})
			initial, err := stored.EnvironmentToken(context.Background())
			require.NoError(t, err)
			_, err = repository.FindBySession(context.Background(), stored, nil)
			require.ErrorContains(t, err, "changed SID")
			compatible, err := repository.IsSessionCompatible(context.Background(), stored)
			require.NoError(t, err)
			require.False(t, compatible)
			compatible, err = repository.IsSessionCompatibleWith(localWindowsTestRequest(t, stored), stored)
			require.NoError(t, err)
			require.False(t, compatible)
			_, err = repository.Ensure(localWindowsTestRequest(t, stored))
			require.Error(t, err)
			unchanged, err := stored.EnvironmentToken(context.Background())
			require.NoError(t, err)
			require.Equal(t, initial, unchanged)

			clean := true
			_, err = repository.FindBySession(context.Background(), stored, &FindOpts{AutoCleanUpAllowed: &clean})
			require.ErrorIs(t, err, ErrNoSuchEnvironment)
			cleared, err := stored.EnvironmentToken(context.Background())
			require.NoError(t, err)
			require.Empty(t, cleared)
			require.Equal(t, int32(2), stored.environmentTokenWrites.Load())
		})
	}
	remaining, err := lookupLocalWindowsAccount(account.Name)
	require.NoError(t, err)
	require.Equal(t, account, remaining)
}

func TestLocalWindowsRejectsInvalidNamesBeforeAccountLookup(t *testing.T) {
	for _, name := range []string{"", ".", "..", " user", "user ", "user.", `host\user`, "user@domain", "user/name", "user:role", "user\nname", "user\x00name", string([]byte{0xff})} {
		t.Run(name, func(t *testing.T) {
			require.False(t, validLocalSAMName(name))
			_, err := lookupLocalWindowsAccount(name)
			require.ErrorContains(t, err, "invalid local SAM account name")
			stored := &sshTestStoredSession{id: session.MustNewId()}
			_, err = localWindowsTestRepository(t, name).Ensure(localWindowsTestRequest(t, stored))
			if name == "" {
				require.ErrorContains(t, err, "name or UID is required")
			} else {
				require.ErrorContains(t, err, "invalid local SAM account name")
			}
			encoded, err := stored.EnvironmentToken(context.Background())
			require.NoError(t, err)
			require.Empty(t, encoded)
		})
	}
}

func TestLocalWindowsRejectsMissingConfiguredUser(t *testing.T) {
	const name = "BifroestNoSuchUser_987654321"
	if _, err := lookupLocalWindowsAccount(name); err == nil {
		t.Skip("test account name unexpectedly exists")
	}
	stored := &sshTestStoredSession{id: session.MustNewId()}
	_, err := localWindowsTestRepository(t, name).Ensure(localWindowsTestRequest(t, stored))
	require.ErrorContains(t, err, "local Windows account not found")
	encoded, err := stored.EnvironmentToken(context.Background())
	require.NoError(t, err)
	require.Empty(t, encoded)
}

func TestLocalWindowsKeepsMissingAccountTokenForProfileCleanup(t *testing.T) {
	const name = "BifroestNoSuchUser_987654321"
	account := windowsLocalAccount{Name: name, SID: "S-1-5-21-1-2-3-1001"}
	if _, err := lookupLocalWindowsAccount(name); err == nil {
		t.Skip("test account name unexpectedly exists")
	}
	stored := &sshTestStoredSession{id: session.MustNewId()}
	setLocalWindowsTestToken(t, stored, localToken{
		Version: 2, User: account, DeleteOnDispose: true, DeleteProfileOnDispose: true,
	})
	repository := localWindowsTestRepository(t, name)
	_, err := repository.FindBySession(context.Background(), stored, nil)
	require.ErrorContains(t, err, "changed SID")
	clean := true
	pending, err := repository.FindBySession(context.Background(), stored, &FindOpts{AutoCleanUpAllowed: &clean})
	require.NoError(t, err)
	require.True(t, pending.(*local).accountMissing)
	require.True(t, pending.(*local).deleteOnDispose)
	require.True(t, pending.(*local).deleteProfileOnDispose)
	encoded, err := stored.EnvironmentToken(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, encoded, "profile cleanup must remain retryable")
}

func TestLocalWindowsKeepsMissingAccountTokenForProcessCleanup(t *testing.T) {
	const name = "BifroestNoSuchUser_987654321"
	if _, err := lookupLocalWindowsAccount(name); err == nil {
		t.Skip("test account name unexpectedly exists")
	}
	stored := &sshTestStoredSession{id: session.MustNewId()}
	setLocalWindowsTestToken(t, stored, localToken{
		Version: 2, User: windowsLocalAccount{Name: name, SID: "S-1-5-21-1-2-3-1001"}, KillProcessesOnDispose: true,
	})
	repository := localWindowsTestRepository(t, name)
	clean := true
	pending, err := repository.FindBySession(context.Background(), stored, &FindOpts{AutoCleanUpAllowed: &clean})
	require.NoError(t, err)
	require.True(t, pending.(*local).accountMissing)
	require.True(t, pending.(*local).killProcessesOnDispose)
	require.False(t, pending.(*local).deleteOnDispose)
	encoded, err := stored.EnvironmentToken(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, encoded)
}

func TestLocalWindowsCompletedKillOnlyDoesNotRequireCoordinator(t *testing.T) {
	account := windowsLocalAccount{Name: "BifroestMissingAccount_987654321", SID: "S-1-5-21-1-2-3-1001"}
	token := localToken{Version: 2, User: account, KillProcessesOnDispose: true, ProcessesKilledOnDispose: true}
	encoded, err := json.Marshal(token)
	require.NoError(t, err)
	stored := &localCoordinatorTestSession{flow: "test", id: session.MustNewId(), state: session.StateDisposed, token: encoded}
	env := (&LocalRepository{}).new(account, stored, false, &token)
	env.accountMissing = true

	_, err = env.Dispose(context.Background())
	require.NoError(t, err)
	require.Empty(t, stored.token)
}

func TestLocalWindowsS4ULogonAsUser(t *testing.T) {
	name := os.Getenv("BIFROEST_TEST_LOCAL_WINDOWS_USER")
	if name == "" {
		t.Skip("set BIFROEST_TEST_LOCAL_WINDOWS_USER explicitly to run privileged S4U integration")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err)
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	if !self.User.Sid.Equals(system) {
		t.Skip("S4U integration requires a LocalSystem process")
	}
	account, err := lookupLocalWindowsAccount(name)
	require.NoError(t, err)
	token, release, err := account.logon()
	require.NoError(t, err)
	defer release()
	profile, err := token.GetUserProfileDirectory()
	require.NoError(t, err)
	environment, err := token.Environ(false)
	require.NoError(t, err)
	cmd := exec.Command(os.Args[0], "local-windows-identity-child")
	cmd.Dir = profile
	cmd.Env = environment
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.Contains(t, strings.ToUpper(string(output)), strings.ToUpper(account.SID))
}

func TestLocalWindowsRunAsUser(t *testing.T) {
	name := os.Getenv("BIFROEST_TEST_LOCAL_WINDOWS_USER")
	if name == "" {
		t.Skip("set BIFROEST_TEST_LOCAL_WINDOWS_USER explicitly to run privileged local environment integration")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err)
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	if !self.User.Sid.Equals(system) {
		t.Skip("local environment integration requires a LocalSystem process")
	}
	account, err := lookupLocalWindowsAccount(name)
	require.NoError(t, err)
	repository := localWindowsTestRepository(t, account.Name)
	exe, err := os.Executable()
	require.NoError(t, err)
	repository.conf.ExecCommandPrefix = template.MustNewStrings(exe)
	stored := &sshTestStoredSession{id: session.MustNewId()}
	req := localWindowsTestRequest(t, stored)
	req.session = newSshTestSession(req.context, "local-windows-identity-child", nil)
	env, err := repository.Ensure(req)
	require.NoError(t, err)
	code, err := env.Run(req)
	require.NoError(t, err)
	require.Zero(t, code)
	require.Contains(t, strings.ToUpper(req.session.(*sshTestSession).stdout.String()), strings.ToUpper(account.SID))
}

type localWindowsPtySession struct {
	*sshTestSession
	input   *io.PipeReader
	changes chan essh.Window
}

func (this *localWindowsPtySession) Read(p []byte) (int, error) { return this.input.Read(p) }
func (this *localWindowsPtySession) Close() error               { return this.input.Close() }
func (this *localWindowsPtySession) Pty() (essh.Pty, <-chan essh.Window, bool) {
	return essh.Pty{Term: "xterm-256color", Window: essh.Window{Width: 80, Height: 25}}, this.changes, true
}

func TestLocalWindowsConPTYAsUser(t *testing.T) {
	name := os.Getenv("BIFROEST_TEST_LOCAL_WINDOWS_USER")
	if name == "" {
		t.Skip("set BIFROEST_TEST_LOCAL_WINDOWS_USER explicitly to run privileged ConPTY integration")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err)
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	if !self.User.Sid.Equals(system) {
		t.Skip("ConPTY integration requires a LocalSystem process")
	}
	account, err := lookupLocalWindowsAccount(name)
	require.NoError(t, err)
	repository := localWindowsTestRepository(t, account.Name)
	exe, err := os.Executable()
	require.NoError(t, err)
	repository.conf.ExecCommandPrefix = template.MustNewStrings(exe)
	stored := &sshTestStoredSession{id: session.MustNewId()}
	req := localWindowsTestRequest(t, stored)
	reader, writer := io.Pipe()
	defer writer.Close()
	pty := &localWindowsPtySession{
		sshTestSession: newSshTestSession(req.context, "local-windows-identity-child", nil),
		input:          reader,
		changes:        make(chan essh.Window, 1),
	}
	pty.changes <- essh.Window{Width: 100, Height: 30}
	req.session = pty
	env, err := repository.Ensure(req)
	require.NoError(t, err)
	supported, err := repository.DoesSupportPty(req, essh.Pty{Window: essh.Window{Width: 80, Height: 25}})
	require.NoError(t, err)
	if !supported {
		t.Skip("ConPTY unavailable on this Windows version")
	}
	type outcome struct {
		code int
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		code, err := env.Run(req)
		done <- outcome{code, err}
	}()
	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Zero(t, result.code)
		require.Contains(t, strings.ToUpper(pty.stdout.String()), strings.ToUpper(account.SID))
	case <-time.After(20 * time.Second):
		_ = pty.Close()
		require.FailNow(t, "ConPTY did not finish within 20 seconds")
	}
}

func TestLocalWindowsConPTYDistinguishesShellExitFromRelayFailure(t *testing.T) {
	name := os.Getenv("BIFROEST_TEST_LOCAL_WINDOWS_USER")
	if name == "" {
		t.Skip("set BIFROEST_TEST_LOCAL_WINDOWS_USER explicitly to run privileged ConPTY integration")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	require.NoError(t, err)
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	if !self.User.Sid.Equals(system) {
		t.Skip("ConPTY integration requires a LocalSystem process")
	}
	if err := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find(); err != nil {
		t.Skip("ConPTY is not available on this Windows version")
	}
	account, err := lookupLocalWindowsAccount(name)
	require.NoError(t, err)
	exe, err := os.Executable()
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		command string
		code    int
		fail    bool
	}{
		{name: "shell exit 1", command: "local-windows-exit-one-child", code: 1},
		{name: "shell exit 255", command: "local-windows-exit-255-child", code: 255},
		{name: "relay failure", command: "invalid\x00argument", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repository := localWindowsTestRepository(t, account.Name)
			repository.conf.ExecCommandPrefix = template.MustNewStrings(exe)
			stored := &sshTestStoredSession{id: session.MustNewId()}
			req := localWindowsTestRequest(t, stored)
			reader, writer := io.Pipe()
			defer writer.Close()
			req.session = &localWindowsPtySession{
				sshTestSession: newSshTestSession(req.context, tc.command, nil),
				input:          reader,
				changes:        make(chan essh.Window),
			}
			env, err := repository.Ensure(req)
			require.NoError(t, err)
			type outcome struct {
				code int
				err  error
			}
			done := make(chan outcome, 1)
			go func() {
				code, err := env.Run(req)
				done <- outcome{code, err}
			}()
			select {
			case result := <-done:
				output := req.session.(*localWindowsPtySession).stdout.String()
				require.NotContains(t, output, "BIFROEST-CONPTY/1 EXIT")
				require.NotContains(t, output, "shell argument contains NUL")
				if tc.fail {
					require.ErrorContains(t, result.err, "relay exited")
					require.ErrorContains(t, result.err, "shell argument contains NUL")
					require.Equal(t, -1, result.code)
				} else {
					require.NoError(t, result.err)
					require.Equal(t, tc.code, result.code)
				}
			case <-time.After(20 * time.Second):
				_ = req.session.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("ConPTY relay did not stop after SSH session close")
				}
				t.Fatal("ConPTY relay did not finish within 20 seconds")
			}
		})
	}
}
