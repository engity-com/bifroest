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
		os.Exit(code)
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
	require.Equal(t, account, created.(*local).user)
	require.Equal(t, int32(1), stored.environmentTokenWrites.Load())
	encoded, err := stored.EnvironmentToken(context.Background())
	require.NoError(t, err)
	var token localToken
	require.NoError(t, json.Unmarshal(encoded, &token))
	require.Equal(t, account, token.User)
	require.False(t, token.PortForwardingAllowed)

	restarted := localWindowsTestRepository(t, strings.ToUpper(account.Name))
	restored, err := restarted.FindBySession(context.Background(), stored, nil)
	require.NoError(t, err)
	require.Equal(t, account, restored.(*local).user)
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
	require.Equal(t, account, again.(*local).user)
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
			require.ErrorContains(t, err, "invalid local SAM account name")
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
