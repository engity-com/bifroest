//go:build unix

package environment

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalUnixCandidateTemplateFields(t *testing.T) {
	ctx := localTemplateContext{
		Request: localTemplateTestRequest{},
		user:    &user.User{Name: "alice", Uid: 42},
		managed: true,
	}
	value, err := template.MustNewString("{{ .user.name }}/{{ .user.uid }}/{{ .user.managed }}").Render(ctx)
	require.NoError(t, err)
	require.Equal(t, "alice/42/true", value)
}

func TestLocalEnvironmentProtectsUserIdentityVariables(t *testing.T) {
	ctx, cancel := newSshTestContext()
	defer cancel()
	storedSession := &sshTestStoredSession{id: session.MustNewId()}
	auth := &sshTestAuthorization{
		session: storedSession,
		environment: sys.EnvVars{
			"HOME":    "/forged/authorization",
			"USER":    "forged-authorization",
			"LOGNAME": "forged-authorization",
			"SHELL":   "/forged/authorization-shell",
		},
	}
	sshSession := newSshTestSession(ctx, "true", nil)
	sshSession.environment = []string{
		"HOME=/forged/client",
		"USER=forged-client",
		"LOGNAME=forged-client",
		"SHELL=/forged/client-shell",
	}
	task := &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: auth,
		session:       sshSession,
		taskType:      TaskTypeShell,
		environmentVariables: configuration.EnvironmentVariables{
			"HOME":    template.MustNewString("/forged/task"),
			"USER":    template.MustNewString("forged-task"),
			"LOGNAME": template.MustNewString("forged-task"),
			"SHELL":   template.MustNewString("/forged/task-shell"),
		},
	}
	local := &local{
		repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}},
		user: &user.User{
			Name:    "trusted-user",
			Uid:     1000,
			Group:   user.Group{Gid: 1001},
			Groups:  user.Groups{{Gid: 1002}},
			HomeDir: "/trusted/home",
			Shell:   "/trusted/shell",
		},
		getEffectiveUserID: func() int { return 0 },
	}
	cmd, environment, release, err := local.createCmdAndEnv(task)
	require.NoError(t, err)
	defer release()
	require.NotNil(t, cmd.SysProcAttr)
	require.NotNil(t, cmd.SysProcAttr.Credential)
	require.Equal(t, uint32(1000), cmd.SysProcAttr.Credential.Uid)
	require.Equal(t, uint32(1001), cmd.SysProcAttr.Credential.Gid)
	require.Equal(t, []uint32{1002}, cmd.SysProcAttr.Credential.Groups)
	require.False(t, cmd.SysProcAttr.Credential.NoSetGroups)
	require.Equal(t, "/trusted/home", cmd.Dir)
	require.Equal(t, "/trusted/home", (*environment)["HOME"])
	require.Equal(t, "trusted-user", (*environment)["USER"])
	require.Equal(t, "trusted-user", (*environment)["LOGNAME"])
	require.Equal(t, "/trusted/shell", (*environment)["SHELL"])
}

func TestLocalUnixShellCommandsDefaultToAccountShell(t *testing.T) {
	ctx, cancel := newSshTestContext()
	defer cancel()
	env := &local{repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}}, user: &user.User{Shell: "/bin/account-shell"}}
	for _, test := range []struct {
		raw  string
		args []string
	}{
		{args: []string{"-account-shell"}},
		{raw: "whoami", args: []string{"account-shell", "-c", "whoami"}},
	} {
		command := &exec.Cmd{}
		task := &sshTestTask{context: ctx, session: newSshTestSession(ctx, test.raw, nil)}
		require.NoError(t, env.configureShellCmd(task, command))
		require.Equal(t, "/bin/account-shell", command.Path)
		require.Equal(t, test.args, command.Args)
	}
}

func TestLocalUnixExplicitShellCommands(t *testing.T) {
	ctx, cancel := newSshTestContext()
	defer cancel()
	bin, err := os.Executable()
	require.NoError(t, err)
	conf := &configuration.EnvironmentLocal{}
	conf.ShellCommand = template.MustNewStrings(bin, "--interactive")
	conf.ExecCommandPrefix = template.MustNewStrings(bin, "--command", "{{.targetUser}}")
	env := &local{repository: &LocalRepository{conf: conf}, user: &user.User{Shell: "/bin/account-shell"}}
	for _, test := range []struct {
		raw  string
		args []string
	}{
		{args: []string{bin, "--interactive"}},
		{raw: "whoami", args: []string{bin, "--command", "alice", "whoami"}},
	} {
		command := &exec.Cmd{}
		task := &sshTestTask{context: ctx, targetUser: "alice", session: newSshTestSession(ctx, test.raw, nil)}
		require.NoError(t, env.configureShellCmd(task, command))
		require.Equal(t, bin, command.Path)
		require.Equal(t, test.args, command.Args)
	}
	conf.ShellCommand = template.MustNewStrings("")
	require.ErrorContains(t, env.configureShellCmd(&sshTestTask{context: ctx, session: newSshTestSession(ctx, "", nil)}, &exec.Cmd{}), "requires an executable")
}

func TestLocalUnixDirectoryOverride(t *testing.T) {
	ctx, cancel := newSshTestContext()
	defer cancel()
	dir := t.TempDir()
	conf := &configuration.EnvironmentLocal{}
	conf.Directory = template.MustNewString("{{.targetUser}}")
	env := &local{repository: &LocalRepository{conf: conf}, user: &user.User{Name: "alice", HomeDir: "/home/alice"}}
	task := &sshTestTask{
		context:       ctx,
		targetUser:    dir,
		authorization: &sshTestAuthorization{session: &sshTestStoredSession{id: session.MustNewId()}},
		session:       newSshTestSession(ctx, "", nil),
	}
	command, vars, release, err := env.createCmdAndEnv(task)
	require.NoError(t, err)
	defer release()
	require.Equal(t, dir, command.Dir)
	require.Equal(t, "/home/alice", (*vars)["HOME"])

	task.targetUser = filepath.Join(dir, "missing")
	_, _, _, err = env.createCmdAndEnv(task)
	require.ErrorContains(t, err, "cannot access directory")
	task.targetUser = filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(task.targetUser, nil, 0600))
	_, _, _, err = env.createCmdAndEnv(task)
	require.ErrorContains(t, err, "is not a directory")
}

func TestLocalUnixNonPtyWaitDoesNotHangOnInheritedOutput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting a process with Unix credentials requires root")
	}
	ctx, cancel := newSshTestContext()
	defer cancel()
	home := t.TempDir()
	pidFile := filepath.Join(home, "child.pid")
	t.Cleanup(func() {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	stored := &sshTestStoredSession{id: session.MustNewId()}
	sshSession := newSshTestSession(ctx, `sleep 30 & echo $! > "$HOME/child.pid"`, nil)
	task := &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: stored},
		session:       sshSession,
		taskType:      TaskTypeShell,
	}
	env := &local{
		repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}},
		user: &user.User{
			Name: "test", Uid: user.Id(os.Getuid()), Group: user.Group{Gid: user.GroupId(os.Getgid())},
			HomeDir: home, Shell: "/bin/sh",
		},
	}
	type outcome struct {
		exitCode int
		err      error
	}
	result := make(chan outcome, 1)
	go func() {
		exitCode, err := env.Run(task)
		result <- outcome{exitCode, err}
	}()
	select {
	case outcome := <-result:
		require.NoError(t, outcome.err)
		require.Zero(t, outcome.exitCode)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("non-PTY process wait remained blocked by child output pipes")
	}
}

type localBlockedOutputSession struct {
	*sshTestSession
	started chan struct{}
	release chan struct{}
}

func (this *localBlockedOutputSession) Write(data []byte) (int, error) {
	select {
	case this.started <- struct{}{}:
	default:
	}
	<-this.release
	return this.sshTestSession.Write(data)
}

type localDelayedOutputSession struct {
	*localBlockedOutputSession
	delivered chan error
}

func (this *localDelayedOutputSession) Write(data []byte) (int, error) {
	n, err := this.localBlockedOutputSession.Write(data)
	select {
	case this.delivered <- err:
	default:
	}
	return n, err
}

func TestLocalUnixNonPtyWaitDoesNotHangOnBlockedOutput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting a process with Unix credentials requires root")
	}
	ctx, cancel := newSshTestContext()
	defer cancel()
	sshSession := &localBlockedOutputSession{
		sshTestSession: newSshTestSession(ctx, "printf output", nil),
		started:        make(chan struct{}, 1),
		release:        make(chan struct{}),
	}
	t.Cleanup(func() { close(sshSession.release) })
	stored := &sshTestStoredSession{id: session.MustNewId()}
	task := &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: stored},
		session:       sshSession,
		taskType:      TaskTypeShell,
	}
	env := &local{
		repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}},
		user: &user.User{
			Name: "test", Uid: user.Id(os.Getuid()), Group: user.Group{Gid: user.GroupId(os.Getgid())},
			HomeDir: t.TempDir(), Shell: "/bin/sh",
		},
	}
	result := make(chan error, 1)
	go func() {
		_, err := env.Run(task)
		result <- err
	}()
	select {
	case <-sshSession.started:
	case <-time.After(5 * time.Second):
		t.Fatal("process did not write to SSH output")
	}
	select {
	case err := <-result:
		require.ErrorContains(t, err, "process output")
	case <-time.After(8 * time.Second):
		cancel()
		t.Fatal("non-PTY process wait remained blocked inside SSH output writer")
	}
}

func TestLocalUnixNonPtyLateSuccessfulWriteKeepsOutputFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting a process with Unix credentials requires root")
	}
	ctx, cancel := newSshTestContext()
	defer cancel()
	sshSession := &localDelayedOutputSession{
		localBlockedOutputSession: &localBlockedOutputSession{
			sshTestSession: newSshTestSession(ctx, "printf output", nil),
			started:        make(chan struct{}, 1),
			release:        make(chan struct{}),
		},
		delivered: make(chan error, 1),
	}
	t.Cleanup(func() {
		select {
		case <-sshSession.release:
		default:
			close(sshSession.release)
		}
	})
	stored := &sshTestStoredSession{id: session.MustNewId()}
	task := &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: stored},
		session:       sshSession,
		taskType:      TaskTypeShell,
	}
	env := &local{
		repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}},
		user: &user.User{
			Name: "test", Uid: user.Id(os.Getuid()), Group: user.Group{Gid: user.GroupId(os.Getgid())},
			HomeDir: t.TempDir(), Shell: "/bin/sh",
		},
	}
	type outcome struct {
		code int
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		code, err := env.Run(task)
		done <- outcome{code, err}
	}()
	select {
	case <-sshSession.started:
	case <-time.After(5 * time.Second):
		t.Fatal("local process did not reach SSH output writer")
	}
	select {
	case result := <-done:
		require.Equal(t, -1, result.code)
		require.ErrorContains(t, result.err, "local process output did not complete before timeout")
	case <-time.After(8 * time.Second):
		cancel()
		t.Fatal("local process did not finish after output timeout")
	}
	close(sshSession.release)
	select {
	case err := <-sshSession.delivered:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("delayed SSH writer did not complete after release")
	}
}

func TestLocalUnixNonPtyForwardsAllOutput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting a process with Unix credentials requires root")
	}
	ctx, cancel := newSshTestContext()
	defer cancel()
	stored := &sshTestStoredSession{id: session.MustNewId()}
	sshSession := newSshTestSession(ctx, "printf stdout; printf stderr >&2", nil)
	task := &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: stored},
		session:       sshSession,
		taskType:      TaskTypeShell,
	}
	env := &local{
		repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}},
		user: &user.User{
			Name: "test", Uid: user.Id(os.Getuid()), Group: user.Group{Gid: user.GroupId(os.Getgid())},
			HomeDir: t.TempDir(), Shell: "/bin/sh",
		},
	}
	exitCode, err := env.Run(task)
	require.NoError(t, err)
	require.Zero(t, exitCode)
	require.Equal(t, "stdout", sshSession.stdout.String())
	require.Equal(t, "stderr", sshSession.stderr.String())
}

func TestLocalUnixNonPtyBlockedOutputDoesNotHoldCancellation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting a process with Unix credentials requires root")
	}
	ctx, cancel := newSshTestContext()
	defer cancel()
	sshSession := &localBlockedOutputSession{
		sshTestSession: newSshTestSession(ctx, "printf output; exec sleep 30", nil),
		started:        make(chan struct{}, 1),
		release:        make(chan struct{}),
	}
	t.Cleanup(func() { close(sshSession.release) })
	stored := &sshTestStoredSession{id: session.MustNewId()}
	task := &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: stored},
		session:       sshSession,
		taskType:      TaskTypeShell,
	}
	env := &local{
		repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}},
		user: &user.User{
			Name: "test", Uid: user.Id(os.Getuid()), Group: user.Group{Gid: user.GroupId(os.Getgid())},
			HomeDir: t.TempDir(), Shell: "/bin/sh",
		},
	}
	type outcome struct {
		exitCode int
		err      error
	}
	result := make(chan outcome, 1)
	go func() {
		exitCode, err := env.Run(task)
		result <- outcome{exitCode, err}
	}()
	select {
	case <-sshSession.started:
	case <-time.After(5 * time.Second):
		t.Fatal("process did not write to SSH output")
	}
	cancel()
	select {
	case actual := <-result:
		require.Equal(t, -2, actual.exitCode)
		require.NoError(t, actual.err)
	case <-time.After(8 * time.Second):
		t.Fatal("canceled non-PTY process remained blocked inside SSH output writer")
	}
}

func TestLocalShellCommandArgumentsAndCredentials(t *testing.T) {
	tests := map[string]struct {
		rawCommand string
		wantArgs   []string
	}{
		"interactive login shell": {
			wantArgs: []string{"-zsh"},
		},
		"remote command remains one raw argument": {
			rawCommand: `printf '%s\n' "$HOME"; touch '/tmp/not interpolated'`,
			wantArgs:   []string{"zsh", "-c", `printf '%s\n' "$HOME"; touch '/tmp/not interpolated'`},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			local, task := newLocalCommandTest(t, TaskTypeShell, test.rawCommand)
			cmd, _, release, err := local.createCmdAndEnv(task)
			require.NoError(t, err)
			defer release()
			credentials := cmd.SysProcAttr.Credential
			require.NotNil(t, credentials)

			require.NoError(t, local.configureCmd(task, cmd))
			require.Equal(t, "/bin/zsh", cmd.Path)
			require.Equal(t, test.wantArgs, cmd.Args)
			require.Same(t, credentials, cmd.SysProcAttr.Credential)
		})
	}
}

func TestLocalNonPtyCommandStartsInNewProcessGroup(t *testing.T) {
	local, task := newLocalCommandTest(t, TaskTypeShell, "true")
	cmd, _, release, err := local.createCmdAndEnv(task)
	require.NoError(t, err)
	defer release()
	require.True(t, cmd.SysProcAttr.Setpgid)
	require.False(t, cmd.SysProcAttr.Setsid)
	require.False(t, cmd.SysProcAttr.Setctty)
}

func TestLocalPtyCommandStartsInNewSessionWithoutSetpgid(t *testing.T) {
	local, task := newLocalCommandTest(t, TaskTypeShell, "")
	cmd, _, release, err := local.createCmdAndEnv(task)
	require.NoError(t, err)
	defer release()

	fPty, fTty, err := pty.Open()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = fPty.Close()
		_ = fTty.Close()
	})
	require.NoError(t, local.configureCmdForPty(cmd, fPty, fTty))
	require.False(t, cmd.SysProcAttr.Setpgid)
	require.True(t, cmd.SysProcAttr.Setsid)
	require.True(t, cmd.SysProcAttr.Setctty)
}

func TestLocalSftpCommandPreservesCredentials(t *testing.T) {
	local, task := newLocalCommandTest(t, TaskTypeSftp, "")
	cmd, _, release, err := local.createCmdAndEnv(task)
	require.NoError(t, err)
	defer release()
	credentials := cmd.SysProcAttr.Credential
	require.NotNil(t, credentials)

	require.NoError(t, local.configureCmd(task, cmd))
	executable, err := os.Executable()
	require.NoError(t, err)
	require.Equal(t, executable, cmd.Path)
	require.Equal(t, []string{executable, "sftp-server"}, cmd.Args)
	require.Same(t, credentials, cmd.SysProcAttr.Credential)
}

func TestInitialPtyWinsize(t *testing.T) {
	size, err := initialPtyWinsize(essh.Window{
		Width:        1<<16 - 1,
		Height:       0,
		WidthPixels:  1920,
		HeightPixels: 1080,
	})
	require.NoError(t, err)
	require.Equal(t, uint16(1<<16-1), size.Cols)
	require.Zero(t, size.Rows)
	require.Equal(t, uint16(1920), size.X)
	require.Equal(t, uint16(1080), size.Y)
}

func TestPtyWinsizeRejectsOutOfRangeDimensions(t *testing.T) {
	tests := map[string]essh.Window{
		"negative width":          {Width: -1},
		"oversized width":         {Width: 1 << 16},
		"negative height":         {Height: -1},
		"oversized height":        {Height: 1 << 16},
		"negative width pixels":   {WidthPixels: -1},
		"oversized width pixels":  {WidthPixels: 1 << 16},
		"negative height pixels":  {HeightPixels: -1},
		"oversized height pixels": {HeightPixels: 1 << 16},
	}

	for name, window := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := initialPtyWinsize(window)
			require.ErrorContains(t, err, "outside uint16 range")

			_, err = resizedPtyWinsize(ptyTestWinsize(), window)
			require.ErrorContains(t, err, "outside uint16 range")
		})
	}
}

func TestResizedPtyWinsizePreservesZeroDimensions(t *testing.T) {
	current := ptyTestWinsize()

	unchanged, err := resizedPtyWinsize(current, essh.Window{})
	require.NoError(t, err)
	require.Equal(t, current, unchanged)

	resized, err := resizedPtyWinsize(current, essh.Window{Width: 100, HeightPixels: 720})
	require.NoError(t, err)
	require.Equal(t, uint16(100), resized.Cols)
	require.Equal(t, current.Rows, resized.Rows)
	require.Equal(t, current.X, resized.X)
	require.Equal(t, uint16(720), resized.Y)
}

func TestLocalRunRejectsInvalidInitialPtySize(t *testing.T) {
	local, task := newLocalCommandTest(t, TaskTypeShell, "true")
	task.session = &localPtyTestSession{
		sshTestSession: task.session.(*sshTestSession),
		pty:            essh.Pty{Window: essh.Window{Width: 1 << 16}},
	}

	exitCode, err := local.Run(task)
	require.Equal(t, -1, exitCode)
	require.ErrorContains(t, err, "invalid initial pty size")
}

func newLocalCommandTest(t *testing.T, taskType TaskType, rawCommand string) (*local, *sshTestTask) {
	t.Helper()
	ctx, cancel := newSshTestContext()
	t.Cleanup(cancel)
	storedSession := &sshTestStoredSession{id: session.MustNewId()}
	sshSession := newSshTestSession(ctx, rawCommand, nil)
	task := &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: storedSession},
		session:       sshSession,
		taskType:      taskType,
	}
	return &local{
		repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}},
		user: &user.User{
			Name:    "trusted-user",
			Uid:     1000,
			Group:   user.Group{Gid: 1001},
			Groups:  user.Groups{{Gid: 1002}},
			HomeDir: "/trusted/home",
			Shell:   "/bin/zsh",
		},
		getEffectiveUserID: func() int { return 0 },
	}, task
}

func ptyTestWinsize() pty.Winsize {
	return pty.Winsize{Rows: 24, Cols: 80, X: 640, Y: 480}
}

type localPtyTestSession struct {
	*sshTestSession
	pty     essh.Pty
	windows <-chan essh.Window
}

func (this *localPtyTestSession) Pty() (essh.Pty, <-chan essh.Window, bool) {
	return this.pty, this.windows, true
}

func TestCredentialsForUser(t *testing.T) {
	target := &user.User{
		Uid:    1000,
		Group:  user.Group{Gid: 1001},
		Groups: user.Groups{{Gid: 1002}},
	}

	tests := map[string]struct {
		effectiveUserID int
		wantPermission  bool
	}{
		"root to another UID": {
			effectiveUserID: 0,
		},
		"non-root to same UID": {
			effectiveUserID: 1000,
		},
		"non-root to another UID denied": {
			effectiveUserID: 1003,
			wantPermission:  true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			credentials, err := credentialsForUser(target, test.effectiveUserID)
			if test.wantPermission {
				require.Nil(t, credentials)
				require.Error(t, err)
				require.True(t, errors.Permission.IsErr(err))
				require.Contains(t, err.Error(), "root privileges are required")
				return
			}

			require.NoError(t, err)
			require.Equal(t, target.ToCredentials(), *credentials)
		})
	}
}

func TestLocalEnvironmentDoesNotCreateCommandWithoutRequiredPrivileges(t *testing.T) {
	local := &local{
		repository:         &LocalRepository{conf: &configuration.EnvironmentLocal{}},
		user:               &user.User{Uid: 1000},
		getEffectiveUserID: func() int { return 1001 },
	}

	cmd, environment, release, err := local.createCmdAndEnv(nil)
	require.Nil(t, cmd)
	require.Nil(t, environment)
	require.Nil(t, release)
	require.Error(t, err)
	require.True(t, errors.Permission.IsErr(err))
}

func TestSignalProcessGroupUsesNegativeProcessGroupID(t *testing.T) {
	var calls []processGroupCall
	kill := func(pid int, signal syscall.Signal) error {
		calls = append(calls, processGroupCall{pid, signal})
		return nil
	}

	require.NoError(t, signalProcessGroup(1234, syscall.SIGUSR1, kill))
	require.Equal(t, []processGroupCall{
		{-1234, 0},
		{-1234, syscall.SIGUSR1},
	}, calls)
}

func TestSignalProcessGroupIgnoresEsrchAfterProbe(t *testing.T) {
	callCount := 0
	kill := func(pid int, signal syscall.Signal) error {
		callCount++
		require.Equal(t, -1234, pid)
		if signal == syscall.SIGTERM {
			return syscall.ESRCH
		}
		return nil
	}

	require.NoError(t, signalProcessGroup(1234, syscall.SIGTERM, kill))
	require.Equal(t, 2, callCount)
}

func TestCleanupProcessGroupTerminatesThenKillsAfterGracePeriod(t *testing.T) {
	var calls []processGroupCall
	var sleeps []time.Duration
	ops := processGroupOps{
		kill: func(pid int, signal syscall.Signal) error {
			calls = append(calls, processGroupCall{pid, signal})
			return nil
		},
		sleep: func(duration time.Duration) {
			sleeps = append(sleeps, duration)
		},
	}

	require.NoError(t, cleanupProcessGroup(4321, 55*time.Millisecond, 20*time.Millisecond, ops))
	require.Equal(t, []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 15 * time.Millisecond}, sleeps)
	require.Equal(t, []processGroupCall{
		{-4321, 0},
		{-4321, syscall.SIGTERM},
		{-4321, 0},
		{-4321, 0},
		{-4321, 0},
		{-4321, syscall.SIGKILL},
	}, calls)
}

func TestCleanupProcessGroupContinuesAfterLeaderIsGone(t *testing.T) {
	var calls []processGroupCall
	ops := processGroupOps{
		kill: func(pid int, signal syscall.Signal) error {
			calls = append(calls, processGroupCall{pid, signal})
			return nil
		},
		sleep: func(time.Duration) {},
	}

	require.NoError(t, cleanupProcessGroup(321, 0, time.Millisecond, ops))
	require.Equal(t, []processGroupCall{
		{-321, 0},
		{-321, syscall.SIGTERM},
		{-321, 0},
		{-321, syscall.SIGKILL},
	}, calls)
}

func TestCleanupProcessGroupAlreadyGoneIsNoop(t *testing.T) {
	var calls []processGroupCall
	ops := processGroupOps{
		kill: func(pid int, signal syscall.Signal) error {
			calls = append(calls, processGroupCall{pid, signal})
			return syscall.ESRCH
		},
		sleep: func(time.Duration) {
			t.Fatal("cleanup slept for an absent process group")
		},
	}

	require.NoError(t, cleanupProcessGroup(987, time.Second, time.Millisecond, ops))
	require.Equal(t, []processGroupCall{{-987, 0}}, calls)
}

func TestCleanupProcessGroupStopsWhenGroupDisappearsDuringGracePeriod(t *testing.T) {
	var calls []processGroupCall
	ops := processGroupOps{
		kill: func(pid int, signal syscall.Signal) error {
			calls = append(calls, processGroupCall{pid, signal})
			if len(calls) == 3 {
				return syscall.ESRCH
			}
			return nil
		},
		sleep: func(time.Duration) {},
	}

	require.NoError(t, cleanupProcessGroup(654, time.Second, time.Second, ops))
	require.Equal(t, []processGroupCall{
		{-654, 0},
		{-654, syscall.SIGTERM},
		{-654, 0},
	}, calls)
}

func TestCleanupProcessGroupTreatsProcessDoneAsGone(t *testing.T) {
	ops := processGroupOps{
		kill:  func(int, syscall.Signal) error { return os.ErrProcessDone },
		sleep: func(time.Duration) { t.Fatal("cleanup slept for a completed process group") },
	}
	require.NoError(t, cleanupProcessGroup(852, time.Second, time.Millisecond, ops))
}

func TestCleanupProcessGroupIsBounded(t *testing.T) {
	var sleepCount int
	ops := processGroupOps{
		kill: func(int, syscall.Signal) error { return nil },
		sleep: func(time.Duration) {
			sleepCount++
		},
	}

	require.NoError(t, cleanupProcessGroup(741, time.Second, 300*time.Millisecond, ops))
	require.Equal(t, 4, sleepCount)
}

func TestLocalProcessGroupLeaderCannotDetach(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_PROCESS_GROUP_DETACH") == "1" {
		if _, err := syscall.Setsid(); err == syscall.EPERM {
			os.Exit(42)
		} else if err != nil {
			os.Exit(43)
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLocalProcessGroupLeaderCannotDetach$")
	cmd.Env = append(os.Environ(), "BIFROEST_TEST_PROCESS_GROUP_DETACH=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err := cmd.Run()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 42, exitErr.ExitCode())
}

func TestCleanupProcessGroupReachesDescendantAfterLeaderExit(t *testing.T) {
	directory := t.TempDir()
	readyFile := filepath.Join(directory, "ready")
	terminatedFile := filepath.Join(directory, "terminated")
	releaseFile := filepath.Join(directory, "release")
	script := `(trap 'printf terminated > "$2"; exit 0' TERM; printf ready > "$1"; while :; do sleep 1; done) & while [ ! -f "$3" ]; do sleep 0.01; done`
	cmd := exec.Command("/bin/sh", "-c", script, "sh", readyFile, terminatedFile, releaseFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	processGroupID := cmd.Process.Pid
	cleanupRequired := true
	t.Cleanup(func() {
		if cleanupRequired {
			_ = syscall.Kill(-processGroupID, syscall.SIGKILL)
		}
		_ = cmd.Wait()
	})
	actualProcessGroupID, err := syscall.Getpgid(cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, cmd.Process.Pid, actualProcessGroupID)
	require.Eventually(t, func() bool {
		_, err := os.Stat(readyFile)
		return err == nil
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, os.WriteFile(releaseFile, nil, 0o600))
	require.NoError(t, cmd.Wait())

	_, exists, err := probeProcessGroup(processGroupID, syscall.Kill)
	require.NoError(t, err)
	require.True(t, exists)
	require.NoError(t, cleanupProcessGroup(processGroupID, 500*time.Millisecond, 10*time.Millisecond, defaultProcessGroupOps()))
	cleanupRequired = false
	require.Eventually(t, func() bool {
		content, err := os.ReadFile(terminatedFile)
		return err == nil && string(content) == "terminated"
	}, time.Second, 10*time.Millisecond)
}

type processGroupCall struct {
	pid    int
	signal syscall.Signal
}
