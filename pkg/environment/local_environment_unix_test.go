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

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
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
			"HOME":    {},
			"USER":    {},
			"LOGNAME": {},
			"SHELL":   {},
		},
	}
	local := &local{repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}}, user: &user.User{Name: "trusted-user", HomeDir: "/trusted/home", Shell: "/trusted/shell"}}
	_, environment, release, err := local.createCmdAndEnv(task)
	require.NoError(t, err)
	defer release()
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
