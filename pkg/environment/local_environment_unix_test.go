//go:build unix

package environment

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

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
