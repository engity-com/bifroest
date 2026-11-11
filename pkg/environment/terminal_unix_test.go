//go:build unix

package environment

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/user"
)

func neutralLocalEnvironment(t *testing.T) *local {
	t.Helper()
	return &local{repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}}, user: &user.User{Name: "neutral-user", Uid: user.Id(os.Getuid()), Group: user.Group{Gid: user.GroupId(os.Getgid())}, HomeDir: t.TempDir(), Shell: "/bin/sh"}}
}

func TestNeutralLocalCommandAndEnvironmentWithoutSsh(t *testing.T) {
	env := neutralLocalEnvironment(t)
	task := newNeutralTerminalTask(t, "printf hello", &sshTestStoredSession{id: session.MustNewId()})
	command := &exec.Cmd{}
	require.NoError(t, env.configureShellCmd(task, command))
	require.Equal(t, []string{"sh", "-c", "printf hello"}, command.Args)
	_, variables, release, err := env.createCmdAndEnv(task)
	require.NoError(t, err)
	defer release()
	require.Equal(t, "neutral-user", (*variables)["USER"])
	require.Equal(t, "authorization", (*variables)["LAYER"])
}

func TestNeutralLocalRunPreservesExitCodeAndSeparateStreams(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("local execution with Unix account credentials requires root")
	}
	env := neutralLocalEnvironment(t)
	task := newNeutralTerminalTask(t, "printf stdout; printf stderr >&2; exit 17", &sshTestStoredSession{id: session.MustNewId()})
	code, err := env.RunTerminal(task)
	require.NoError(t, err)
	require.Equal(t, 17, code)
	require.Equal(t, "stdout", task.stream.output.String())
	require.Equal(t, "stderr", task.stream.stderr.String())
}
