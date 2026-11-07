//go:build unix

package environment

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalCommandEnvironmentPinsConnectionAndFreshExecutionIdentity(t *testing.T) {
	stored := &sshTestStoredSession{id: session.MustNewId()}
	env := &local{repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}}, user: &user.User{Name: "test", Uid: user.Id(os.Getuid()), Group: user.Group{Gid: user.GroupId(os.Getgid())}, HomeDir: t.TempDir(), Shell: "/bin/sh"}}
	seen := map[string]bool{}
	task := newNeutralTerminalTask(t, "", stored)
	task.auth.(*sshTestAuthorization).environment = sys.EnvVars{connection.EnvName: "untrusted-connection", execution.EnvName: "untrusted-execution", session.EnvName: "untrusted-session"}
	for range 3 {
		_, actual, release, err := env.createCmdAndEnv(task)
		require.NoError(t, err)
		release()
		require.Equal(t, task.conn.id.String(), (*actual)[connection.EnvName])
		require.Equal(t, stored.id.String(), (*actual)[session.EnvName])
		var id execution.Id
		require.NoError(t, id.Set((*actual)[execution.EnvName]))
		require.False(t, id.IsZero())
		require.NotEqual(t, task.conn.id.String(), id.String())
		require.False(t, seen[id.String()], "a new execution must not reuse a previous execution ID")
		seen[id.String()] = true
	}
}
