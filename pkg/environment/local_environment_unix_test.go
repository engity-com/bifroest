//go:build unix

package environment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

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
	local := &local{user: &user.User{Name: "trusted-user", HomeDir: "/trusted/home", Shell: "/trusted/shell"}}
	_, environment, err := local.createCmdAndEnv(task)
	require.NoError(t, err)
	require.Equal(t, "/trusted/home", (*environment)["HOME"])
	require.Equal(t, "trusted-user", (*environment)["USER"])
	require.Equal(t, "trusted-user", (*environment)["LOGNAME"])
	require.Equal(t, "/trusted/shell", (*environment)["SHELL"])
}
