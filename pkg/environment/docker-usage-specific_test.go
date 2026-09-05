package environment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/sys"
)

func TestDockerExecWrapperDoesNotReceiveTargetEnvironment(t *testing.T) {
	environment := sys.EnvVars{"LD_PRELOAD": "/tmp/attacker.so", "USER_VALUE": "secret"}
	require.ElementsMatch(t, dockerWrapperEnvironment, dockerExecEnvironment(true, sys.OsLinux, environment))
	require.Nil(t, dockerExecEnvironment(true, sys.OsWindows, environment))
	require.ElementsMatch(t, []string{"LD_PRELOAD=/tmp/attacker.so", "USER_VALUE=secret"}, dockerExecEnvironment(false, sys.OsLinux, environment))
}

func TestIsolatedDockerContainerEnvironmentClearsImageValues(t *testing.T) {
	actual := isolatedDockerContainerEnvironment(
		[]string{"PATH=/attacker", "LD_PRELOAD=/tmp/attacker.so", "TOKEN=secret", "BIFROEST_SESSION_ID=attacker"},
		[]string{"BIFROEST_SESSION_ID=trusted", "BIFROEST_MASTER_PUBLIC_KEY=trusted-key"},
	)
	require.ElementsMatch(t, []string{
		"PATH=" + dockerWrapperPath,
		"LD_PRELOAD=",
		"TOKEN=",
		"BIFROEST_SESSION_ID=trusted",
		"BIFROEST_MASTER_PUBLIC_KEY=trusted-key",
	}, actual)
}
