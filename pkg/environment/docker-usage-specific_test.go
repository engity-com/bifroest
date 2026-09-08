package environment

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestDockerExecWrapperReceivesTargetEnvironmentOnlyAsEncodedPayload(t *testing.T) {
	environment := sys.EnvVars{"LD_PRELOAD": "/tmp/attacker.so", "USER_VALUE": "secret"}
	actual, err := dockerExecEnvironment(true, sys.OsLinux, environment)
	require.NoError(t, err)
	require.Len(t, actual, len(dockerWrapperEnvironment)+1)
	require.ElementsMatch(t, dockerWrapperEnvironment, actual[:len(actual)-1])
	encoded := strings.TrimPrefix(actual[len(actual)-1], execution.TargetEnvironmentEnvName+"=")
	require.NotEqual(t, actual[len(actual)-1], encoded)
	decoded, err := execution.DecodeTargetEnvironment(encoded)
	require.NoError(t, err)
	require.Equal(t, map[string]string(environment), decoded)

	actual, err = dockerExecEnvironment(true, sys.OsWindows, environment)
	require.NoError(t, err)
	require.Len(t, actual, 1)
	require.NotContains(t, actual[0], "secret")

	actual, err = dockerExecEnvironment(false, sys.OsLinux, environment)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"LD_PRELOAD=/tmp/attacker.so", "USER_VALUE=secret"}, actual)
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
