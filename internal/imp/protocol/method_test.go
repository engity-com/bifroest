package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMethodIdsRemainWireCompatible(t *testing.T) {
	require.Equal(t, Method(0), MethodPing)
	require.Equal(t, Method(1), MethodKill)
	require.Equal(t, Method(2), MethodTcpForward)
	require.Equal(t, Method(3), MethodNamedPipe)
	require.Equal(t, Method(4), MethodGetConnectionExitCode)
	require.Equal(t, Method(5), MethodGetEnvironment)
	require.Equal(t, Method(6), MethodKillExecution)
	require.Equal(t, Method(7), MethodGetExecutionExitCode)
	require.Equal(t, Method(8), MethodNamedPipeForUser)
}
