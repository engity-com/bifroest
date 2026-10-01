//go:build linux || darwin

package sys

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignalUsesLinuxProtocolValues(t *testing.T) {
	require.Equal(t, Signal(10), SIGUSR1)
	require.Equal(t, Signal(12), SIGUSR2)
	require.Equal(t, Signal(17), SIGCHLD)
	require.Equal(t, Signal(29), SIGIO)
}
