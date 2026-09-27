//go:build linux

package sys

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinuxSignalMappingsPreserveProtocolValues(t *testing.T) {
	tests := []struct {
		protocol Signal
		native   syscall.Signal
	}{
		{SIGUSR1, syscall.SIGUSR1},
		{SIGUSR2, syscall.SIGUSR2},
		{SIGCHLD, syscall.SIGCHLD},
		{SIGIO, syscall.SIGIO},
	}

	for _, test := range tests {
		native, err := test.protocol.Native()
		require.NoError(t, err)
		require.Equal(t, test.native, native)

		protocol, err := SignalFromNative(test.native)
		require.NoError(t, err)
		require.Equal(t, test.protocol, protocol)
	}
}
