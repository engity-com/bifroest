//go:build darwin

package sys

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDarwinSignalMappings(t *testing.T) {
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
		native, ok := signalToNative(test.protocol)
		require.True(t, ok)
		require.Equal(t, test.native, native)
		require.Equal(t, test.native, test.protocol.Native())
	}
}

func TestDarwinRejectsLinuxOnlySignal(t *testing.T) {
	_, ok := signalToNative(SIGPWR)
	require.False(t, ok)
	require.Zero(t, SIGPWR.Native())
}
