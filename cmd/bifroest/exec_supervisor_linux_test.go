//go:build linux

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestExecProcessSupervisorFallsBackWithoutAnonymousInodes(t *testing.T) {
	original := openExecPidfd
	openExecPidfd = func(int, int) (int, error) { return -1, unix.ENODEV }
	t.Cleanup(func() { openExecPidfd = original })

	supervisor, err := newExecProcessSupervisor()
	require.NoError(t, err)
	require.False(t, supervisor.pidfdSupported)
	require.NoError(t, supervisor.Cleanup())
}
