package environment

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainerLeasePreservesNativeTerminalCapability(t *testing.T) {
	for name, raw := range map[string]Environment{"kubernetes": &kubernetes{}, "docker": &docker{}} {
		t.Run(name, func(t *testing.T) {
			_, ok := raw.(TerminalRunner)
			require.True(t, ok, "the raw native backend supports neutral execution")
			var lease Environment = &containerLease{Environment: raw}
			_, ok = lease.(TerminalRunner)
			require.True(t, ok, "repository-acquired ownership must not erase the neutral execution capability")
		})
	}
}

type leaseTerminalEnvironment struct {
	Environment
	task          TerminalTask
	calls, closes int
	err           error
}

func (e *leaseTerminalEnvironment) RunTerminal(task TerminalTask) (int, error) {
	e.task = task
	e.calls++
	return 7, e.err
}
func (e *leaseTerminalEnvironment) Close() error { e.closes++; return nil }

func TestContainerLeaseDelegatesExactNeutralTaskAndFailureWithoutSshFallback(t *testing.T) {
	task := newNeutralTerminalTask(t, "exact terminal command", nil)
	for _, failure := range []error{nil, errors.New("backend failure")} {
		raw := &leaseTerminalEnvironment{err: failure}
		var lease Environment = &containerLease{Environment: raw}
		runner, ok := lease.(TerminalRunner)
		require.True(t, ok)
		code, err := runner.RunTerminal(task)
		require.Equal(t, 7, code)
		require.Same(t, task, raw.task)
		if failure == nil {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, failure)
		}
		require.Equal(t, 1, raw.calls)
		require.NoError(t, lease.Close())
		require.NoError(t, lease.Close())
		require.Equal(t, 1, raw.closes)
		_, err = runner.RunTerminal(task)
		require.ErrorContains(t, err, "lease already closed")
		require.Equal(t, 1, raw.calls, "a released lease cannot start another execution")
	}
	legacy := &containerLease{Environment: &lifecycleDisposableEnvironment{}}
	runner, ok := any(legacy).(TerminalRunner)
	require.True(t, ok)
	_, err := runner.RunTerminal(task)
	require.ErrorContains(t, err, "does not support neutral terminal execution")
}
