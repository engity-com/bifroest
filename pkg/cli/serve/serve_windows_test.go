//go:build windows

package serve

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExplicitWindowsServiceModeDoesNotDependOnParentHeuristics(t *testing.T) {
	active, err := windowsServiceMode(true, func() (bool, error) {
		t.Fatal("explicit SCM startup must not call the unreliable parent detector")
		return false, nil
	})
	require.NoError(t, err)
	require.True(t, active)
	for _, detected := range []bool{false, true} {
		active, err := windowsServiceMode(false, func() (bool, error) { return detected, nil })
		require.NoError(t, err)
		require.Equal(t, detected, active, "implicit startup keeps its existing detection semantics")
	}
	failure := errors.New("cannot inspect parent")
	_, err = windowsServiceMode(false, func() (bool, error) { return false, failure })
	require.ErrorIs(t, err, failure)
}
