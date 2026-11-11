//go:build windows

package environment

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLocalConPTYReleaseUsesOnlyThePublicFeatureAndKeepsFailures(t *testing.T) {
	failure := errors.New("public release failed")
	for _, test := range []struct {
		name             string
		findErr, callErr error
		released         bool
		calls            int
		wantErr          error
	}{
		{"older supported close", windows.ERROR_PROC_NOT_FOUND, nil, false, 0, nil},
		{"public release", nil, nil, true, 1, nil},
		{"lookup denied", windows.ERROR_ACCESS_DENIED, nil, false, 0, windows.ERROR_ACCESS_DENIED},
		{"release failed", nil, failure, false, 1, failure},
	} {
		t.Run(test.name, func(t *testing.T) {
			lookups, calls := 0, 0
			released, err := resolveLocalConPTYRelease(func() error {
				lookups++
				return test.findErr
			}, func() error {
				calls++
				return test.callErr
			})
			require.Equal(t, test.released, released)
			require.ErrorIs(t, err, test.wantErr)
			require.Equal(t, 1, lookups)
			require.Equal(t, test.calls, calls, "no retry or optimistic release on failure")
		})
	}
}
