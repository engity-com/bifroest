package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSAMBlankNetworkPolicyKnownValuesAndStrictErrors(t *testing.T) {
	for _, scenario := range []string{"zero", "one", "missing-open", "output-open-error", "null-open", "read-error", "close-error", "unknown-type", "unknown-value", "cancel-open", "cancel-read", "cancel-close", "read-close-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			readFailure, closeFailure := errors.New("policy read failed"), errors.New("policy close failed")
			opened, reads, closes := false, 0, 0
			value := uint64(1)
			if scenario == "zero" {
				value = 0
			}
			result, err := inspectSAMBlankNetworkPolicyFlow(ctx, samBlankNetworkPolicyOperations{
				open: func() (uintptr, error) {
					if scenario == "missing-open" {
						return 0, readFailure
					}
					if scenario == "null-open" {
						return 0, nil
					}
					opened = true
					if scenario == "cancel-open" {
						cancel()
					}
					if scenario == "output-open-error" {
						return 7, readFailure
					}
					return 7, nil
				},
				read: func(key uintptr) (uint64, uint32, error) {
					reads++
					require.Equal(t, uintptr(7), key)
					if scenario == "cancel-read" {
						cancel()
					}
					if scenario == "read-error" || scenario == "read-close-cancel" {
						return 0, 0, readFailure
					}
					if scenario == "unknown-type" {
						return value, 11, nil
					}
					if scenario == "unknown-value" {
						return 2, samBlankPolicyDWORD, nil
					}
					return value, samBlankPolicyDWORD, nil
				},
				close: func(key uintptr) error {
					closes++
					require.Equal(t, uintptr(7), key)
					if scenario == "cancel-close" || scenario == "read-close-cancel" {
						cancel()
					}
					if scenario == "close-error" || scenario == "read-close-cancel" {
						return closeFailure
					}
					return nil
				},
			})
			if scenario == "zero" || scenario == "one" {
				require.NoError(t, err)
				require.Equal(t, value == 1, result)
			} else {
				require.Error(t, err)
				require.False(t, result)
			}
			if opened {
				require.Equal(t, 1, closes)
			} else {
				require.Zero(t, closes)
			}
			if scenario == "missing-open" || scenario == "null-open" || scenario == "output-open-error" || scenario == "cancel-open" {
				require.Zero(t, reads)
			} else {
				require.Equal(t, 1, reads)
			}
			if scenario == "read-close-cancel" {
				require.ErrorIs(t, err, readFailure)
				require.ErrorIs(t, err, closeFailure)
				require.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}

func TestSAMBlankNetworkPolicyRequiresContextAndOperations(t *testing.T) {
	called := false
	api := samBlankNetworkPolicyOperations{open: func() (uintptr, error) { called = true; return 7, nil }, read: func(uintptr) (uint64, uint32, error) { called = true; return 1, samBlankPolicyDWORD, nil }, close: func(uintptr) error { called = true; return nil }}
	_, err := inspectSAMBlankNetworkPolicyFlow(nil, api)
	require.Error(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = inspectSAMBlankNetworkPolicyFlow(ctx, api)
	require.ErrorIs(t, err, context.Canceled)
	for index, incomplete := range []samBlankNetworkPolicyOperations{{read: api.read, close: api.close}, {open: api.open, close: api.close}, {open: api.open, read: api.read}} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			_, err := inspectSAMBlankNetworkPolicyFlow(t.Context(), incomplete)
			require.Error(t, err)
		})
	}
	require.False(t, called)
}
