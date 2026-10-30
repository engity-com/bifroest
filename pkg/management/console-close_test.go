package management

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConsoleInputCleanupFlushRestoreCloseOrderAndErrors(t *testing.T) {
	for _, discard := range []bool{false, true} {
		for failureMask := range 8 {
			t.Run(fmt.Sprintf("discard=%t/errors=%d", discard, failureMask), func(t *testing.T) {
				var calls []string
				flushErr, restoreErr, closeErr := errors.New("flush failed"), errors.New("restore failed"), errors.New("close failed")
				operation := func(name string, bit int, failure error) func() error {
					return func() error {
						calls = append(calls, name)
						if failureMask&bit != 0 {
							return failure
						}
						return nil
					}
				}
				cleanupErr := closeConsoleInputLifecycle(discard, operation("flush", 1, flushErr), operation("restore", 2, restoreErr), operation("close", 4, closeErr))
				expected := []string{"restore", "close"}
				if discard {
					expected = []string{"flush", "restore", "close"}
				}
				require.Equal(t, expected, calls)
				require.Equal(t, discard && failureMask&1 != 0, errors.Is(cleanupErr, flushErr))
				require.Equal(t, failureMask&2 != 0, errors.Is(cleanupErr, restoreErr))
				require.Equal(t, failureMask&4 != 0, errors.Is(cleanupErr, closeErr))
				challengeErr := errors.Join(context.Canceled, cleanupErr)
				require.ErrorIs(t, challengeErr, context.Canceled)
			})
		}
	}
}
