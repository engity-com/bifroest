package windowslocal

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// A controlled native denial is not a successful cleanup/context reference if
// additional independent failures were joined to it. Preserve every leaf for
// the native assertions; a wrapping message alone is not an additional cause.
func samPolicyErrorLeaves(err error) []error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var result []error
		for _, child := range joined.Unwrap() {
			result = append(result, samPolicyErrorLeaves(child)...)
		}
		return result
	}
	if child := errors.Unwrap(err); child != nil {
		return samPolicyErrorLeaves(child)
	}
	return []error{err}
}

func TestSAMPolicyDenialCauseAccountingPreservesAdditionalFailures(t *testing.T) {
	denied, cleanup := errors.New("controlled denial"), errors.New("cleanup failed")
	wrapped := fmt.Errorf("native restriction: %w", denied)
	require.Empty(t, samPolicyErrorLeaves(nil))
	require.Equal(t, []error{denied}, samPolicyErrorLeaves(errors.Join(wrapped)))
	require.Equal(t, []error{denied, cleanup, context.Canceled}, samPolicyErrorLeaves(errors.Join(wrapped, errors.Join(cleanup, context.Canceled))))
	require.Equal(t, []error{denied, denied}, samPolicyErrorLeaves(errors.Join(denied, denied)), "duplicate causes must not silently collapse either")
}
