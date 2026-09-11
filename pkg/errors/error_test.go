package errors

import (
	goerrors "errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsTypeTraversesJoinedAndWrappedErrors(t *testing.T) {
	err := fmt.Errorf("outer: %w", goerrors.Join(
		Config.Newf("configuration failed"),
		System.Newf("cleanup failed"),
	))
	require.True(t, Config.IsErr(err))
	require.True(t, System.IsErr(err))
	require.False(t, Network.IsErr(err))
}
