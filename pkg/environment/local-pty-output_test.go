package environment

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLocalPtyOutputDrainWaitsBeforePublishingProcessSuccess(t *testing.T) {
	done := make(chan error)
	result := make(chan error, 1)
	go func() {
		result <- waitLocalPtyOutput(t.Context(), done, time.Second, func() { t.Error("unexpected abort") })
	}()
	select {
	case <-result:
		t.Fatal("process success escaped before output completion")
	default:
	}
	done <- nil
	require.NoError(t, <-result)
}

func TestLocalPtyOutputDrainCancellationClosesBothSides(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	aborted := false
	err := waitLocalPtyOutput(ctx, make(chan error), time.Second, func() { aborted = true })
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, aborted)
}

func TestLocalPtyOutputDrainTimeoutCannotTurnIntoLateSuccess(t *testing.T) {
	done := make(chan error, 1)
	aborted := false
	err := waitLocalPtyOutput(t.Context(), done, 10*time.Millisecond, func() { aborted = true })
	require.ErrorContains(t, err, "PTY output did not complete")
	require.True(t, aborted)
	done <- nil
	require.Error(t, err, "late output completion cannot replace the timed-out result")
}
