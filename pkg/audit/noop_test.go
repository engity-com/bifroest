package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoopRecorder(t *testing.T) {
	recorder := NewNoopRecorder()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	require.NoError(t, recorder.Record(ctx, Event{Name: "test.event"}))
	require.NoError(t, recorder.Close())
	require.NoError(t, recorder.Close())
}
