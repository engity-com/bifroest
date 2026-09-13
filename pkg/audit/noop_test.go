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
	suppressible, ok := recorder.(SuppressibleRecorder)
	require.True(t, ok)
	recorded, err := suppressible.RecordSuppressible(ctx, Event{Name: "test.suppressible"})
	require.NoError(t, err)
	require.True(t, recorded)
	require.NoError(t, recorder.Close())
	require.NoError(t, recorder.Close())
}
