package cast

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCastEventInspectionSharesFullVerifierAndExactRawOutput(t *testing.T) {
	_, expected := portableCastVector(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "assets", "recording-format-vectors", "native-v1", "bcast-v1.cast"))
	require.NoError(t, err)
	var events []CastEvent
	verified, err := InspectCastEvents(bytes.NewReader(data), CastVerifyOptions{ExpectedProducerId: expected}, func(event CastEvent) error { events = append(events, event); return nil })
	require.NoError(t, err)
	plain, err := VerifyCast(bytes.NewReader(data), CastVerifyOptions{ExpectedProducerId: expected})
	require.NoError(t, err)
	require.Equal(t, plain, verified)
	require.Len(t, events, 4)
	require.Equal(t, []byte("Welcome\r\n\xff"), events[0].Data)
	require.Equal(t, OutputStreamTerminal, events[0].Stream)
	require.Equal(t, 248*time.Millisecond, events[0].Elapsed)
	require.EqualValues(t, 132, events[1].Columns)
	require.EqualValues(t, 43, events[1].Rows)
	require.Equal(t, 1001*time.Millisecond, events[1].Elapsed)
	require.Equal(t, "m", events[2].Code)
	require.Equal(t, "x", events[3].Code)
	require.Equal(t, 2104*time.Millisecond, events[3].Elapsed)
	for index := range events[0].Data {
		events[0].Data[index] = 0
	}
	require.Contains(t, string(data), "Welcome")
	failure := errors.New("local visitor bound")
	verified, err = InspectCastEvents(bytes.NewReader(data), CastVerifyOptions{ExpectedProducerId: expected}, func(CastEvent) error { return failure })
	require.ErrorIs(t, err, failure)
	require.Nil(t, verified)
	provisional := 0
	verified, err = InspectCastEvents(bytes.NewReader(data[:len(data)-10]), CastVerifyOptions{ExpectedProducerId: expected}, func(CastEvent) error { provisional++; return nil })
	require.Error(t, err)
	require.Nil(t, verified)
	require.Positive(t, provisional, "callbacks are explicitly provisional, not independent verification success")
	ctx, cancel := context.WithCancel(t.Context())
	verified, err = InspectCastEvents(bytes.NewReader(data), CastVerifyOptions{ExpectedProducerId: expected, Context: ctx}, func(CastEvent) error { cancel(); return nil })
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, verified)
}
