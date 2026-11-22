package test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPerformanceSecondsPreservesMeasuredTicks(t *testing.T) {
	const start = int64(1 << 62)
	require.Equal(t, 0.0000007, performanceSeconds(start, start+7, 10000000))
	require.Zero(t, performanceSeconds(start, start, 10000000), "do not invent a minimum duration")
	for _, value := range []struct{ start, end, frequency int64 }{
		{-1, 1, 10000000}, {2, 1, 10000000}, {1, 2, 0}, {1, 2, -1},
	} {
		require.True(t, math.IsNaN(performanceSeconds(value.start, value.end, value.frequency)))
	}
}

func TestPerformanceCounterIsAvailable(t *testing.T) {
	require.Positive(t, performanceFrequency)
	start := startMeasurement()
	require.GreaterOrEqual(t, int64(start), int64(0))
	require.GreaterOrEqual(t, start.seconds(), 0.0)
}
