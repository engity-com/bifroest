//go:build linux

package processidentity

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Legacy gopsutil times use a wall-clock/uptime-derived boot epoch in
	// containers. Pin and warm that reference before any test goroutines start;
	// production still uses its unchanged strict, fail-closed comparison.
	process.EnableBootTimeCache(true)
	candidate, err := process.NewProcess(int32(os.Getpid()))
	if err == nil {
		_, err = candidate.CreateTime()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot initialize legacy process test clock")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestGetIsStable(t *testing.T) {
	expected, err := Get(os.Getpid())
	require.NoError(t, err)
	require.Regexp(t, `^linux:[0-9a-f-]+:[0-9]+$`, expected)

	for range 100 {
		actual, err := Get(os.Getpid())
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}

func TestMatchesCurrentProcess(t *testing.T) {
	identity, err := Get(os.Getpid())
	require.NoError(t, err)

	matches, err := Matches(os.Getpid(), identity)
	require.NoError(t, err)
	require.True(t, matches)

	matches, err = Matches(os.Getpid(), identity+"0")
	require.NoError(t, err)
	require.False(t, matches)
}

func TestMatchesLegacyCreationTime(t *testing.T) {
	candidate, err := process.NewProcess(int32(os.Getpid()))
	require.NoError(t, err)
	createdAt, err := candidate.CreateTime()
	require.NoError(t, err)

	matches, err := Matches(os.Getpid(), strconv.FormatInt(createdAt, 10))
	require.NoError(t, err)
	require.True(t, matches)
	for _, difference := range []int64{-1000, -1, 1, 1000} {
		matches, err := Matches(os.Getpid(), strconv.FormatInt(createdAt+difference, 10))
		require.NoError(t, err)
		require.False(t, matches, "legacy identity comparison must not acquire a tolerance window")
	}
}

func TestParseLinuxStatHandlesSpecialCommandNames(t *testing.T) {
	raw := []byte("123 (a name) with ) chars) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20")

	actual, err := parseLinuxStat(raw)

	require.NoError(t, err)
	require.Equal(t, int64(987654), actual)
}

func TestParseLinuxStatRejectsInvalidInput(t *testing.T) {
	for _, raw := range []string{
		"123 invalid",
		"123 (short) S 1 2",
		"123 (invalid start) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 nope",
		"123 (negative start) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 -1",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := parseLinuxStat([]byte(raw))
			require.Error(t, err)
		})
	}
}
