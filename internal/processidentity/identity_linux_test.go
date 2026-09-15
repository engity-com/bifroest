//go:build linux

package processidentity

import (
	"os"
	"strconv"
	"testing"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/require"
)

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
