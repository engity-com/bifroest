package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWatchModeCanonicalValuesAndAliases(t *testing.T) {
	for input, expected := range map[string]WatchMode{
		"off": WatchModeOff, "false": WatchModeOff, "no": WatchModeOff, "0": WatchModeOff,
		"preserve": WatchModePreserve, "true": WatchModePreserve,
		"reconnect": WatchModeReconnect, "reuse": WatchModeReuse,
	} {
		t.Run(input, func(t *testing.T) {
			var mode WatchMode
			require.NoError(t, mode.Set(input))
			require.Equal(t, expected, mode)
			require.NoError(t, mode.Validate())
			text, err := mode.MarshalText()
			require.NoError(t, err)
			require.Equal(t, expected.String(), string(text))
			require.True(t, mode.IsEqualTo(&expected))
			require.Equal(t, mode, mode.Clone())
			require.Equal(t, mode == WatchModeOff, mode.IsZero())
			require.Equal(t, mode != WatchModeOff, mode.IsEnabled())
		})
	}
	for _, input := range []string{"", "invalid", "1", "yes", "Preserve"} {
		mode := WatchModeReuse
		require.Error(t, mode.Set(input))
		require.Equal(t, WatchModeReuse, mode)
	}
	require.Error(t, WatchMode(255).Validate())
	require.Contains(t, WatchMode(255).String(), "illegal-watch-mode")
	require.False(t, WatchModeOff.IsEqualTo(nil))
}
