package template

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDurationLockUsesTheDurationRendererWithoutChangingOrdinaryProperties(t *testing.T) {
	for _, entry := range []struct {
		name   string
		text   string
		data   any
		locked bool
	}{
		{name: "literal", text: "10s"},
		{name: "locked literal", text: "!10s", locked: true},
		{name: "template", text: "{{.interval}}", data: map[string]string{"interval": "10s"}},
		{name: "locked template", text: "{{.interval}}", data: map[string]string{"interval": "!10s"}, locked: true},
		{name: "trimmed template", text: " {{.interval}} ", data: map[string]string{"interval": "!10s"}, locked: true},
	} {
		t.Run(entry.name, func(t *testing.T) {
			value := MustNewDuration(entry.text)
			interval, locked, err := value.RenderWithLock(entry.data, 64)
			require.NoError(t, err)
			require.Equal(t, 10*time.Second, interval)
			require.Equal(t, entry.locked, locked)
			normal, err := value.Render(entry.data)
			if entry.locked {
				require.Error(t, err, "ordinary durations must not silently accept the lock marker")
				require.Zero(t, normal)
			} else {
				require.NoError(t, err)
				require.Equal(t, interval, normal)
			}
		})
	}
}

func TestDurationLockKeepsStaticAndTemplatedValidationSeparate(t *testing.T) {
	for _, text := range []string{"10s", "!10s", "invalid"} {
		require.True(t, MustNewDuration(text).IsHardCoded())
	}
	value := MustNewDuration("{{.interval}}")
	require.False(t, value.IsHardCoded())
	_, _, err := value.RenderWithLock(nil, 64)
	require.Error(t, err)
	for _, interval := range []string{"!", "!!10s", "!invalid", "1s" + strings.Repeat("0µs", 20)} {
		_, _, err := value.RenderWithLock(map[string]string{"interval": interval}, 64)
		require.Error(t, err)
	}
	_, _, err = MustNewDuration("10s").RenderWithLock(nil, 1)
	require.Error(t, err)
}
