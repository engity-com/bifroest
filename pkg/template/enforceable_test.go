package template

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEnforceableDuration(t *testing.T) {
	for _, entry := range []struct {
		name     string
		text     string
		data     any
		enforced bool
	}{
		{name: "literal", text: "10s"},
		{name: "enforced literal", text: "!10s", enforced: true},
		{name: "template", text: "{{.interval}}", data: map[string]string{"interval": "10s"}},
		{name: "enforced template result", text: "{{.interval}}", data: map[string]string{"interval": "!10s"}, enforced: true},
		{name: "enforced template", text: "!{{.interval}}", data: map[string]string{"interval": "10s"}, enforced: true},
		{name: "trimmed template", text: " {{.interval}} ", data: map[string]string{"interval": "!10s"}, enforced: true},
	} {
		t.Run(entry.name, func(t *testing.T) {
			value := MustNewEnforceable[Duration](entry.text)
			interval, enforced, err := value.Render(entry.data)
			require.NoError(t, err)
			require.Equal(t, 10*time.Second, interval)
			require.Equal(t, entry.enforced, enforced)
			require.Equal(t, entry.text, value.String())
			encoded, err := yaml.Marshal(value)
			require.NoError(t, err)
			var restored Enforceable[Duration, time.Duration, *Duration]
			require.NoError(t, yaml.Unmarshal(encoded, &restored))
			require.True(t, value.IsEqualTo(restored))
			again, flag, err := restored.Render(entry.data)
			require.NoError(t, err)
			require.Equal(t, interval, again)
			require.Equal(t, enforced, flag)
		})
	}
}

func TestEnforceableUsesDifferentUnderlyingTypes(t *testing.T) {
	text, enforced, err := MustNewEnforceable[String]("!{{.value}}").Render(map[string]string{"value": "kept"})
	require.NoError(t, err)
	require.Equal(t, "kept", text)
	require.True(t, enforced)
	boolean, enforced, err := MustNewEnforceable[Bool]("{{.value}}").Render(map[string]string{"value": "!false"})
	require.NoError(t, err)
	require.False(t, boolean)
	require.True(t, enforced)
	integer, enforced, err := MustNewEnforceable[Int64]("!-42").Render(nil)
	require.NoError(t, err)
	require.EqualValues(t, -42, integer)
	require.True(t, enforced)
	unsigned, enforced, err := MustNewEnforceable[Uint64]("42").Render(nil)
	require.NoError(t, err)
	require.EqualValues(t, 42, unsigned)
	require.False(t, enforced)
	address, enforced, err := MustNewEnforceable[Url]("!https://example.org/path").Render(nil)
	require.NoError(t, err)
	require.Equal(t, &url.URL{Scheme: "https", Host: "example.org", Path: "/path"}, address)
	require.True(t, enforced)
}

func TestEnforceableRejectsMalformedValuesAndKeepsBoundsLocal(t *testing.T) {
	for _, text := range []string{"!!10s", "invalid", "!invalid"} {
		value := MustNewEnforceable[Duration](text)
		require.True(t, value.IsHardCoded())
		require.Error(t, value.Validate())
		_, enforced, err := value.Render(nil)
		require.Error(t, err)
		require.False(t, enforced)
	}
	value := MustNewEnforceable[Duration]("{{.interval}}")
	require.False(t, value.IsHardCoded())
	require.NoError(t, value.Validate(), "validation must not evaluate authenticated context")
	_, _, err := value.Render(nil)
	require.Error(t, err)
	_, _, err = value.RenderBounded(map[string]string{"interval": "1s" + strings.Repeat("0µs", 20)}, 64)
	require.Error(t, err)
	_, _, err = MustNewEnforceable[Duration]("10s").RenderBounded(nil, 1)
	require.Error(t, err)
	_, _, err = MustNewEnforceable[Duration]("!{{.interval}}").Render(map[string]string{"interval": "!10s"})
	require.Error(t, err)
}

func TestEnforceablePreservesInnerZeroAndStringValues(t *testing.T) {
	empty := MustNewEnforceable[String]("!")
	value, enforced, err := empty.Render(nil)
	require.NoError(t, err)
	require.Empty(t, value)
	require.True(t, enforced)
	require.False(t, empty.IsZero(), "an enforced empty value is not an absent setting")
	require.NoError(t, empty.Validate())
	for _, entry := range []struct {
		source, value string
		enforced      bool
	}{
		{source: " spaced ", value: " spaced "},
		{source: "! spaced ", value: " spaced ", enforced: true},
		{source: "!!literal", value: "!literal", enforced: true},
	} {
		value, enforced, err := MustNewEnforceable[String](entry.source).Render(nil)
		require.NoError(t, err)
		require.Equal(t, entry.value, value)
		require.Equal(t, entry.enforced, enforced)
	}
	zero, enforced, err := MustNewEnforceable[Duration]("!").Render(nil)
	require.NoError(t, err, "duration range requirements belong to the consuming property")
	require.Zero(t, zero)
	require.True(t, enforced)
}

func TestEnforceableTreatsRenderedTemplateSyntaxAsData(t *testing.T) {
	for _, text := range []string{"{{.missing}}", "{{panic}}", "{{`private` | file}}"} {
		value, enforced, err := MustNewEnforceable[String]("{{.value}}").Render(map[string]string{"value": text})
		require.NoError(t, err)
		require.Equal(t, text, value)
		require.False(t, enforced)
		_, _, err = MustNewEnforceable[Duration]("{{.value}}").Render(map[string]string{"value": text})
		require.Error(t, err)
	}
}

func TestEnforceableZeroEqualityAndFailedSet(t *testing.T) {
	var zero Enforceable[Duration, time.Duration, *Duration]
	require.True(t, zero.IsZero())
	interval, enforced, err := zero.Render(nil)
	require.NoError(t, err)
	require.Zero(t, interval)
	require.False(t, enforced)
	value := MustNewEnforceable[Duration]("!10s")
	require.False(t, value.IsZero())
	require.False(t, value.IsEqualTo(MustNewEnforceable[Duration]("10s")))
	require.False(t, value.IsEqualTo(nil))
	require.False(t, value.IsEqualTo((*Enforceable[Duration, time.Duration, *Duration])(nil)))
	require.Error(t, value.Set("{{"))
	require.Equal(t, "!10s", value.String(), "a failed update must retain the original value")
	require.NoError(t, value.Set(""))
	require.True(t, value.IsZero())
}

func TestOrdinaryDurationStillRejectsEnforcement(t *testing.T) {
	for _, text := range []string{"!10s", "{{.interval}}"} {
		value, err := MustNewDuration(text).Render(map[string]string{"interval": "!10s"})
		require.Error(t, err)
		require.Zero(t, value)
	}
}

func TestEnforceableRenderingDoesNotShareEnforcementBetweenCalls(t *testing.T) {
	value := MustNewEnforceable[Duration]("{{.value}}")
	for index := range 8 {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			t.Parallel()
			text := "10s"
			expected := index%2 == 0
			if expected {
				text = "!10s"
			}
			for range 100 {
				duration, enforced, err := value.Render(map[string]string{"value": text})
				require.NoError(t, err)
				require.Equal(t, 10*time.Second, duration)
				require.Equal(t, expected, enforced)
			}
		})
	}
}
