package format

import (
	"encoding"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	_ encoding.TextMarshaler   = MetricsText
	_ encoding.TextUnmarshaler = (*MetricsFormat)(nil)
)

func TestMetricsFormatMarshalText(t *testing.T) {
	for _, selected := range []MetricsFormat{MetricsText, MetricsJson, MetricsOpenMetrics} {
		t.Run(string(selected), func(t *testing.T) {
			encoded, err := selected.MarshalText()
			require.NoError(t, err)
			require.Equal(t, string(selected), string(encoded))
			var restored MetricsFormat
			require.NoError(t, restored.UnmarshalText(encoded))
			require.Equal(t, selected, restored)
			encoded, err = json.Marshal(selected)
			require.NoError(t, err)
			require.Equal(t, `"`+string(selected)+`"`, string(encoded))
			require.NoError(t, json.Unmarshal(encoded, &restored))
			require.Equal(t, selected, restored)
		})
	}
	for _, selected := range []MetricsFormat{"", "text", "yaml", "cbor", "openmetric", "unknown", MetricsWireCbor} {
		encoded, err := selected.MarshalText()
		require.ErrorIs(t, err, ErrIllegal)
		require.True(t, errors.IsType(err, errors.User))
		require.Empty(t, encoded)
	}
}

func TestMetricsFormatUnmarshalText(t *testing.T) {
	for _, test := range []struct {
		input string
		want  MetricsFormat
	}{
		{"table", MetricsText}, {"text", MetricsText}, {"TABLE", MetricsText},
		{"json", MetricsJson}, {"JSON", MetricsJson},
		{"openmetrics", MetricsOpenMetrics}, {"OpenMetrics", MetricsOpenMetrics},
	} {
		t.Run(test.input, func(t *testing.T) {
			var selected MetricsFormat
			require.NoError(t, selected.UnmarshalText([]byte(test.input)))
			require.Equal(t, test.want, selected)
		})
	}
	for _, input := range []string{"", "yaml", "cbor", "openmetric", "unknown", "internal-cbor", "internal-cbor-stream"} {
		selected := MetricsJson
		err := selected.UnmarshalText([]byte(input))
		require.ErrorIs(t, err, ErrIllegal)
		require.True(t, errors.IsType(err, errors.User))
		require.Equal(t, MetricsJson, selected, "invalid input must not change the selected format")
	}
}

func TestMetricsFormatDoesNotExtendGeneralFormats(t *testing.T) {
	var selected Format
	require.ErrorIs(t, selected.UnmarshalText([]byte("openmetrics")), ErrIllegal)
	_, err := Format("openmetrics").MarshalText()
	require.ErrorIs(t, err, ErrIllegal)
}
