package format

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/cli/transport"
)

func TestManagementOutputFormats(t *testing.T) {
	type entry struct {
		Name string `json:"name" yaml:"name"`
	}
	entries := []entry{{Name: "first"}}
	for _, format := range []Format{Text, Json, Yaml} {
		t.Run(string(format), func(t *testing.T) {
			var result bytes.Buffer
			require.NoError(t, WriteList(&result, format, []string{"NAME"}, [][]string{{"first"}}, entries))
			if format == Text {
				require.Equal(t, "NAME\nfirst\n", result.String())
			} else {
				var restored []entry
				if format == Json {
					require.NoError(t, json.Unmarshal(result.Bytes(), &restored))
				} else {
					require.NoError(t, yaml.Unmarshal(result.Bytes(), &restored))
				}
				require.Equal(t, entries, restored)
			}
			result.Reset()
			require.NoError(t, WriteDetail(&result, format, []Field{{Name: "Name", Value: "first"}}, entries[0]))
			if format == Text {
				require.Equal(t, "Name:  first\n", result.String())
			} else {
				require.Contains(t, result.String(), "name")
			}
		})
	}
	var output bytes.Buffer
	require.NoError(t, WriteList(&output, Text, []string{"NAME"}, [][]string{{"first\nSECOND\tvalue"}}, entries))
	require.Equal(t, 2, strings.Count(output.String(), "\n"))
	require.ErrorContains(t, WriteList(&output, Text, []string{"NAME"}, [][]string{{"one", "two"}}, entries), "instead of")
	require.ErrorContains(t, WriteDetail(&output, "xml", nil, entries), "unsupported output format")
}

func TestManagementCBORResultHasVersionAndBounds(t *testing.T) {
	type data struct {
		Name string `cbor:"name"`
	}
	var output bytes.Buffer
	require.NoError(t, WriteDetail(&output, WireCbor, nil, data{Name: "secure"}))
	var decoded data
	require.NoError(t, transport.DecodeWireResult(&output, &decoded))
	require.Equal(t, data{Name: "secure"}, decoded)
	require.Error(t, transport.DecodeWireResult(bytes.NewReader(bytes.Repeat([]byte{0}, transport.MaxWireResultBytes+1)), &decoded))
	require.Error(t, transport.DecodeWireResult(bytes.NewReader([]byte{0xff}), &decoded))
	output.Reset()
	require.Error(t, transport.DecodeWireResult(&output, &decoded))
	require.NoError(t, WriteDetail(io.Discard, WireCbor, nil, decoded))
	output.Reset()
	settings := map[string]any{"environment": map[string]any{"password": "***redacted***"}}
	require.NoError(t, WriteSettings(&output, WireCbor, settings))
	var restored map[string]any
	require.NoError(t, transport.DecodeWireResult(&output, &restored))
	require.Equal(t, settings, restored)
}

func TestVerificationAndProducerFormats(t *testing.T) {
	for _, format := range []Format{Text, Json, Yaml} {
		var output bytes.Buffer
		require.NoError(t, WriteVerification(&output, format, "outer"))
		if format == Text {
			require.Equal(t, "verified (scope: outer)\n", output.String())
		} else {
			require.Contains(t, output.String(), "outer")
			require.Contains(t, output.String(), "verified")
		}
		output.Reset()
		require.NoError(t, WriteProducerID(&output, format, "abc"))
		if format == Text {
			require.Equal(t, "abc\n", output.String())
		} else {
			require.Contains(t, output.String(), "producerId")
		}
	}
}
