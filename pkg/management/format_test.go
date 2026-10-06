package management

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestManagementOutputFormats(t *testing.T) {
	type entry struct {
		Name string `json:"name" yaml:"name"`
	}
	entries := []entry{{Name: "first"}}
	for _, format := range []Format{FormatTable, FormatJSON, FormatYAML} {
		t.Run(string(format), func(t *testing.T) {
			var result bytes.Buffer
			require.NoError(t, WriteList(&result, format, []string{"NAME"}, [][]string{{"first"}}, entries))
			if format == FormatTable {
				require.Equal(t, "NAME\nfirst\n", result.String())
			} else {
				var restored []entry
				if format == FormatJSON {
					require.NoError(t, json.Unmarshal(result.Bytes(), &restored))
				} else {
					require.NoError(t, yaml.Unmarshal(result.Bytes(), &restored))
				}
				require.Equal(t, entries, restored)
			}
			result.Reset()
			require.NoError(t, WriteDetail(&result, format, []Field{{Name: "Name", Value: "first"}}, entries[0]))
			if format == FormatTable {
				require.Equal(t, "Name:  first\n", result.String())
			} else {
				require.Contains(t, result.String(), "name")
			}
		})
	}
	var output bytes.Buffer
	require.NoError(t, WriteList(&output, FormatTable, []string{"NAME"}, [][]string{{"first\nSECOND\tvalue"}}, entries))
	require.Equal(t, 2, strings.Count(output.String(), "\n"))
	require.ErrorContains(t, WriteList(&output, FormatTable, []string{"NAME"}, [][]string{{"one", "two"}}, entries), "instead of")
	require.ErrorContains(t, WriteDetail(&output, "xml", nil, entries), "unsupported output format")
}

func TestManagementCBORResultHasVersionAndBounds(t *testing.T) {
	type data struct {
		Name string `cbor:"name"`
	}
	var output bytes.Buffer
	require.NoError(t, WriteDetail(&output, FormatCBOR, nil, data{Name: "secure"}))
	var decoded data
	require.NoError(t, DecodeWireResult(&output, &decoded))
	require.Equal(t, data{Name: "secure"}, decoded)
	require.Error(t, DecodeWireResult(bytes.NewReader(bytes.Repeat([]byte{0}, MaxWireResultBytes+1)), &decoded))
	require.Error(t, DecodeWireResult(bytes.NewReader([]byte{0xff}), &decoded))
	output.Reset()
	require.Error(t, DecodeWireResult(&output, &decoded))
	require.NoError(t, WriteDetail(io.Discard, FormatCBOR, nil, decoded))
}
