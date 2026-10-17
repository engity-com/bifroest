package format

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
)

func TestRecordingListStreamWritesEachEntryAndCompletesFormats(t *testing.T) {
	entries := []model.RecordingView{{ID: "first", Auditlog: "default"}, {ID: "second", Auditlog: "default"}}
	for _, selected := range []Format{Text, Json, Yaml, Cbor, WireCborStream} {
		var output bytes.Buffer
		writer, err := NewRecordingListStream(&output, selected)
		require.NoError(t, err)
		require.Empty(t, output.Bytes())
		for _, entry := range entries {
			before := output.Len()
			require.NoError(t, writer.Write(entry))
			require.Greater(t, output.Len(), before)
			require.Contains(t, output.String(), entry.ID)
		}
		require.NoError(t, writer.Close())
		var decoded []model.RecordingView
		switch selected {
		case Text:
			require.Equal(t, 1, bytes.Count(output.Bytes(), []byte("AUDITLOG")))
			continue
		case Json:
			require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
		case Yaml:
			require.NoError(t, yaml.Unmarshal(output.Bytes(), &decoded))
		case Cbor:
			require.NoError(t, cbor.Unmarshal(output.Bytes(), &decoded))
		case WireCborStream:
			require.NoError(t, transport.DecodeRecordingListStream(&output, func(row model.RecordingView) error {
				decoded = append(decoded, row)
				return nil
			}))
		}
		require.Equal(t, entries, decoded)
		require.ErrorIs(t, writer.Write(entries[0]), io.ErrClosedPipe)
	}
}

func TestRecordingListStreamEmptyResults(t *testing.T) {
	for _, selected := range []Format{Json, Yaml, Cbor, WireCborStream} {
		var output bytes.Buffer
		writer, err := NewRecordingListStream(&output, selected)
		require.NoError(t, err)
		require.NoError(t, writer.Close())
		var decoded []model.RecordingView
		switch selected {
		case Json:
			require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
		case Yaml:
			require.NoError(t, yaml.Unmarshal(output.Bytes(), &decoded))
		case Cbor:
			require.NoError(t, cbor.Unmarshal(output.Bytes(), &decoded))
		case WireCborStream:
			require.NoError(t, transport.DecodeRecordingListStream(&output, func(model.RecordingView) error {
				t.Fatal("empty stream yielded an entry")
				return nil
			}))
		}
		require.Empty(t, decoded)
	}
}

type shortRecordingListOutput struct{}

func (shortRecordingListOutput) Write([]byte) (int, error) { return 0, nil }

func TestRecordingListStreamReportsShortWrites(t *testing.T) {
	for _, selected := range []Format{Text, Json, Yaml, Cbor, WireCborStream} {
		writer, err := NewRecordingListStream(shortRecordingListOutput{}, selected)
		require.NoError(t, err)
		require.ErrorIs(t, writer.Write(model.RecordingView{ID: "entry"}), io.ErrShortWrite)
	}
}
