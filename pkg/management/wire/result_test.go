package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestPortableWireResultBoundsCompletionAndStringMapShape(t *testing.T) {
	want := map[string]any{"name": "work", "nested": map[string]any{"key": "value"}}
	encoded, err := EncodeWireResult(want)
	require.NoError(t, err)
	var actual map[string]any
	require.NoError(t, DecodeWireResult(bytes.NewReader(encoded), &actual))
	require.Equal(t, want, actual)
	badVersion, err := cbor.Marshal(wireResult{Version: 2, Payload: cbor.RawMessage{0xf6}})
	require.NoError(t, err)
	for _, raw := range [][]byte{nil, {0xff}, encoded[:len(encoded)-1], append(bytes.Clone(encoded), 0), append(bytes.Clone(encoded), encoded...), badVersion, bytes.Repeat([]byte{0}, MaxWireResultBytes+1)} {
		var target any
		require.Error(t, DecodeWireResult(bytes.NewReader(raw), &target))
	}
	failure := errors.New("transport failed after result")
	require.ErrorIs(t, DecodeWireResult(io.MultiReader(bytes.NewReader(encoded), transferErrorReader{failure}), &actual), failure)
}
