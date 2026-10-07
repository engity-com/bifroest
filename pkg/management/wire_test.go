package management

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWireRequestBoundsAndVersion(t *testing.T) {
	want := []string{"session", "ls", "--format=cbor"}
	encoded, err := EncodeWireRequest(want)
	require.NoError(t, err)
	actual, err := DecodeWireRequest(bytes.NewReader(encoded))
	require.NoError(t, err)
	require.Equal(t, want, actual)
	_, err = DecodeWireRequest(bytes.NewReader(bytes.Repeat([]byte{0}, maxWireRequestBytes+1)))
	require.Error(t, err)
	_, err = DecodeWireRequest(bytes.NewReader([]byte{0xff}))
	require.Error(t, err)
	_, err = DecodeWireRequest(bytes.NewReader(nil))
	require.Error(t, err)
	_, err = EncodeWireRequest([]string{string(bytes.Repeat([]byte{'x'}, maxWireRequestBytes))})
	require.Error(t, err)
}
