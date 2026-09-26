package nativeformat

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testWireValue struct {
	Number uint64 `cbor:"1,keyasint"`
	Name   string `cbor:"2,keyasint,omitempty"`
}

type noncanonicalValue struct{}

func (noncanonicalValue) MarshalCBOR() ([]byte, error) {
	return []byte{0xa1, 0x18, 0x01, 0x02}, nil
}

func TestNativeCBORRequiresCanonicalTypedMaps(t *testing.T) {
	encoded, err := Marshal(testWireValue{Number: 42}, MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, []byte{0xa1, 0x01, 0x18, 0x2a}, encoded)
	decoded, err := Unmarshal[testWireValue](encoded, MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, testWireValue{Number: 42}, decoded)

	for name, encoded := range map[string][]byte{
		"unknown field":        {0xa2, 0x01, 0x02, 0x03, 0x04},
		"duplicate key":        {0xa2, 0x01, 0x02, 0x01, 0x03},
		"text key":             {0xa1, 0x61, '1', 0x02},
		"noncanonical integer": {0xa1, 0x18, 0x01, 0x02},
		"unsorted keys":        {0xa2, 0x02, 0x61, 'x', 0x01, 0x02},
		"indefinite map":       {0xbf, 0x01, 0x02, 0xff},
		"tagged value":         {0xa1, 0x01, 0xc0, 0x02},
		"invalid UTF-8":        {0xa2, 0x01, 0x02, 0x02, 0x61, 0xff},
		"trailing item":        {0xa1, 0x01, 0x02, 0x00},
		"null field":           {0xa1, 0x01, 0xf6},
	} {
		t.Run(name, func(t *testing.T) {
			decoded, err := Unmarshal[testWireValue](encoded, MaxMetadataPayload)
			require.Error(t, err)
			require.Equal(t, testWireValue{}, decoded)
		})
	}

	_, err = Marshal(testWireValue{Number: 1, Name: string([]byte{0xff})}, MaxMetadataPayload)
	require.Error(t, err)
	_, err = Marshal(noncanonicalValue{}, MaxMetadataPayload)
	require.Error(t, err)
	_, err = Marshal(testWireValue{Number: 1}, 1)
	require.Error(t, err)
	_, err = Unmarshal[testWireValue]([]byte{0xa1, 0x01, 0x02}, 2)
	require.Error(t, err)

	type requiredBytes struct {
		Value []byte `cbor:"1,keyasint"`
	}
	_, err = Marshal(requiredBytes{}, MaxMetadataPayload)
	require.Error(t, err, "nil required bytes must not be encoded as CBOR null")
	_, err = Unmarshal[requiredBytes]([]byte{0xa1, 0x01, 0xf6}, MaxMetadataPayload)
	require.Error(t, err)
	_, err = Unmarshal[requiredBytes]([]byte{0xa1, 0x01, 0xf7}, MaxMetadataPayload)
	require.Error(t, err)
	_, err = Unmarshal[map[uint64]any]([]byte{0xa1, 0x20, 0x01}, MaxMetadataPayload)
	require.Error(t, err, "CBOR map keys must be unsigned integers")
}

func TestNativeTimestampUsesNanosecondArray(t *testing.T) {
	value := time.Unix(-1, 987654321).UTC()
	stamp := TimestampOf(value)
	encoded, err := Marshal(struct {
		Timestamp Timestamp `cbor:"1,keyasint"`
	}{stamp}, MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, []byte{0xa1, 0x01, 0x82, 0x20, 0x1a, 0x3a, 0xde, 0x68, 0xb1}, encoded)
	decoded, err := Unmarshal[struct {
		Timestamp Timestamp `cbor:"1,keyasint"`
	}](encoded, MaxMetadataPayload)
	require.NoError(t, err)
	actual, err := decoded.Timestamp.Time()
	require.NoError(t, err)
	require.True(t, actual.Equal(value))
	_, err = (Timestamp{Seconds: 1, Nanoseconds: 1e9}).Time()
	require.Error(t, err)
	_, err = Marshal(struct {
		Timestamp Timestamp `cbor:"1,keyasint"`
	}{Timestamp{Seconds: 1, Nanoseconds: 1e9}}, MaxMetadataPayload)
	require.Error(t, err)
	_, err = Unmarshal[struct {
		Timestamp Timestamp `cbor:"1,keyasint"`
	}]([]byte{0xa1, 0x01, 0x82, 0x01, 0x1a, 0x3b, 0x9a, 0xca, 0x00}, MaxMetadataPayload)
	require.Error(t, err)
}

func TestNativeCBORByteArraysAreByteStrings(t *testing.T) {
	value := struct {
		Hash [32]byte `cbor:"1,keyasint"`
	}{Hash: [32]byte{1, 2, 3}}
	encoded, err := Marshal(value, MaxMetadataPayload)
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(encoded, []byte{0xa1, 0x01, 0x58, 0x20}))
	decoded, err := Unmarshal[struct {
		Hash [32]byte `cbor:"1,keyasint"`
	}](encoded, MaxMetadataPayload)
	require.NoError(t, err)
	require.Equal(t, value, decoded)
}
