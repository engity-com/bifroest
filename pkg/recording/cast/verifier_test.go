package cast

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	connectionid "github.com/engity-com/bifroest/pkg/connection/id"
	sessionid "github.com/engity-com/bifroest/pkg/session/id"
)

func portableCastVector(t *testing.T) ([]byte, evidence.ProducerId) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "assets", "recording-format-vectors", "cast-v3.cast"))
	require.NoError(t, err)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	require.NoError(t, err)
	return data, evidence.ProducerId(sha256.Sum256(key.Marshal()))
}

func TestPortableCastVerifiesFrozenNativeGoldenWithIndependentTrust(t *testing.T) {
	data, expected := portableCastVector(t)
	result, err := VerifyCast(bytes.NewReader(data), CastVerifyOptions{ExpectedProducerId: expected})
	require.NoError(t, err)
	require.True(t, result.Trusted)
	require.Equal(t, expected, result.Metadata.ProducerId)
	require.Equal(t, CastStatusCompleted, result.Result.Status)
	require.EqualValues(t, 4, result.EventCount)
	require.EqualValues(t, 1, result.OutputEvents)
	require.EqualValues(t, 1, result.ResizeEvents)
	require.EqualValues(t, 1, result.MarkerEvents)
	require.NotNil(t, result.ExitStatus)
	require.Zero(t, *result.ExitStatus)
	_, err = VerifyCast(bytes.NewReader(data), CastVerifyOptions{})
	require.Error(t, err)
	untrusted, err := VerifyCast(bytes.NewReader(data), CastVerifyOptions{AllowUntrusted: true})
	require.NoError(t, err)
	require.False(t, untrusted.Trusted)
	wrong := expected
	wrong[0] ^= 1
	result, err = VerifyCast(bytes.NewReader(data), CastVerifyOptions{ExpectedProducerId: wrong})
	require.Error(t, err)
	require.Nil(t, result)
}

func TestPortableCastNeverReturnsPartialVerificationForMalformedEvidence(t *testing.T) {
	data, expected := portableCastVector(t)
	for _, bad := range [][]byte{
		data[:len(data)-16], data[:len(data)/2], append(bytes.Clone(data), []byte("# trailing\n")...),
		bytes.Replace(data, []byte("production"), []byte("forged"), 1),
		bytes.Replace(data, []byte(`[0.248,"o"`), []byte(`[0.248,"i"`), 1),
		bytes.Replace(data, []byte(`"version":3`), []byte(`"version":3,"version":3`), 1),
	} {
		require.False(t, bytes.Equal(data, bad), "negative fixture mutation must change input")
		result, err := VerifyCast(bytes.NewReader(bad), CastVerifyOptions{ExpectedProducerId: expected})
		require.Error(t, err)
		require.Nil(t, result)
	}
	result, err := VerifyCast(bytes.NewReader(data), CastVerifyOptions{ExpectedProducerId: expected, MaximumBytes: int64(len(data) - 1)})
	require.Error(t, err)
	require.Nil(t, result)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err = VerifyCast(bytes.NewReader(data), CastVerifyOptions{ExpectedProducerId: expected, Context: ctx})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, result)
}

type cancelCastReader struct {
	reader io.Reader
	cancel context.CancelFunc
}

func (this *cancelCastReader) Read(data []byte) (int, error) {
	n, err := this.reader.Read(data)
	this.cancel()
	return n, err
}

func TestPortableCastCancellationAndIdentifierDistinctionArePreserved(t *testing.T) {
	data, expected := portableCastVector(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result, err := VerifyCast(&cancelCastReader{bytes.NewReader(data), cancel}, CastVerifyOptions{Context: ctx, ExpectedProducerId: expected})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, result)
	var connection connectionid.Id
	connection[0] = 1
	session := sessionid.Id(connection)
	require.False(t, connection.IsEqualTo(session))
	require.False(t, session.IsEqualTo(connection), "portable IDs must not erase the session/connection boundary")
	connectionJSON, err := json.Marshal(connection)
	require.NoError(t, err)
	sessionJSON, err := json.Marshal(session)
	require.NoError(t, err)
	require.Equal(t, connectionJSON, sessionJSON)
	require.Error(t, ValidateMetadata(CastHeader{Timestamp: 1}, CastMetadata{}))
}

func TestPortableCastCodecsRetainStrictUnicodeAndShapeRules(t *testing.T) {
	_, _, _, err := DecodeEvent([]byte(`[0.001,"o","\ud800"]`))
	require.Error(t, err)
	_, _, data, err := DecodeEvent([]byte(`[0.001,"o","\ud83d\ude00"]`))
	require.NoError(t, err)
	require.Equal(t, "😀", data)
	var header CastHeader
	require.Error(t, DecodeHeader([]byte(`{"version":3,"term":{"cols":80,"rows":24},"timestamp":1,"version":3}`), &header))
	require.Error(t, RejectDuplicateJSONFields([]byte(`{"a":1,"a":2}`)))
	require.Error(t, ValidateResizeEvent("65536x24"))
	require.NoError(t, ValidateResizeEvent("65535x65535"))
	require.Equal(t, `"a\u2028b"`, string(MarshalEventString("a\u2028b")))
	require.Error(t, ValidateHeader(CastHeader{Version: CastVersion, Timestamp: 1, Terminal: CastTerminal{Columns: 1, Rows: 1, Type: strings.Repeat("x", 256)}}))
}
