package recording

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestBECastHeadCanonicalRoundTrip(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	var output bytes.Buffer
	writer, err := NewBECastWriter(&output, identity, recipient, header, metadata, 0)
	require.NoError(t, err)
	head, err := writer.Checkpoint()
	require.NoError(t, err)
	payload, err := encodeBECastHead(head)
	require.NoError(t, err)
	decoded, err := decodeBECastHead(payload)
	require.NoError(t, err)
	require.Equal(t, head, decoded)
	require.NoError(t, audit.VerifySessionRecordingBECastHead(identity.PublicKey(), decoded))
	require.Contains(t, string(payload), `"schema":"`+castBECastHeadSchema+`"`)
	require.Contains(t, string(payload), `"castState":1`)
	require.Contains(t, string(payload), `"startedAtUnixSeconds":`)
	require.Contains(t, string(payload), `"startedAtNanoseconds":`)
	require.LessOrEqual(t, len(payload), maximumCastBECastHeadBytes)

	nonCanonical := []byte(strings.Replace(string(payload), head.LastUnitHash.String(), strings.ToUpper(head.LastUnitHash.String()), 1))
	_, err = decodeBECastHead(nonCanonical)
	require.ErrorContains(t, err, "canonically")
	require.True(t, bferrors.System.IsErr(err))
}

func TestBECastHeadDecodeRejectsSchemaSizeAndSignatureTampering(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	recipient, _ := newBECastTestEncryption(t)
	var output bytes.Buffer
	writer, err := NewBECastWriter(&output, identity, recipient, header, metadata, 0)
	require.NoError(t, err)
	head, err := writer.Checkpoint()
	require.NoError(t, err)
	payload, err := encodeBECastHead(head)
	require.NoError(t, err)

	wrongSchema := bytes.Replace(payload, []byte(castBECastHeadSchema), []byte("bifroest.session-recording-becast-head/v2"), 1)
	_, err = decodeBECastHead(wrongSchema)
	require.ErrorContains(t, err, "unsupported BECast head schema")
	require.True(t, bferrors.System.IsErr(err))

	_, err = decodeBECastHead(make([]byte, maximumCastBECastHeadBytes+1))
	require.ErrorContains(t, err, "size is outside")
	require.True(t, bferrors.System.IsErr(err))

	head.Signature[0] ^= 1
	payload, err = encodeBECastHead(head)
	require.NoError(t, err)
	decoded, err := decodeBECastHead(payload)
	require.NoError(t, err)
	err = audit.VerifySessionRecordingBECastHead(identity.PublicKey(), decoded)
	require.ErrorContains(t, err, "illegal session recording signature")
	require.True(t, bferrors.System.IsErr(err))
}
