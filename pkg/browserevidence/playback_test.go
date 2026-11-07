package browserevidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

func TestBrowserPlaybackReverifiesFrozenLocalCastAndExactBinaryPlan(t *testing.T) {
	data := asset(t, "recording-format-vectors/native-v1", "bcast-v1.cast")
	before := bytes.Clone(data)
	prepared, err := PreparePlayback(t.Context(), data, recordingID, producerPin, false)
	require.NoError(t, err)
	require.Equal(t, data, before)
	require.Equal(t, "pinned", prepared.Metadata.Trust)
	require.EqualValues(t, 120, prepared.Metadata.Columns)
	require.EqualValues(t, 40, prepared.Metadata.Rows)
	require.EqualValues(t, 2, prepared.Metadata.Frames)
	require.EqualValues(t, 2_104_000, prepared.Metadata.DurationUs)
	require.EqualValues(t, 7, *prepared.Metadata.ExitStatus)
	reader := prepared.Frames
	require.EqualValues(t, 248_000, binary.LittleEndian.Uint64(reader[:8]))
	require.Zero(t, reader[8])
	require.EqualValues(t, 10, binary.LittleEndian.Uint32(reader[9:13]))
	require.Equal(t, []byte("Welcome\r\n\xff"), reader[13:23])
	reader = reader[23:]
	require.EqualValues(t, 1_001_000, binary.LittleEndian.Uint64(reader[:8]))
	require.EqualValues(t, 3, reader[8])
	require.EqualValues(t, 8, binary.LittleEndian.Uint32(reader[9:13]))
	require.EqualValues(t, 132, binary.LittleEndian.Uint32(reader[13:17]))
	require.EqualValues(t, 43, binary.LittleEndian.Uint32(reader[17:21]))
	require.Len(t, reader, 21)
	untrusted, err := PreparePlayback(t.Context(), data, recordingID, "", true)
	require.NoError(t, err)
	require.Equal(t, "untrusted", untrusted.Metadata.Trust)
	for _, scenario := range []string{"missing pin", "wrong pin", "wrong id", "truncated", "trailing", "tampered", "canceled"} {
		content, id, pin := bytes.Clone(data), recordingID, producerPin
		ctx, cancel := context.WithCancel(t.Context())
		switch scenario {
		case "missing pin":
			pin = ""
		case "wrong pin":
			pin = strings.Repeat("a", 64)
		case "wrong id":
			id = "6d05798f-b877-4191-8aa0-4576a30411ad"
		case "truncated":
			content = content[:len(content)-10]
		case "trailing":
			content = append(content, '\n')
		case "tampered":
			content[100] ^= 1
		case "canceled":
			cancel()
		}
		failed, err := PreparePlayback(ctx, content, id, pin, false)
		cancel()
		require.Error(t, err, scenario)
		require.Nil(t, failed)
	}
}

// The public frozen fixture seed signs real modified Casts offline in tests;
// neither a second verifier nor a native signing capability enters production.
func signPlaybackTestCast(t *testing.T, content []byte) []byte {
	t.Helper()
	position := bytes.Index(content, []byte(cast.SignatureCommentPrefix))
	require.Positive(t, position)
	var signature evidence.SessionRecordingCastSignature
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(content[position+len(cast.SignatureCommentPrefix):]), &signature))
	unsigned := bytes.Clone(content[:position])
	digest := sha256.New()
	_, _ = digest.Write([]byte(cast.ContentHashDomain))
	_, _ = digest.Write(unsigned)
	signature.Digest = cast.CastDigest(digest.Sum(nil)).String()
	message, err := evidence.SessionRecordingCastSignatureMessage(signature)
	require.NoError(t, err)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	signature.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(seed), message)
	payload, err := json.Marshal(signature)
	require.NoError(t, err)
	return append(append(append(unsigned, []byte(cast.SignatureCommentPrefix)...), payload...), '\n')
}

func TestBrowserPlaybackLimitsRejectValidEvidenceWithoutChangingNativeLimits(t *testing.T) {
	data := asset(t, "recording-format-vectors/native-v1", "bcast-v1.cast")
	for _, content := range [][]byte{
		bytes.Replace(data, []byte(`"cols":120`), []byte(`"cols":513`), 1),
		bytes.Replace(data, []byte(`"rows":40`), []byte(`"rows":257`), 1),
		bytes.Replace(data, []byte(`"132x43"`), []byte(`"512x256"`), 1),
		bytes.Replace(data, []byte(`[1.084,"x","7"]`), append(bytes.Repeat([]byte("[0,\"z\",\"\"]\n"), MaximumPlaybackEvents), []byte(`[1.084,"x","7"]`)...), 1),
	} {
		content = signPlaybackTestCast(t, content)
		var pin evidence.ProducerId
		require.NoError(t, pin.UnmarshalText([]byte(producerPin)))
		_, err := cast.VerifyCast(bytes.NewReader(content), cast.CastVerifyOptions{ExpectedProducerId: pin})
		require.NoError(t, err, "resource fixtures must remain genuinely valid native evidence")
		prepared, err := PreparePlayback(t.Context(), content, recordingID, producerPin, false)
		require.ErrorIs(t, err, ErrLimit)
		require.Nil(t, prepared)
	}
}

func TestBrowserPlaybackKeepsStderrBytesDistinctWithoutCreatingInputEvents(t *testing.T) {
	data := asset(t, "recording-format-vectors/native-v1", "bcast-v1.cast")
	data = bytes.Replace(data, []byte(`"pty":true`), []byte(`"pty":false`), 1)
	data = bytes.Replace(data, []byte(`"stream":"terminal"`), []byte(`"stream":"stderr"`), 1)
	data = bytes.Replace(data, []byte(`[0.753,"r","132x43"]`), []byte(`[0.753,"m","not-a-resize"]`), 1)
	data = signPlaybackTestCast(t, data)
	prepared, err := PreparePlayback(t.Context(), data, recordingID, producerPin, false)
	require.NoError(t, err)
	require.False(t, prepared.Metadata.Pty)
	require.EqualValues(t, 1, prepared.Metadata.Frames)
	require.EqualValues(t, 2, prepared.Frames[8])
	require.Equal(t, []byte("Welcome\r\n\xff"), prepared.Frames[13:])
	data = bytes.Replace(data, []byte(`[0.248,"o"`), []byte(`[0.248,"i"`), 1)
	data = signPlaybackTestCast(t, data)
	prepared, err = PreparePlayback(t.Context(), data, recordingID, producerPin, false)
	require.Error(t, err)
	require.Nil(t, prepared)
}
