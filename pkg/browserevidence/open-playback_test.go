package browserevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/engity-com/bifroest/pkg/recording/cast"
	"github.com/stretchr/testify/require"
)

func TestOpenPlaybackSeparatesDecodingDecryptionAndSignatureVerification(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "bcast-v1.bcast"
		if encrypted {
			name = "becast-v1.becast"
		}
		data := asset(t, "recording-format-vectors/native-v1", name)
		original := bytes.Clone(data)
		opened, err := OpenPlayback(t.Context(), data, recordingID, nil, nil)
		require.NoError(t, err)
		if encrypted {
			require.True(t, opened.Info.RequiresKey)
			require.Nil(t, opened.Playback)
			require.Empty(t, opened.Frames)
			opened, err = OpenPlayback(t.Context(), data, recordingID, recipientPrivate(t, "secret"), []byte("secret"))
			require.NoError(t, err)
			require.Equal(t, "authenticated", opened.Info.Decryption)
		} else {
			require.Equal(t, "not-encrypted", opened.Info.Decryption)
		}
		require.NotNil(t, opened.Playback)
		require.Equal(t, "not-checked", opened.Playback.Trust)
		require.NotEmpty(t, opened.Frames)
		expected, err := PreparePlayback(t.Context(), asset(t, "recording-format-vectors/native-v1", "bcast-v1.cast"), recordingID, producerPin, false)
		require.NoError(t, err)
		require.Equal(t, expected.Frames, opened.Frames)
		require.Equal(t, original, data)
	}
}

func TestOpenPlaybackDoesNotVerifySignaturesButExplicitVerificationStillFails(t *testing.T) {
	data := asset(t, "recording-format-vectors/native-v1", "bcast-v1.bcast")
	unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(data), int64(len(nativeformat.RecordingMagic)), int64(len(data)), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.False(t, tail)
	header, err := nativeformat.Unmarshal[cast.NativeRecordingHeader](unit.Payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	header.Signature[0] ^= 1
	payload, err := nativeformat.Marshal(header, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	encoded, err := nativeformat.EncodeUnit(nativeformat.HeaderUnit, payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	changed := append([]byte(nativeformat.RecordingMagic), encoded...)
	changed = append(changed, data[next:]...)
	opened, err := OpenPlayback(t.Context(), changed, recordingID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "not-checked", opened.Playback.Trust)
	verified, err := Verify(t.Context(), protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "vector", ID: recordingID}, []File{{Name: "recording", Data: changed}}, Options{Producer: producerPin, Level: "outer"}, nil, nil)
	require.ErrorIs(t, err, ErrVerification)
	require.Nil(t, verified)
}

func TestOpenPlaybackRejectsWrongKeysTruncationAndSelectionWithoutPartialOutput(t *testing.T) {
	data := asset(t, "recording-format-vectors/native-v1", "becast-v1.becast")
	for _, scenario := range []string{"password", "truncated", "id", "ciphertext"} {
		t.Run(scenario, func(t *testing.T) {
			image := bytes.Clone(data)
			id := recordingID
			password := []byte("secret")
			switch scenario {
			case "password":
				password = []byte("wrong")
			case "truncated":
				image = image[:len(image)-1]
			case "id":
				id = "6d05798f-b877-4191-8aa0-4576a30411ad"
			case "ciphertext":
				image[len(image)/2] ^= 1
			}
			opened, err := OpenPlayback(t.Context(), image, id, recipientPrivate(t, "secret"), password)
			require.Error(t, err)
			require.Nil(t, opened)
		})
	}
}

func TestOpenPlaybackAuthenticatesCiphertextEvenWhenContainerChecksumsAreValid(t *testing.T) {
	data := asset(t, "recording-format-vectors/native-v1", "becast-v1.becast")
	offset := int64(len(nativeformat.RecordingMagic))
	_, offset, _, err := nativeformat.ReadUnitAt(bytes.NewReader(data), offset, int64(len(data)), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	unit, next, _, err := nativeformat.ReadUnitAt(bytes.NewReader(data), offset, int64(len(data)), nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	require.Equal(t, nativeformat.ContentUnit, unit.Type)
	chunk, err := nativeformat.Unmarshal[cast.NativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	chunk.StoredPayload[len(chunk.StoredPayload)-1] ^= 1
	payload, err := nativeformat.Marshal(chunk, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	encoded, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	changed := append(bytes.Clone(data[:offset]), encoded...)
	changed = append(changed, data[next:]...)
	opened, err := OpenPlayback(t.Context(), changed, recordingID, recipientPrivate(t, ""), nil)
	require.Error(t, err)
	require.Nil(t, opened)
}

func TestOpenPlaybackLegacyGrammarAndCancellationDoNotDependOnSignatureValidity(t *testing.T) {
	data := asset(t, "recording-format-vectors/native-v1", "bcast-v1.cast")
	position := bytes.Index(data, []byte(cast.SignatureCommentPrefix))
	require.Positive(t, position)
	var signature evidence.SessionRecordingCastSignature
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(data[position+len(cast.SignatureCommentPrefix):]), &signature))
	signature.Signature[0] ^= 1
	encoded, err := json.Marshal(signature)
	require.NoError(t, err)
	unchecked := append(bytes.Clone(data[:position]), []byte(cast.SignatureCommentPrefix)...)
	unchecked = append(append(unchecked, encoded...), '\n')
	opened, err := OpenPlayback(t.Context(), unchecked, recordingID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "not-checked", opened.Playback.Trust)
	_, err = PreparePlayback(t.Context(), unchecked, recordingID, producerPin, false)
	require.Error(t, err)
	for _, image := range [][]byte{append(bytes.Clone(data), '\n'), data[:len(data)-10], bytes.Replace(data, []byte(`[0.248,"o"`), []byte(`[0.248,"i"`), 1)} {
		opened, err = OpenPlayback(t.Context(), image, recordingID, nil, nil)
		require.Error(t, err)
		require.Nil(t, opened)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	opened, err = OpenPlayback(ctx, data, recordingID, nil, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, opened)
}
