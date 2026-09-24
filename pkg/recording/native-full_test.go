package recording

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

func TestNativeRecordingFullVerifyAndExportBeforeOutput(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "clear"
		if encrypted {
			name = "age"
		}
		t.Run(name, func(t *testing.T) {
			identity, castHeader, metadata := castTestValues(t, true)
			var recipient *bfcrypto.AgeSshRecipient
			var identities *bfcrypto.AgeSshIdentities
			if encrypted {
				recipient, identities = newBECastTestEncryption(t)
			}
			var container bytes.Buffer
			writer, err := NewNativeRecordingWriter(&container, identity, recipient, castHeader, metadata, 0, NativeRecordingWriterLimits{})
			require.NoError(t, err)
			require.NoError(t, writer.WriteOutput(248*time.Millisecond, OutputStreamTerminal, []byte("Welcome")))
			_, err = writer.Checkpoint()
			require.NoError(t, err)
			exit := uint32(0)
			_, err = writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &exit)
			require.NoError(t, err)
			original := bytes.Clone(container.Bytes())
			expected, _ := nativeCastTest(t, writer.signer)
			options := NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()}
			verification, err := VerifyNativeRecordingFull(bytes.NewReader(original), int64(len(original)), identities, options)
			require.NoError(t, err)
			require.Equal(t, uint64(len(expected)), verification.Seal.CastBytes)
			var export bytes.Buffer
			verification, err = ExportNativeRecordingCast(bytes.NewReader(original), int64(len(original)), identities, &export, options)
			require.NoError(t, err)
			require.True(t, verification.Trusted)
			require.Equal(t, expected, export.Bytes())

			invalid := bytes.Clone(original)
			invalid[len(invalid)/2] ^= 1
			var denied bytes.Buffer
			_, _ = denied.WriteString("unchanged")
			_, err = ExportNativeRecordingCast(bytes.NewReader(invalid), int64(len(invalid)), identities, &denied, options)
			require.Error(t, err)
			require.Equal(t, "unchanged", denied.String())
			wrong := options
			wrong.ExpectedProducerId[0] ^= 1
			_, err = ExportNativeRecordingCast(bytes.NewReader(original), int64(len(original)), identities, &denied, wrong)
			require.Error(t, err)
			require.Equal(t, "unchanged", denied.String())
			if encrypted {
				_, err = ExportNativeRecordingCast(bytes.NewReader(original), int64(len(original)), nil, &denied, options)
				require.Error(t, err)
				require.Equal(t, "unchanged", denied.String())
				_, wrongIdentity := newBECastTestEncryptionWithByte(t, 0x97)
				_, err = ExportNativeRecordingCast(bytes.NewReader(original), int64(len(original)), wrongIdentity, &denied, options)
				require.Error(t, err)
				require.Equal(t, "unchanged", denied.String())
			}
			_, err = ExportNativeRecordingCast(bytes.NewReader(original), int64(len(original)), identities, nil, options)
			require.Error(t, err)
		})
	}
}

func TestNativeFullVerifyRejectsForgedCastByteCountBeforeExport(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var output bytes.Buffer
	writer, err := NewNativeRecordingWriter(&output, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{})
	require.NoError(t, err)
	exit := uint32(0)
	_, err = writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &exit)
	require.NoError(t, err)
	original := bytes.NewReader(output.Bytes())
	_, offset, _, err := nativeformat.ReadUnitAt(original, int64(len(nativeformat.RecordingMagic)), int64(output.Len()), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	unit, next, _, err := nativeformat.ReadUnitAt(original, offset, int64(output.Len()), nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	tooLarge := uint64(1 << 20)
	chunk.CastBytes = &tooLarge
	payload, err := writer.signer.Chunk(chunk)
	require.NoError(t, err)
	frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	prefix := append(bytes.Clone(output.Bytes()[:offset]), frame...)
	sealUnit, _, _, err := nativeformat.ReadUnitAt(original, next, int64(output.Len()), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	seal, err := nativeformat.Unmarshal[nativeRecordingSeal](sealUnit.Payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	seal.CastBytes = tooLarge
	seal.LastUnitHash = nativeRecordingHash(nativeRecordingUnitDomain, frame)
	seal.ContentHash = nativeRecordingHash(nativeRecordingContentDomain, prefix)
	payload, err = writer.signer.Seal(seal, metadata.RecordingId)
	require.NoError(t, err)
	sealFrame, err := nativeformat.EncodeUnit(nativeformat.SealUnit, payload, nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	oversized := append(prefix, sealFrame...)
	options := NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()}
	_, err = VerifyNativeRecordingOuter(bytes.NewReader(oversized), int64(len(oversized)), options)
	require.NoError(t, err, "outer verification does not attest decrypted Cast size")
	var denied bytes.Buffer
	_, err = ExportNativeRecordingCast(bytes.NewReader(oversized), int64(len(oversized)), nil, &denied, options)
	require.ErrorContains(t, err, "byte count differs from seal")
	require.Zero(t, denied.Len())
}

func TestNativeFullVerifyStreamsCastAboveFormer16MiBLimit(t *testing.T) {
	identity, header, metadata := castTestValues(t, true)
	var container bytes.Buffer
	writer, err := NewNativeRecordingWriter(&container, identity, nil, header, metadata, 0, NativeRecordingWriterLimits{})
	require.NoError(t, err)
	data := bytes.Repeat([]byte("output\n"), (17<<20)/7+1)
	require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamTerminal, data))
	exit := uint32(0)
	result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}
	summary, err := writer.Seal(time.Second, result, &exit)
	require.NoError(t, err)
	require.Greater(t, summary.CastBytes, uint64(16<<20))
	var expectedHash = sha256.New()
	cast, err := NewCastWriter(expectedHash, identity, header, metadata)
	require.NoError(t, err)
	reader := bytes.NewReader(container.Bytes())
	_, offset, _, err := nativeformat.ReadUnitAt(reader, int64(len(nativeformat.RecordingMagic)), int64(container.Len()), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	for index := uint64(0); index < summary.ChunkCount; index++ {
		unit, next, tail, err := nativeformat.ReadUnitAt(reader, offset, int64(container.Len()), nativeformat.MaxRecordingChunkPayload)
		require.NoError(t, err)
		require.False(t, tail)
		chunk, err := nativeformat.Unmarshal[nativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
		require.NoError(t, err)
		decoded, err := nativeformat.DecodeStoredPayload(chunk.StoredPayload, nil, "", nativeRecordingPayloadLimits)
		require.NoError(t, err)
		events, err := decodeNativeRecordingEvents(decoded)
		require.NoError(t, err)
		for _, event := range events {
			switch event.Kind {
			case NativeEventSetup:
				require.Equal(t, header, event.Header)
			case NativeEventOutput:
				require.NoError(t, cast.WriteOutput(event.Elapsed, event.Stream, event.Data))
			case NativeEventPaddingCheckpoint:
				_, err = padCastForSha256Checkpoint(cast)
				require.NoError(t, err)
			case NativeEventResult:
				_, err = cast.Seal(event.Elapsed, event.Result, event.ExitStatus)
				require.NoError(t, err)
			default:
				t.Fatalf("unexpected event kind %d", event.Kind)
			}
		}
		offset = next
	}
	options := NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()}
	verification, err := VerifyNativeRecordingFull(bytes.NewReader(container.Bytes()), int64(container.Len()), nil, options)
	require.NoError(t, err)
	require.Equal(t, summary.CastBytes, verification.Seal.CastBytes)
	exportHash := sha256.New()
	_, err = ExportNativeRecordingCast(bytes.NewReader(container.Bytes()), int64(container.Len()), nil, exportHash, options)
	require.NoError(t, err)
	require.Equal(t, expectedHash.Sum(nil), exportHash.Sum(nil))
}
