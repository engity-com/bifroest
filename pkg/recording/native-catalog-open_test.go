package recording

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

type catalogBudgetNoRead struct{ t *testing.T }

func (reader catalogBudgetNoRead) ReadAt([]byte, int64) (int, error) {
	reader.t.Fatal("an oversized actual container must fail before any artifact read")
	return 0, nil
}

func TestOpenCatalogSealedStatGatePrecedesAllArtifactReads(t *testing.T) {
	identity, _, _ := castTestValues(t, true)
	repo, err := NewLocalNativeRecordingRepository(t.Context(), t.TempDir(), identity, nil, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repo.Close()) })
	_, _, err = repo.verifyCatalogFile(t.Context(), catalogBudgetNoRead{t}, 65, CatalogVerifyLimits{MaximumContainerBytes: 64, MaximumCastBytes: 64})
	require.ErrorIs(t, err, ErrCatalogVerificationBudget)
	for _, limits := range []CatalogVerifyLimits{
		{}, {MaximumContainerBytes: 1}, {MaximumCastBytes: 1},
		{MaximumContainerBytes: MaximumNativeCatalogBytes + 1, MaximumCastBytes: 1},
	} {
		_, err := repo.OpenCatalogSealed(t.Context(), sealedPageTestID(1), limits)
		require.ErrorIs(t, err, ErrCatalogVerificationBudget)
	}
}

func TestOpenCatalogSealedBoundsTheActuallyReopenedArtifactAndKeepsRepoDefaults(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			identity, header, metadata := castTestValues(t, false)
			var recipient *bfcrypto.AgeSshRecipient
			if encrypted {
				recipient, _ = newBECastTestEncryption(t)
			}
			root := t.TempDir()
			repo, err := NewLocalNativeRecordingRepository(t.Context(), root, identity, recipient, NativeRecordingVerifyOptions{}, localRepositoryTestOptions)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, repo.Close()) })
			active, err := repo.CreateActive(t.Context(), header, metadata, DefaultNativeRecordingChunkTarget)
			require.NoError(t, err)
			_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
			require.NoError(t, err)
			selected, err := repo.CatalogMetadata(t.Context())
			require.NoError(t, err)
			require.Len(t, selected, 1)
			limits := CatalogVerifyLimits{MaximumContainerBytes: selected[0].Bytes, MaximumCastBytes: MaximumNativeCatalogBytes}
			artifact, err := repo.OpenCatalogSealed(t.Context(), metadata.RecordingId, limits)
			require.NoError(t, err)
			require.Equal(t, selected[0], artifact.Summary())
			require.GreaterOrEqual(t, artifact.VerificationCastBytes(), selected[0].CastBytes)
			require.NoError(t, artifact.Close())
			// Repository creation already writes a checkpoint. At one byte of
			// remaining allowance its canonical Cast commitment exceeds the bound
			// before the continuation validator or any payload decompression.
			artifact, err = repo.OpenCatalogSealed(t.Context(), metadata.RecordingId, CatalogVerifyLimits{
				MaximumContainerBytes: selected[0].Bytes, MaximumCastBytes: 1,
			})
			require.ErrorIs(t, err, cast.ErrNativeCatalogCastBudget)
			require.Nil(t, artifact)
			ordinary, err := repo.OpenSealed(t.Context(), metadata.RecordingId)
			require.NoError(t, err, "a catalog allowance must not mutate normal repository verification defaults")
			require.NoError(t, ordinary.Close())
			format := repo.repository.format.(*localNativeRecordingFormat)
			require.Zero(t, format.options.MaximumContainerBytes)
			require.Zero(t, format.options.MaximumCastBytes)
			path := filepath.Join(root, localSealedDirectory, metadata.RecordingId.String()+repo.repository.format.sealedSuffix())
			original, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, append(original, 0), 0600))
			t.Cleanup(func() { require.NoError(t, os.WriteFile(path, original, 0600)) })
			artifact, err = repo.OpenCatalogSealed(t.Context(), metadata.RecordingId, limits)
			require.ErrorIs(t, err, ErrCatalogVerificationBudget, "growth after cached selection must fail at the actual fstat size gate")
			require.Nil(t, artifact)
		})
	}
}

func TestNativeCatalogCanonicalAndDecodedBudgetsAreIndependent(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			identity, header, metadata := castTestValues(t, false)
			var recipient *bfcrypto.AgeSshRecipient
			if encrypted {
				recipient, _ = newBECastTestEncryption(t)
			}
			// Unlike repository CreateActive, this writer has no initial
			// checkpoint: the fixture deliberately consists of one final chunk.
			var container bytes.Buffer
			writer, err := NewNativeRecordingWriter(&container, identity, recipient, header, metadata, DefaultNativeRecordingChunkTarget, NativeRecordingWriterLimits{})
			require.NoError(t, err)
			data := bytes.Repeat([]byte{'"', '\\', '\n', '\t', 0}, 256)
			require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamStdout, data))
			summary, err := writer.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
			require.NoError(t, err)
			require.EqualValues(t, 1, summary.ChunkCount)
			content := container.Bytes()
			var decodedBytes uint64
			for offset := int64(len(nativeformat.RecordingMagic)); offset < int64(len(content)); {
				unit, next, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(content), offset, int64(len(content)), nativeformat.MaxRecordingChunkPayload)
				require.NoError(t, err)
				require.False(t, tail)
				if unit.Type == nativeformat.ContentUnit {
					chunk, err := nativeformat.Unmarshal[NativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
					require.NoError(t, err)
					decodedBytes += uint64(chunk.DecodedLength)
				}
				offset = next
			}
			require.Positive(t, decodedBytes)
			require.Greater(t, summary.CastBytes, decodedBytes, "JSON escaping makes canonical Cast bytes independently larger than decoded CBOR")
			seenMetadata := false
			options := NativeRecordingVerifyOptions{
				ExpectedProducerId: identity.ProducerId(), MaximumContainerBytes: int64(len(content)), MaximumCastBytes: int64(summary.CastBytes),
				VerifiedMetadata: func(CastMetadata) { seenMetadata = true },
			}
			verified, used, err := cast.VerifyNativeRecordingCatalog(bytes.NewReader(content), int64(len(content)), encrypted, decodedBytes-1, options)
			require.ErrorIs(t, err, cast.ErrNativeCatalogDecodedBudget, "only the decoded bound is exceeded; the canonical bound remains exact")
			require.Nil(t, verified)
			require.Zero(t, used)
			require.False(t, seenMetadata)
			canonicalLimited := options
			canonicalLimited.MaximumCastBytes--
			verified, used, err = cast.VerifyNativeRecordingCatalog(bytes.NewReader(content), int64(len(content)), encrypted, decodedBytes, canonicalLimited)
			require.ErrorIs(t, err, cast.ErrNativeCatalogCastBudget, "only the canonical bound is exceeded; decoded bytes fit exactly")
			require.Nil(t, verified)
			require.Zero(t, used)
			require.False(t, seenMetadata)
			verified, used, err = cast.VerifyNativeRecordingCatalog(bytes.NewReader(content), int64(len(content)), encrypted, decodedBytes, options)
			require.NoError(t, err, "both exact independent bounds permit the genuine artifact")
			require.NotNil(t, verified)
			require.Equal(t, decodedBytes, used)
			require.Equal(t, !encrypted, seenMetadata, "encrypted inspection still publishes no private metadata")
		})
	}
}

type catalogChangeAfterOuterHash struct {
	before, after []byte
	changed       bool
}

func (reader *catalogChangeAfterOuterHash) ReadAt(target []byte, offset int64) (int, error) {
	data := reader.before
	if reader.changed {
		data = reader.after
	}
	n, err := bytes.NewReader(data).ReadAt(target, offset)
	if !reader.changed && offset == 0 && len(target) > len(nativeformat.RecordingMagic) {
		reader.changed = true // Return old bytes for the completed outer content hash.
	}
	return n, err
}

func TestNativeCatalogBudgetAlsoGuardsActualFullVerificationPass(t *testing.T) {
	identity, header, metadata := castTestValues(t, false)
	var original bytes.Buffer
	writer, err := NewNativeRecordingWriter(&original, identity, nil, header, metadata, DefaultNativeRecordingChunkTarget, NativeRecordingWriterLimits{})
	require.NoError(t, err)
	data := make([]byte, 4096)
	for index := range data {
		data[index] = byte(index)
	}
	require.NoError(t, writer.WriteOutput(time.Millisecond, OutputStreamStdout, data))
	exit := uint32(0)
	result := CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}
	summary, err := writer.Seal(time.Second, result, &exit)
	require.NoError(t, err)
	require.EqualValues(t, 1, summary.ChunkCount)
	before := original.Bytes()
	_, headerEnd, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(before), int64(len(nativeformat.RecordingMagic)), int64(len(before)), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	require.False(t, tail)
	unit, chunkEnd, tail, err := nativeformat.ReadUnitAt(bytes.NewReader(before), headerEnd, int64(len(before)), nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	require.False(t, tail)
	chunk, err := nativeformat.Unmarshal[NativeRecordingChunk](unit.Payload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	decoded, err := EncodeNativeRecordingEvents([]NativeCastEvent{
		{Kind: NativeEventSetup, Header: header, Metadata: metadata},
		{Kind: NativeEventOutput, Elapsed: time.Millisecond, Stream: OutputStreamStdout, Data: bytes.Repeat([]byte("x"), 32768)},
		{Kind: NativeEventResult, Elapsed: time.Second, Result: result, ExitStatus: &exit},
	})
	require.NoError(t, err)
	chunk.StoredPayload, err = nativeformat.EncodeStoredPayload(decoded, nil, nativeRecordingPayloadLimits)
	require.NoError(t, err)
	chunk.DecodedLength = uint32(len(decoded))
	chunk.StoredHash = sha256.Sum256(chunk.StoredPayload)
	signer, err := NewNativeRecordingSigner(identity)
	require.NoError(t, err)
	payload, err := signer.Chunk(chunk)
	require.NoError(t, err)
	frame, err := nativeformat.EncodeUnit(nativeformat.ContentUnit, payload, nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	after := append(bytes.Clone(before[:headerEnd]), frame...)
	after = append(after, before[chunkEnd:]...)
	require.LessOrEqual(t, len(after), len(before), "replacement fits the same bounded ReaderAt snapshot size")
	reader := &catalogChangeAfterOuterHash{before: before, after: after}
	verified, _, err := cast.VerifyNativeRecordingCatalog(reader, int64(len(before)), false, 8192, NativeRecordingVerifyOptions{ExpectedProducerId: identity.ProducerId()})
	require.True(t, reader.changed)
	require.ErrorIs(t, err, cast.ErrNativeCatalogDecodedBudget, "a changed signed chunk must not expand under the larger defaults in the second pass")
	require.Nil(t, verified)
}
