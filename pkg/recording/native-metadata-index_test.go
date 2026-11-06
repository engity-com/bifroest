package recording

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/engity-com/bifroest/pkg/recording/cast"
	"github.com/stretchr/testify/require"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type metadataRangeReader struct {
	data                []byte
	firstEnd, tailStart int64
	reads               int64
}

func (r *metadataRangeReader) ReadAt(data []byte, offset int64) (int, error) {
	if offset < r.tailStart && offset+int64(len(data)) > r.firstEnd {
		return 0, io.ErrUnexpectedEOF
	}
	r.reads += int64(len(data))
	return bytes.NewReader(r.data).ReadAt(data, offset)
}
func largeMetadataRecording(t *testing.T) (*LocalNativeRecordingRepository, string, CastMetadata) {
	t.Helper()
	repo, root := newCatalogWarmupFixture(t, false)
	_, header, metadata := castTestValues(t, true)
	metadata.RecordingId = sealedPageTestID(3)
	active, err := repo.CreateActive(t.Context(), header, metadata, 256<<10)
	require.NoError(t, err)
	payload := make([]byte, 64<<10)
	_, err = rand.New(rand.NewSource(7)).Read(payload)
	require.NoError(t, err)
	for index := 1; index <= 40; index++ {
		require.NoError(t, active.WriteOutput(time.Duration(index)*time.Millisecond, OutputStreamTerminal, payload))
	}
	_, err = active.Seal(time.Second, CastResult{Status: CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, sealedArtifactUint32(0))
	require.NoError(t, err)
	return repo, filepath.Join(root, "sealed", metadata.RecordingId.String()+".bcast"), metadata
}
func TestRecordingMetadataNeverReadsTheInterveningContents(t *testing.T) {
	_, path, metadata := largeMetadataRecording(t)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	_, next, _, err := nativeformat.ReadUnitAt(bytes.NewReader(data), int64(len(nativeformat.RecordingMagic)), int64(len(data)), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	_, firstEnd, _, err := nativeformat.ReadUnitAt(bytes.NewReader(data), next, int64(len(data)), nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	reader := &metadataRangeReader{data: data, firstEnd: firstEnd, tailStart: int64(len(data)) - (nativeformat.MaxMetadataPayload + 18)}
	require.Greater(t, reader.tailStart, reader.firstEnd)
	value, err := cast.ReadNativeRecordingMetadata(reader, int64(len(data)), cast.NativeRecordingVerifyOptions{ExpectedProducerId: metadata.ProducerId, Context: t.Context()})
	require.NoError(t, err)
	require.NotNil(t, value.Metadata)
	require.Equal(t, metadata.Flow, value.Metadata.Flow)
	require.Less(t, reader.reads, int64(len(data)))
	_, err = cast.VerifyNativeRecordingOuter(reader, int64(len(data)), cast.NativeRecordingVerifyOptions{ExpectedProducerId: metadata.ProducerId, Context: t.Context()})
	require.Error(t, err, "negative control: actual content verification must read the protected middle")
}
func TestRecordingMetadataIndexIsNotFullVerificationAndExplicitVerificationBypassesCache(t *testing.T) {
	repo, path, _ := largeMetadataRecording(t)
	stats := &CatalogReadStats{}
	ctx := WithCatalogReadStats(t.Context(), stats)
	consume := func(NativeRecordingSummary) error { return nil }
	require.NoError(t, repo.WalkMetadata(ctx, consume, nil))
	require.EqualValues(t, 3, stats.MetadataReads.Load())
	require.Zero(t, stats.ContentReads.Load())
	require.Empty(t, repo.catalog.entries)
	require.NoError(t, repo.WalkMetadata(ctx, consume, nil))
	require.EqualValues(t, 3, stats.MetadataReads.Load(), "unchanged metadata is reused without rereading recording setup chunks")
	require.NoError(t, repo.VerifyCatalog(ctx, consume, nil))
	require.EqualValues(t, 3, stats.ContentReads.Load())
	require.NoError(t, repo.VerifyCatalog(ctx, consume, nil))
	require.EqualValues(t, 6, stats.ContentReads.Load(), "an explicit verify-all is not a stamp-only cached success")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	_, offset, _, err := nativeformat.ReadUnitAt(bytes.NewReader(data), int64(len(nativeformat.RecordingMagic)), int64(len(data)), nativeformat.MaxMetadataPayload)
	require.NoError(t, err)
	_, offset, _, err = nativeformat.ReadUnitAt(bytes.NewReader(data), offset, int64(len(data)), nativeformat.MaxRecordingChunkPayload)
	require.NoError(t, err)
	length := int64(binary.BigEndian.Uint32(data[offset+1 : offset+5]))
	require.Greater(t, length, int64(32))
	data[offset+6+length/2] ^= 1
	require.NoError(t, os.WriteFile(path, data, 0600))
	require.NoError(t, repo.WalkMetadata(ctx, consume, nil), "an unselected body is not implicitly fully verified by a metadata query")
	require.Error(t, repo.VerifyCatalog(context.Background(), consume, nil), "explicit verification must still reject corrupt contents")
}
