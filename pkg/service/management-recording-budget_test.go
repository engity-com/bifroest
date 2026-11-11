package service

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/recording/cast"
)

func TestManagementRecordingReverificationUsesActualRemainingContainerBudget(t *testing.T) {
	svc, _, _, _ := managementWebFixture(t)
	id := catalogRecording(t, svc, "default", 1)
	repository := svc.recordingRepositories["default"].native
	selected, err := repository.OpenSealed(t.Context(), id)
	require.NoError(t, err)
	cached := selected.Summary()
	path := filepath.Join(svc.Configuration.Auditlogs[0].Recording.Directory, "sealed", selected.FileName())
	require.NoError(t, selected.Close())
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	// Grow only after selection. Checking/debiting the old summary alone would
	// let the actual larger descriptor enter ordinary full verification first.
	require.NoError(t, os.WriteFile(path, append(bytes.Clone(original), 0), 0600))
	t.Cleanup(func() { require.NoError(t, os.WriteFile(path, original, 0600)) })
	remainingContainer, remainingCast := cached.Bytes, uint64(recording.MaximumNativeCatalogBytes)
	row, err := reverifyManagementRecording(t.Context(), repository, cached, &remainingContainer, &remainingCast)
	require.ErrorIs(t, err, recording.ErrCatalogVerificationBudget)
	require.Zero(t, row)
	require.Equal(t, cached.Bytes, remainingContainer)
	require.EqualValues(t, recording.MaximumNativeCatalogBytes, remainingCast)
}

func TestManagementRecordingReverificationBoundsReplacementBeforeActualDecode(t *testing.T) {
	svc, _, _, _ := managementWebFixture(t)
	id := catalogRecording(t, svc, "default", 1)
	repository := svc.recordingRepositories["default"].native
	selected, err := repository.OpenSealed(t.Context(), id)
	require.NoError(t, err)
	cached := selected.Summary()
	inspection, err := recording.Inspect(selected, selected.Size(), recording.InspectOptions{ExpectedProducerId: selected.ProducerId()})
	require.NoError(t, err)
	require.NotNil(t, inspection.Metadata)
	metadata := *inspection.Metadata
	path := filepath.Join(svc.Configuration.Auditlogs[0].Recording.Directory, "sealed", selected.FileName())
	require.NoError(t, selected.Close())
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	var replacement bytes.Buffer
	writer, err := recording.NewNativeRecordingWriter(&replacement, svc.auditIdentities["default"], nil,
		recording.CastHeader{Version: recording.CastVersion, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: metadata.StartedAt.Unix()},
		metadata, recording.DefaultNativeRecordingChunkTarget, recording.NativeRecordingWriterLimits{})
	require.NoError(t, err)
	// Compressible replacement: physical size fits the container allowance, but
	// its final canonical Cast commitment exceeds the actual remaining allowance.
	output := bytes.Repeat([]byte("x"), int(cached.CastBytes)+4096)
	require.NoError(t, writer.WriteOutput(time.Millisecond, recording.OutputStreamStdout, output))
	exit := uint32(0)
	summary, err := writer.Seal(time.Second, recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: metadata.StartedAt.Add(time.Second)}, &exit)
	require.NoError(t, err)
	require.EqualValues(t, 1, summary.ChunkCount, "one final chunk exercises the pre-decode guard before final Cast-size/seal checks")
	require.NoError(t, os.WriteFile(path, replacement.Bytes(), 0600))
	t.Cleanup(func() { require.NoError(t, os.WriteFile(path, original, 0600)) })
	remainingContainer, remainingCast := uint64(recording.MaximumNativeCatalogBytes), cached.CastBytes
	row, err := reverifyManagementRecording(t.Context(), repository, cached, &remainingContainer, &remainingCast)
	require.ErrorIs(t, err, cast.ErrNativeCatalogCastBudget, "must reject the signed canonical commitment before decode, not merely at summary mismatch")
	require.Zero(t, row)
	require.EqualValues(t, recording.MaximumNativeCatalogBytes, remainingContainer)
	require.Equal(t, cached.CastBytes, remainingCast)
	ordinary, err := repository.OpenSealed(t.Context(), id)
	require.NoError(t, err, "negative control: the signed larger artifact remains valid under unchanged ordinary repository defaults")
	require.Equal(t, summary, ordinary.Summary())
	require.NoError(t, ordinary.Close())
}

func TestManagementRecordingReverificationDebitsActualSuccessfulCosts(t *testing.T) {
	svc, _, _, _ := managementWebFixture(t)
	id := catalogRecording(t, svc, "default", 1)
	repository := svc.recordingRepositories["default"].native
	limits := recording.CatalogVerifyLimits{MaximumContainerBytes: recording.MaximumNativeCatalogBytes, MaximumCastBytes: recording.MaximumNativeCatalogBytes}
	actual, err := repository.OpenCatalogSealed(t.Context(), id, limits)
	require.NoError(t, err)
	selected := actual.Summary()
	containerCost, castCost := uint64(actual.Size()), actual.VerificationCastBytes()
	require.NoError(t, actual.Close())
	remainingContainer, remainingCast := containerCost+1, castCost+1
	row, err := reverifyManagementRecording(t.Context(), repository, selected, &remainingContainer, &remainingCast)
	require.NoError(t, err)
	require.Equal(t, selected, row)
	require.EqualValues(t, 1, remainingContainer)
	require.EqualValues(t, 1, remainingCast)
	row, err = reverifyManagementRecording(t.Context(), repository, selected, &remainingContainer, &remainingCast)
	require.Error(t, err, "the next page item must not fall back to repository-wide limits")
	require.Zero(t, row)
	require.EqualValues(t, 1, remainingContainer)
	require.EqualValues(t, 1, remainingCast)
}
