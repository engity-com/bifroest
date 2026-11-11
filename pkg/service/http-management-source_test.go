package service

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/engity-com/bifroest/pkg/management/wire"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/stretchr/testify/require"
)

func TestRecordingSourceRejectsTheActualFileSizeBeforeContentVerification(t *testing.T) {
	svc, _, _ := executionTestFixture(t, nil)
	id := catalogRecording(t, svc, "default", 1)
	ctx := context.WithValue(t.Context(), managementArtifactLimitKey{}, int64(1))
	var output bytes.Buffer
	err := svc.writeManagementRecording(ctx, "default", id, &output)
	require.ErrorIs(t, err, recording.ErrCatalogVerificationBudget)
	require.Empty(t, output.Bytes())
}

func TestRecordingSourceCreditIsBoundedAndCannotBeReplayedOrSkipped(t *testing.T) {
	gate := &webRecordingSourceGate{next: make(chan struct{}, 1)}
	require.False(t, gate.advance(1))
	gate.ready(1)
	require.False(t, gate.advance(2))
	require.True(t, gate.advance(1))
	require.False(t, gate.advance(1))
	require.NoError(t, gate.wait(t.Context()))
	gate.ready(2)
	require.False(t, gate.advance(1))
	require.True(t, gate.advance(2))
	require.NoError(t, gate.wait(t.Context()))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, gate.wait(ctx), context.Canceled)
}

func TestRecordingSourceCannotUseDirectHTTPOrAnUnboundResponse(t *testing.T) {
	service := &webService{}
	for _, extra := range []bool{false, true} {
		request := httptest.NewRequest(http.MethodPost, webAPI+"management/artifacts/recordings", nil)
		if extra {
			request = request.WithContext(context.WithValue(request.Context(), webManagementContextKey{}, &webManagementChannel{}))
		}
		output := httptest.NewRecorder()
		service.handleManagementRecordingSource(output, request, webScope{}, map[string]string{"slug": "admin", "auditlog": "default"})
		require.Equal(t, http.StatusBadRequest, output.Code)
	}
}

func TestRecordingSourceRejectsPrivateErrorBodiesAndOversizedImagesBeforeWriting(t *testing.T) {
	entry := &webRecordingSourceEntry{header: make(http.Header)}
	entry.WriteHeader(http.StatusForbidden)
	n, err := entry.Write([]byte("must-not-be-emitted"))
	require.Zero(t, n)
	require.Error(t, err)
	require.True(t, entry.failed)
	entry = &webRecordingSourceEntry{status: http.StatusOK, written: webRecordingSourceImageBytes}
	n, err = entry.Write([]byte{1})
	require.Zero(t, n)
	require.True(t, errors.Is(err, wire.ErrArtifactLimit))
	require.True(t, entry.failed)
}
