package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
	"testing"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/stretchr/testify/require"
)

func TestManagementNotFoundNeverMasksMixedFinalAuditOrPolicyFailure(t *testing.T) {
	for _, err := range []error{session.ErrNoSuchSession, fmt.Errorf("lookup: %w", session.ErrNoSuchSession), &os.PathError{Op: "open", Path: "fixture", Err: syscall.ENOENT}, errors.Join(fs.ErrNotExist, session.ErrNoSuchSession)} {
		require.True(t, managementOnlyNotFound(managementEntityLookupError(err)))
	}
	for _, err := range []error{nil, context.Canceled, errManagementPolicy, errors.Join(session.ErrNoSuchSession, errors.New("final audit failure")), errors.Join(fs.ErrNotExist, context.Canceled)} {
		require.False(t, managementOnlyNotFound(err))
		require.False(t, managementOnlyNotFound(managementEntityLookupError(err)))
	}
	marked := managementEntityLookupError(session.ErrNoSuchSession)
	require.False(t, managementOnlyNotFound(errors.Join(marked, fs.ErrNotExist)), "a separate final audit IO failure is never a missing entity")
	require.False(t, managementOnlyNotFound(fs.ErrNotExist))
}

func TestHTTPSManagementMissingRecordingHasNoPartialTransfer(t *testing.T) {
	fixture := newArtifactHTTPSFixture(t)
	token := fixture.login(t)
	id, err := recording.NewId()
	require.NoError(t, err)
	response := artifactHTTPSPost(t, fixture, token, "artifacts/recording", map[string]string{"auditlog": "default", "id": id.String()})
	defer func() { require.NoError(t, response.Body.Close()) }()
	data, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, 404, response.StatusCode, string(data))
	require.Equal(t, "application/json; charset=utf-8", response.Header.Get("Content-Type"))
	require.NotContains(t, string(data), fixture.svc.Configuration.Flows[0].Name.String()+"/")
}

func TestManagementEntityMissingIs404ButEmptySelectionIs200AndFinalAuditFailureIs503(t *testing.T) {
	svc, handler, recorder, token := managementWebFixture(t)
	flow := svc.Configuration.Flows[0].Name.String()
	id := session.MustNewId().String()
	code, _, body := managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": flow, "id": id})
	require.Equal(t, 404, code, body)
	code, result, body := managementWebRead(t, handler, token, "sessions/list", map[string]string{"flow": "no-such-configured-flow"})
	require.Equal(t, 200, code, body)
	require.Empty(t, result.Sessions.Items)
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, errors.New("private final audit failure"))
	code, _, body = managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": flow, "id": id})
	require.Equal(t, 503, code, body)
	require.NotContains(t, body, "private final audit failure")
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, fs.ErrNotExist)
	code, _, body = managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": flow, "id": id})
	require.Equal(t, 503, code, body)
}
