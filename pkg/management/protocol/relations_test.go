package protocol

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSessionScopedArtifactReadsAreStrictAndCursorBound(t *testing.T) {
	const id = "34e34ab8-7457-4d88-a5e4-c57791775c3a"
	for _, operation := range []ReadOperation{ListRecordings, ListAuditEvents} {
		request, err := (ReadRequest{Operation: operation, Auditlog: "default", Flow: "work", SessionID: id}).Normalize()
		require.NoError(t, err)
		require.Equal(t, id, request.SessionID)
		changed := request
		changed.SessionID = "00000001-0000-4000-8000-000000000000"
		if operation == ListRecordings {
			require.NotEqual(t, request.RecordingFilter(), changed.RecordingFilter())
		} else {
			require.NotEqual(t, request.AuditEventFilter(), changed.AuditEventFilter())
		}
		for _, bad := range []string{"../file", "not-an-id", "00000000-0000-0000-0000-000000000000"} {
			request.SessionID = bad
			_, err = request.Normalize()
			require.ErrorIs(t, err, ErrRequest)
		}
	}
	for _, operation := range []ReadOperation{ListSessions, ListFlows, ListAuditlogs, VerifyRecordings, ShowSession, ShowVersion} {
		_, err := (ReadRequest{Operation: operation, Auditlog: "default", SessionID: id}).Normalize()
		require.ErrorIs(t, err, ErrRequest)
	}
}
