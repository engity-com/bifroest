package service

import (
	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRecordingSessionScopeSelectsTheWholeDatasetAndDoesNotBecomeAQueryHint(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	for index := 1; index <= 25; index++ {
		catalogRecordingWithContext(t, svc, "default", index, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "history", recording.CastStatusCompleted)
	}
	code, all, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "flow": "history"})
	require.Equal(t, 200, code, body)
	require.Len(t, all.Recordings.Items, 20)
	chosen := all.Recordings.Items[0]
	code, filtered, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "flow": "history", "sessionId": chosen.SessionID, "filterField": "sessionId", "filterOperator": "equals", "filterValue": chosen.SessionID})
	require.Equal(t, 200, code, body)
	require.Len(t, filtered.Recordings.Items, 1)
	require.Equal(t, chosen.ID, filtered.Recordings.Items[0].ID)
	code, empty, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "flow": "different", "sessionId": chosen.SessionID})
	require.Equal(t, 200, code, body)
	require.Empty(t, empty.Recordings.Items)
	code, _, _ = managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "flow": "history", "sessionId": chosen.SessionID, "after": all.Recordings.Next})
	require.Equal(t, 400, code, "a session scope must not reuse an unscoped cursor")
}

func TestAuditSessionRelationsRespectPrivateProjectionAndExactScope(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement).AllowArtifactTransfer = true
	})
	flow := svc.Configuration.Flows[0].Name
	svc.flowAuditRecorders[flow] = svc.auditRecorders[svc.Configuration.Flows[0].Auditlog]
	wanted, other := session.MustNewId().String(), session.MustNewId().String()
	recordingID := "34e34ab8-7457-4d88-a5e4-c57791775c3a"
	for _, id := range []string{wanted, other} {
		pty := false
		require.NoError(t, svc.recordFlowAudit(t.Context(), flow, audit.Event{Name: audit.EventNameSessionRecordingStarted, Domain: audit.EventDomainSession, Flow: flow.String(), SessionId: id, RecordingId: recordingID, ConnectionId: uuid.NewString(), OperationId: uuid.NewString(), SessionTask: audit.SessionTaskExec, Pty: &pty}))
	}
	fields := map[string]string{"auditlog": "default", "flow": flow.String(), "sessionId": wanted, "filterField": "sessionId", "filterOperator": "equals", "filterValue": wanted}
	code, page, body := managementWebRead(t, handler, token, "audit-events/list", fields)
	require.Equal(t, 200, code, body)
	require.Len(t, page.AuditEvents.Items, 1)
	require.NotContains(t, page.AuditEvents.Items[0].Event, "sessionId")
	require.NotContains(t, page.AuditEvents.Items[0].Event, "recordingId")
	fields["sensitive"] = "true"
	code, page, body = managementWebRead(t, handler, token, "audit-events/list", fields)
	require.Equal(t, 200, code, body)
	require.Len(t, page.AuditEvents.Items, 1)
	require.Equal(t, wanted, page.AuditEvents.Items[0].Event["sessionId"])
	require.Equal(t, recordingID, page.AuditEvents.Items[0].Event["recordingId"])
	_, err := (protocol.ReadRequest{Operation: protocol.ListAuditEvents, Auditlog: "default", SessionID: "../untrusted"}).Normalize()
	require.ErrorIs(t, err, protocol.ErrRequest)
}

func TestSessionArtifactTargetsArePolicyProjectedWithoutChangingOriginalRequestIdentity(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	code, page, body := managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all"})
	require.Equal(t, 200, code, body)
	require.NotEmpty(t, page.Sessions.Items)
	for _, item := range page.Sessions.Items {
		require.Equal(t, "alice", item.User)
		require.Equal(t, "default", item.Auditlog)
	}
	code, detail, body := managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": page.Sessions.Items[0].Flow, "id": page.Sessions.Items[0].ID})
	require.Equal(t, 200, code, body)
	require.Equal(t, "default", detail.Session.Auditlog)
	forced := forcedManagementWebLogin(t, svc, handler, "session ls --state=all")
	code, limited, body := managementWebRead(t, handler, forced, "sessions/list", map[string]string{"state": "all"})
	require.Equal(t, 200, code, body)
	for _, item := range limited.Sessions.Items {
		require.Empty(t, item.Auditlog)
		require.True(t, item.PolicyLimited)
	}
}
