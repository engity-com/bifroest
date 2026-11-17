package service

import (
	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/metadatacache"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOperationalRecordingPageChecksOnlyItsVisibleTwentyAndVerifyAllIsExplicit(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for index := 1; index <= 25; index++ {
		catalogRecordingWithContext(t, svc, "default", index, started, "overview-fixture", recording.CastStatusCompleted)
	}
	stats := &recording.CatalogReadStats{}
	ctx := recording.WithCatalogReadStats(t.Context(), stats)
	request, err := (protocol.ReadRequest{Operation: protocol.ListRecordings, Auditlog: "default", Flow: "overview-fixture"}).Normalize()
	require.NoError(t, err)
	actor := webTestAccess(t, svc, token, "Work").auth
	page, err := svc.managementRecordingPage(ctx, request, actor)
	require.NoError(t, err)
	require.Len(t, page.Items, 20)
	require.EqualValues(t, 25, stats.MetadataReads.Load())
	require.EqualValues(t, 20, stats.ContentReads.Load())
	require.NotEmpty(t, page.Next)
	request.After = page.Next
	page, err = svc.managementRecordingPage(ctx, request, actor)
	require.NoError(t, err)
	require.Len(t, page.Items, 5)
	expectedMetadata := 25
	if !metadatacache.FileStampReuse {
		expectedMetadata = 50
	}
	require.EqualValues(t, expectedMetadata, stats.MetadataReads.Load(), "only supported file-version observations may reuse the index")
	require.EqualValues(t, 25, stats.ContentReads.Load(), "only each displayed page is fully verified")
	before := stats.ContentReads.Load()
	verification, err := svc.managementVerifyRecordings(ctx, protocol.ReadRequest{Operation: protocol.VerifyRecordings, Auditlog: "default"})
	require.NoError(t, err)
	require.EqualValues(t, 25, verification.Checked)
	require.EqualValues(t, 25, stats.ContentReads.Load()-before)
	for _, route := range []string{"recordings/verify", "audit-events/list"} {
		forced := forcedManagementWebLogin(t, svc, handler, "flow ls")
		code, _, _ := managementWebRead(t, handler, forced, route, map[string]string{"auditlog": "default"})
		require.Equal(t, 403, code)
	}
}

func TestAuditOverviewPreservesTransferPolicyPrivateProjectionAndFlowScope(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement).AllowArtifactTransfer = true
	})
	flow := svc.Configuration.Flows[0].Name
	// The execution fixture replaces flow auditing with an in-memory observer;
	// this overview test needs the actual persisted native journal.
	svc.flowAuditRecorders[flow] = svc.auditRecorders[svc.Configuration.Flows[0].Auditlog]
	for index := 0; index < 25; index++ {
		require.NoError(t, svc.recordFlowAudit(t.Context(), flow, audit.Event{Name: audit.EventNameSessionTaskCompleted, Domain: audit.EventDomainSession, Outcome: audit.EventOutcomeSuccess, Flow: flow.String(), Reason: audit.EventReasonDisconnected}))
	}
	code, page, body := managementWebRead(t, handler, token, "audit-events/list", map[string]string{"auditlog": "default"})
	require.Equal(t, 200, code, body)
	require.NotNil(t, page.AuditEventSource)
	require.Equal(t, "server-overview", page.AuditEventSource.Verification)
	require.Len(t, page.AuditEvents.Items, 20)
	require.NotEmpty(t, page.AuditEvents.Next)
	for _, row := range page.AuditEvents.Items {
		require.NotContains(t, row.Event, "flow")
		require.NotContains(t, row.Event, "reason")
	}
	code, next, body := managementWebRead(t, handler, token, "audit-events/list", map[string]string{"auditlog": "default", "after": page.AuditEvents.Next})
	require.Equal(t, 200, code, body)
	require.NotEmpty(t, next.AuditEvents.Items)
	code, private, body := managementWebRead(t, handler, token, "audit-events/list", map[string]string{"auditlog": "default", "flow": flow.String(), "sensitive": "true"})
	require.Equal(t, 200, code, body)
	require.NotEmpty(t, private.AuditEvents.Items)
	for _, row := range private.AuditEvents.Items {
		require.Equal(t, flow.String(), row.Event["flow"])
	}
	id := private.AuditEvents.Items[0].ID
	code, detail, body := managementWebRead(t, handler, token, "audit-events/list", map[string]string{"auditlog": "default", "id": id, "flow": flow.String()})
	require.Equal(t, 200, code, body)
	require.Len(t, detail.AuditEvents.Items, 1)
	code, empty, body := managementWebRead(t, handler, token, "audit-events/list", map[string]string{"auditlog": "default", "id": id, "flow": "other"})
	require.Equal(t, 200, code, body)
	require.Empty(t, empty.AuditEvents.Items)
	code, _, _ = managementWebRead(t, handler, token, "audit-events/list", map[string]string{"auditlog": "default", "after": page.AuditEvents.Next, "sensitive": "true"})
	require.Equal(t, 400, code)
	_, deniedHandler, _, deniedToken := managementWebFixture(t)
	code, _, _ = managementWebRead(t, deniedHandler, deniedToken, "audit-events/list", map[string]string{"auditlog": "default"})
	require.Equal(t, 403, code)
}
