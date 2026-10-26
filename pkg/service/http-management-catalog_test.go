package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfconnection "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func catalogRecording(t *testing.T, svc *service, name configuration.AuditlogName, index int) recording.Id {
	t.Helper()
	var id recording.Id
	require.NoError(t, id.UnmarshalText([]byte(fmt.Sprintf("%08x-0000-4000-8000-000000000000", index))))
	started := time.Now().UTC().Truncate(time.Second)
	repository := svc.recordingRepositories[name]
	metadata := recording.CastMetadata{RecordingId: id, ConnectionId: bfconnection.MustNewId(), SessionId: session.MustNewId(), OperationId: uuid.New(),
		Flow: svc.Configuration.Flows[0].Name, Task: audit.SessionTaskExec, ProducerId: repository.producerId, StartedAt: started}
	if repository.audited {
		artifact, err := repository.artifactName(id)
		require.NoError(t, err)
		event := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil)
		require.NoError(t, repository.receipts.BeginLifecycle(t.Context(), artifact, started, event))
	}
	active, err := repository.native.CreateActive(t.Context(),
		recording.CastHeader{Version: 3, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: started.Unix()},
		metadata, 300)
	require.NoError(t, err)
	status := uint32(0)
	result := recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: started.Add(time.Second)}
	if repository.audited {
		require.NoError(t, svc.recordSessionRecordingEvent(t.Context(), metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil))
		event := sessionRecordingTerminalAuditEvent(metadata, result, nil, nil, nil, sessionRecordingFailurePhaseNone, time.Second, &status)
		require.NoError(t, repository.stageLifecycle(t.Context(), id, event))
	}
	_, err = active.Seal(time.Second, result, &status)
	require.NoError(t, err)
	if repository.audited {
		require.NoError(t, svc.recordPendingSessionRecordingLifecycle(t.Context(), t.Context(), repository, id))
	}
	return id
}

func TestWebCatalogReusesManagementReadsWithoutTransferRightsOrCli(t *testing.T) {
	svc, handler, recorder, token := managementWebFixture(t)
	svc.managementApplication = nil
	id := catalogRecording(t, svc, "default", 1)
	beforeRecordings := len(auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionRecordingCompleted))
	code, logs, body := managementWebRead(t, handler, token, "auditlogs/list", nil)
	require.Equal(t, 200, code, body)
	require.Len(t, logs.Auditlogs.Items, 1)
	require.Equal(t, "default", logs.Auditlogs.Items[0].Name)
	code, rows, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "limit": "1"})
	require.Equal(t, 200, code, body)
	require.Len(t, rows.Recordings.Items, 1)
	require.Equal(t, id.String(), rows.Recordings.Items[0].ID)
	require.Equal(t, "full", rows.Recordings.Items[0].VerificationScope, "server inspection metadata is not browser evidence")
	for _, forbidden := range []string{token, "plain:correct", "identityFile", "directory", "privateKey", `"owner"`, `"sessionId"`} {
		require.NotContains(t, body, forbidden)
	}
	require.Equal(t, 403, artifactWebRequest(handler, token, "recording", map[string]string{"auditlog": "default", "id": id.String()}).Code)
	events := recorder.eventsSnapshot()
	require.Len(t, auditEventsNamed(events, audit.EventNameSessionTaskCompleted), 2)
	require.Len(t, auditEventsNamed(events, audit.EventNameSessionRecordingCompleted), beforeRecordings+2)
}

func TestWebRecordingCatalogBoundsLookaheadAndPublishesNoCorruptSelectedPage(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	for index := 1; index <= protocol.MaximumPageSize; index++ {
		catalogRecording(t, svc, "default", index)
	}
	path := filepath.Join(svc.Configuration.Auditlogs[0].Recording.Directory, "sealed", "00000015-0000-4000-8000-000000000000.bcast")
	require.NoError(t, os.WriteFile(path, []byte("private corrupt selected artifact"), 0600))
	t.Cleanup(func() { require.NoError(t, os.Remove(path)) }) // Only this test's injected corruption, after preservation assertions.
	code, first, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default"})
	require.Equal(t, 200, code, body)
	require.Len(t, first.Recordings.Items, 20)
	require.NotEmpty(t, first.Recordings.Next)
	require.Equal(t, "00000014-0000-4000-8000-000000000000", first.Recordings.Items[19].ID)
	code, _, body = managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "after": first.Recordings.Next})
	require.Equal(t, 503, code, body)
	require.NotContains(t, body, `"items"`)
	require.NotContains(t, body, "private corrupt")
	require.FileExists(t, path, "catalog reads cannot repair/delete damaged artifacts")
	code, _, _ = managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "other", "after": first.Recordings.Next})
	require.Equal(t, 400, code)
	code, _, _ = managementWebRead(t, handler, token, "auditlogs/list", map[string]string{"after": first.Recordings.Next})
	require.Equal(t, 400, code)
}

func TestWebAuditlogCatalogPagesPublicConfigurationIncludingDisabledEntries(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	for _, name := range []string{"zz", "aa"} {
		conf := svc.Configuration.Auditlogs[0]
		conf.Name, conf.Enabled = configuration.AuditlogName(name), false
		conf.IdentityFile, conf.Directory = "private signing path", "private archive path"
		svc.Configuration.Auditlogs = append(svc.Configuration.Auditlogs, conf)
	}
	var names []string
	after := ""
	for range 3 {
		code, result, body := managementWebRead(t, handler, token, "auditlogs/list", map[string]string{"limit": "1", "after": after})
		require.Equal(t, 200, code, body)
		require.Len(t, result.Auditlogs.Items, 1)
		names = append(names, result.Auditlogs.Items[0].Name)
		after = result.Auditlogs.Next
		require.NotContains(t, body, "private")
		if result.Auditlogs.Items[0].Name != "default" {
			require.False(t, result.Auditlogs.Items[0].Enabled)
		}
	}
	require.Equal(t, []string{"aa", "default", "zz"}, names)
	require.Empty(t, after)
}

func TestWebCatalogStrictInputsForcedPolicyAndFinalAuditBoundaries(t *testing.T) {
	svc, handler, recorder, token := managementWebFixture(t)
	for _, route := range []string{"auditlogs/list", "recordings/list"} {
		for _, fields := range []map[string]string{{"auditlog": "../private"}, {"limit": "21"}, {"includingCredentials": "true"}, {"privateKey": "private material"}, {"command": "recording ls default"}} {
			if route == "recordings/list" && fields["auditlog"] == "" {
				fields["auditlog"] = "default"
			}
			code, _, _ := managementWebRead(t, handler, token, route, fields)
			require.Equal(t, 400, code)
		}
	}
	for _, command := range []string{"flow ls", "session ls --state=all"} {
		forced := forcedManagementWebLogin(t, svc, handler, command)
		for _, route := range []string{"auditlogs/list", "recordings/list"} {
			fields := map[string]string{}
			if route == "recordings/list" {
				fields["auditlog"] = "default"
			}
			code, _, _ := managementWebRead(t, handler, forced, route, fields)
			require.Equal(t, 403, code)
		}
	}
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, errors.New("private final audit failure"))
	code, _, body := managementWebRead(t, handler, token, "auditlogs/list", nil)
	require.Equal(t, 503, code, body)
	require.NotContains(t, body, `"items"`)
	require.NotContains(t, body, "private final")
}

func TestWebCatalogUsesTheSharedQuotaAndDoesNotExpandCredentialProjection(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
		conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement).IncludingCredentials = true
	})
	lease, err := webTestAccess(t, svc, token, "Work").auth.FindSession().ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	for _, route := range []string{"auditlogs/list", "recordings/list"} {
		fields := map[string]string{}
		if route == "recordings/list" {
			fields["auditlog"] = "default"
		}
		code, _, _ := managementWebRead(t, handler, token, route, fields)
		require.Equal(t, 403, code)
	}
	require.NoError(t, lease.Close())
	for _, route := range []string{"auditlogs/list", "recordings/list"} {
		fields := map[string]string{}
		if route == "recordings/list" {
			fields["auditlog"] = "default"
		}
		code, _, body := managementWebRead(t, handler, token, route, fields)
		require.Equal(t, 200, code, body)
		require.NotContains(t, body, "plain:correct")
		require.NotContains(t, body, "identityFile")
	}
}
