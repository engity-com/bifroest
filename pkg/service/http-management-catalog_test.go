package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfconnection "github.com/engity-com/bifroest/pkg/connection"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func catalogRecording(t *testing.T, svc *service, name configuration.AuditlogName, index int, outputs ...[]byte) recording.Id {
	t.Helper()
	return catalogRecordingWithContext(t, svc, name, index, time.Now().UTC().Truncate(time.Second), svc.Configuration.Flows[0].Name, recording.CastStatusCompleted, outputs...)
}

func catalogRecordingWithContext(t *testing.T, svc *service, name configuration.AuditlogName, index int, started time.Time, flow configuration.FlowName, recordingStatus recording.CastStatus, outputs ...[]byte) recording.Id {
	t.Helper()
	var id recording.Id
	require.NoError(t, id.UnmarshalText([]byte(fmt.Sprintf("%08x-0000-4000-8000-000000000000", index))))
	repository := svc.recordingRepositories[name]
	if _, exists := svc.flowAuditRecorders[flow]; !exists {
		// Historical fixture flow distinct from the catalog request's own new
		// recordings, routed to the same existing test recorder.
		svc.flowAuditRecorders[flow] = svc.flowAuditRecorders[svc.Configuration.Flows[0].Name]
		svc.flowAuditlogs[flow] = name
	}
	metadata := recording.CastMetadata{RecordingId: id, ConnectionId: bfconnection.MustNewId(), SessionId: session.MustNewId(), OperationId: uuid.New(),
		Flow: flow, Task: audit.SessionTaskExec, ProducerId: repository.producerId, StartedAt: started}
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
	for _, output := range outputs {
		require.NoError(t, active.WriteOutput(100*time.Millisecond, recording.OutputStreamStdout, output))
	}
	status := uint32(0)
	if recordingStatus != recording.CastStatusCompleted {
		status = 1
	}
	result := recording.CastResult{Status: recordingStatus, EndedAt: started.Add(time.Second)}
	if repository.audited {
		require.NoError(t, svc.recordSessionRecordingEvent(t.Context(), metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil))
		var taskErr, captureErr error
		if recordingStatus == recording.CastStatusIncomplete {
			taskErr = errors.New("fixture interrupted session")
		}
		if recordingStatus == recording.CastStatusFailed {
			captureErr = errors.New("fixture recording capture failure")
		}
		event := sessionRecordingTerminalAuditEvent(metadata, result, taskErr, captureErr, nil, sessionRecordingFailurePhaseNone, time.Second, &status)
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
	code, rows, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "limit": "1"})
	require.Equal(t, 200, code, body)
	require.Len(t, rows.Recordings.Items, 1)
	require.Equal(t, id.String(), rows.Recordings.Items[0].ID)
	require.Equal(t, "full", rows.Recordings.Items[0].VerificationScope, "server inspection metadata is not browser evidence")
	require.Equal(t, svc.Configuration.Flows[0].Name.String(), rows.Recordings.Items[0].Flow)
	require.True(t, protocol.ValidID(rows.Recordings.Items[0].SessionID))
	require.Empty(t, rows.Recordings.Items[0].User)
	require.Empty(t, rows.Recordings.Items[0].Target)
	for _, forbidden := range []string{token, "plain:correct", "identityFile", "directory", "privateKey", `"owner"`} {
		require.NotContains(t, body, forbidden)
	}
	code, logs, body := managementWebRead(t, handler, token, "auditlogs/list", nil)
	require.Equal(t, 200, code, body)
	require.Len(t, logs.Auditlogs.Items, 1)
	require.Equal(t, "default", logs.Auditlogs.Items[0].Name)
	require.Equal(t, 403, artifactWebRequest(handler, token, "recording", map[string]string{"auditlog": "default", "id": id.String()}).Code)
	events := recorder.eventsSnapshot()
	require.Len(t, auditEventsNamed(events, audit.EventNameSessionTaskCompleted), 2)
	require.Len(t, auditEventsNamed(events, audit.EventNameSessionRecordingCompleted), beforeRecordings+2)
}

func TestWebRecordingCatalogRevalidatesCachedInventoryAndFailsClosedOnCorruption(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for index := 1; index <= protocol.MaximumPageSize+1; index++ {
		catalogRecordingWithContext(t, svc, "default", index, started, "catalog-fixture", recording.CastStatusCompleted)
	}
	path := filepath.Join(svc.Configuration.Auditlogs[0].Recording.Directory, "sealed", "00000015-0000-4000-8000-000000000000.bcast")
	code, first, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "flow": "catalog-fixture"})
	require.Equal(t, 200, code, body)
	require.Len(t, first.Recordings.Items, 20)
	require.NotEmpty(t, first.Recordings.Next)
	require.Equal(t, "00000014-0000-4000-8000-000000000000", first.Recordings.Items[19].ID)
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("private corrupt selected artifact"), 0600))
	t.Cleanup(func() { require.NoError(t, os.WriteFile(path, original, 0600)) })
	code, _, body = managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "flow": "catalog-fixture", "after": first.Recordings.Next})
	require.Equal(t, 503, code, body)
	require.NotContains(t, body, `"items"`)
	require.NotContains(t, body, "private corrupt")
	require.FileExists(t, path, "catalog reads cannot repair/delete damaged artifacts")
	code, _, body = managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "flow": "catalog-fixture"})
	require.Equal(t, 503, code, body, "an invalid candidate cannot silently disappear from sorted/filtered results")
	code, _, _ = managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "other", "after": first.Recordings.Next})
	require.Equal(t, 400, code)
	code, _, _ = managementWebRead(t, handler, token, "auditlogs/list", map[string]string{"after": first.Recordings.Next})
	require.Equal(t, 400, code)
}

func TestWebAuditlogCatalogPagesPublicConfigurationIncludingDisabledEntries(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	for _, name := range []string{"zz", "aa"} {
		conf := svc.Configuration.Auditlogs[0]
		conf.Name = configuration.AuditlogName(name)
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
			require.True(t, result.Auditlogs.Items[0].Enabled)
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

func TestWebRecordingCatalogFiltersNewestSortInclusiveBoundariesAndLaterRecords(t *testing.T) {
	svc, handler, recorder, token := managementWebFixture(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 5, time.UTC)
	for _, value := range []struct {
		id     int
		offset time.Duration
		status recording.CastStatus
	}{{1, -time.Second, recording.CastStatusIncomplete}, {2, 0, recording.CastStatusFailed},
		{3, time.Second, recording.CastStatusCompleted}, {4, time.Second, recording.CastStatusCompleted}, {5, 2 * time.Second, recording.CastStatusCompleted}} {
		catalogRecordingWithContext(t, svc, "default", value.id, base.Add(value.offset), "catalog-fixture", value.status)
	}
	read := func(extra map[string]string) (int, protocol.ReadResult, string) {
		fields := map[string]string{"auditlog": "default", "flow": "catalog-fixture"}
		for key, value := range extra {
			fields[key] = value
		}
		return managementWebRead(t, handler, token, "recordings/list", fields)
	}
	for _, filter := range []struct {
		fields map[string]string
		want   []string
	}{
		{map[string]string{"status": "failed"}, []string{"00000002-0000-4000-8000-000000000000"}},
		{map[string]string{"status": "incomplete"}, []string{"00000001-0000-4000-8000-000000000000"}},
		{map[string]string{"startedFrom": base.Add(time.Second).Format(time.RFC3339Nano), "startedUntil": base.Add(time.Second).Format(time.RFC3339Nano)}, []string{"00000003-0000-4000-8000-000000000000", "00000004-0000-4000-8000-000000000000"}},
		{map[string]string{"flow": "unavailable-flow"}, nil},
		{map[string]string{"user": "alice"}, nil},
		{map[string]string{"target": "host.example.org"}, nil},
	} {
		code, result, body := read(filter.fields)
		require.Equal(t, 200, code, body)
		var actual []string
		for _, row := range result.Recordings.Items {
			actual = append(actual, row.ID)
		}
		require.Equal(t, filter.want, actual)
		require.Empty(t, result.Recordings.Next)
	}
	code, first, body := read(map[string]string{"limit": "2"})
	require.Equal(t, 200, code, body)
	require.Equal(t, "00000005-0000-4000-8000-000000000000", first.Recordings.Items[0].ID)
	require.Equal(t, "00000003-0000-4000-8000-000000000000", first.Recordings.Items[1].ID)
	require.NotEmpty(t, first.Recordings.Next)
	// Newer records do not cause duplicates/restart a subsequent keyset page.
	catalogRecordingWithContext(t, svc, "default", 6, base.Add(3*time.Second), "catalog-fixture", recording.CastStatusCompleted)
	catalogRecordingWithContext(t, svc, "default", 7, base.Add(time.Second), "catalog-fixture", recording.CastStatusCompleted)
	code, second, body := read(map[string]string{"limit": "2", "after": first.Recordings.Next})
	require.Equal(t, 200, code, body)
	require.Equal(t, "00000004-0000-4000-8000-000000000000", second.Recordings.Items[0].ID)
	require.Equal(t, "00000007-0000-4000-8000-000000000000", second.Recordings.Items[1].ID)
	code, third, body := read(map[string]string{"limit": "2", "after": second.Recordings.Next})
	require.Equal(t, 200, code, body)
	require.Equal(t, "00000002-0000-4000-8000-000000000000", third.Recordings.Items[0].ID)
	require.Equal(t, "00000001-0000-4000-8000-000000000000", third.Recordings.Items[1].ID)
	require.Empty(t, third.Recordings.Next)
	code, latest, body := read(map[string]string{"limit": "2"})
	require.Equal(t, 200, code, body)
	require.Equal(t, "00000006-0000-4000-8000-000000000000", latest.Recordings.Items[0].ID)
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, errors.New("private final recording list audit failure"))
	code, _, body = read(nil)
	require.Equal(t, 503, code, body)
	require.NotContains(t, body, `"items"`)
	require.NotContains(t, body, "private final")
}

func TestWebRecordingCatalogCursorAuthenticatesActorFilterSortExpiryAndPosition(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		auth := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		auth.Entries = append(auth.Entries, configuration.AuthorizationSimpleEntry{Name: "bob", Password: bfcrypto.Password("plain:correct")})
	})
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for index := 1; index <= 3; index++ {
		catalogRecordingWithContext(t, svc, "default", index, base, "catalog-fixture", recording.CastStatusCompleted)
	}
	fields := func(after string) map[string]string {
		return map[string]string{"auditlog": "default", "flow": "catalog-fixture", "limit": "1", "after": after}
	}
	code, first, body := managementWebRead(t, handler, token, "recordings/list", fields(""))
	require.Equal(t, 200, code, body)
	bob := webTestToken(t, webTestPassword(handler, "bob", "correct", "Work"))
	code, _, body = managementWebRead(t, handler, bob, "recordings/list", fields(first.Recordings.Next))
	require.Equal(t, 503, code, body)
	require.NotContains(t, body, `"items"`)
	for key, value := range map[string]string{"flow": "other", "user": "alice", "target": "host", "status": "failed", "startedFrom": "2025-01-01T00:00:00Z", "startedUntil": "2027-01-01T00:00:00Z", "sort": "uuid", "limit": "2", "auditlog": "other"} {
		changed := fields(first.Recordings.Next)
		changed[key] = value
		_, err := managementReadRequest(webAPI+"management/recordings/list", changed)
		require.ErrorIs(t, err, protocol.ErrRequest)
	}
	changed := fields(first.Recordings.Next)
	changed["user"] = "alice"
	code, _, body = managementWebRead(t, handler, token, "recordings/list", changed)
	require.Equal(t, 400, code, body)
	request, err := managementReadRequest(webAPI+"management/recordings/list", fields(first.Recordings.Next))
	require.NoError(t, err)
	cursor, err := request.RecordingCursor()
	require.NoError(t, err)
	for _, mutate := range []func(*protocol.RecordingPageCursor){
		func(c *protocol.RecordingPageCursor) { c.ID = "00000003-0000-4000-8000-000000000000" },
		func(c *protocol.RecordingPageCursor) { c.StartedAt = "2025-01-01T00:00:00Z" },
		func(c *protocol.RecordingPageCursor) { c.ActorFlow = "other" },
		func(c *protocol.RecordingPageCursor) { c.Expires = time.Now().Add(time.Hour).Unix() },
	} {
		changed := cursor
		mutate(&changed)
		code, _, body = managementWebRead(t, handler, token, "recordings/list", fields(changed.Token()))
		require.Equal(t, 503, code, body)
		require.NotContains(t, body, `"items"`)
	}
	cursor.Expires = time.Now().Add(-time.Second).Unix()
	mac, err := svc.recordingRepositories["default"].native.CatalogCursorMAC(cursor.Payload())
	require.NoError(t, err)
	cursor.MAC = base64.RawURLEncoding.EncodeToString(mac)
	code, _, body = managementWebRead(t, handler, token, "recordings/list", fields(cursor.Token()))
	require.Equal(t, 503, code, body, "even an authentic expired cursor is not usable")
	forced := forcedManagementWebLogin(t, svc, handler, "session ls --state=all")
	code, _, _ = managementWebRead(t, handler, forced, "recordings/list", fields(first.Recordings.Next))
	require.Equal(t, 403, code)
}

func TestWebRecordingCatalogWithholdsEncryptedPrivateContextEvenFromFilters(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	svc, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Auditlogs[0].EncryptionPublicKey = bfcrypto.PublicKeys(string(ssh.MarshalAuthorizedKey(key)))
	})
	id := catalogRecording(t, svc, "default", 1)
	code, page, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default"})
	require.Equal(t, 200, code, body)
	require.Len(t, page.Recordings.Items, 1)
	require.Equal(t, id.String(), page.Recordings.Items[0].ID)
	require.True(t, page.Recordings.Items[0].MetadataUnavailable)
	for _, field := range []string{`"flow"`, `"sessionId"`, `"user"`, `"target"`} {
		require.NotContains(t, body, field)
	}
	for _, fields := range []map[string]string{
		{"auditlog": "default", "flow": svc.Configuration.Flows[0].Name.String()},
		{"auditlog": "default", "user": "alice"},
		{"auditlog": "default", "target": "host.example.org"},
	} {
		code, page, body := managementWebRead(t, handler, token, "recordings/list", fields)
		require.Equal(t, 200, code, body)
		require.Empty(t, page.Recordings.Items)
		require.Empty(t, page.Recordings.Next)
	}
}
