package service

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfconnection "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/metadatacache"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestManagementProgressNeverLeaksArchiveCountsThroughForcedReadCeilings(t *testing.T) {
	svc, _, _, token := managementWebFixture(t)
	auth := webTestAccess(t, svc, token, "Work").auth
	progress := managementReadProgress{Phase: "verifying", Completed: 230, Total: 284}
	require.Equal(t, progress, managementProgressFor(auth, progress))
	forced := "recordings --flow=docker"
	restricted := executionPolicyAuthorization{Authorization: auth, policy: &authorization.AuthorizedKeyPolicy{ForcedCommand: &forced}}
	require.Equal(t, managementReadProgress{Phase: "verifying", Completed: 0, Total: -1}, managementProgressFor(restricted, progress))
}

type streamingManagementRepository struct {
	environment.CloseableRepository
	release chan struct{}
}

func TestManagementStreamingDoesNotSendUnnegotiatedProgressToLegacyClients(t *testing.T) {
	fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	socket := managementChannelDial(t, fixture, fixture.login(t), false)
	requireWebSocketReady(t, socket)
	code, data := managementChannelRead(t, socket, "1", "auditlogs/list", nil)
	require.Equal(t, 200, code, string(data))
	require.Contains(t, string(data), `"auditlogs"`)
}

func (r *streamingManagementRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, _ := environment.SessionTargetResolverFor(r.CloseableRepository, ctx.Authorization().Flow())
	return resolver.ResolveSessionTarget(ctx)
}
func (r *streamingManagementRepository) Ensure(request environment.Request) (environment.Environment, error) {
	value, err := r.CloseableRepository.Ensure(request)
	if err != nil {
		return nil, err
	}
	return &streamingManagementEnvironment{Environment: value, release: r.release}, nil
}

type streamingManagementEnvironment struct {
	environment.Environment
	release chan struct{}
}

func (e *streamingManagementEnvironment) ReadManagement(task environment.TaskContext, request protocol.ReadRequest, output io.Writer) (int, error) {
	if request.Operation == protocol.ListAuditlogs {
		if err := reportManagementProgress(task.Context(), "inventory", 0, 1); err != nil {
			return -1, err
		}
		select {
		case <-task.Context().Done():
			return -1, task.Context().Err()
		case <-e.release:
		}
	}
	return e.Environment.(environment.ManagementReader).ReadManagement(task, request, output)
}

func TestManagementStreamingProgressIsProvisionalAndCancellationKeepsAdmission(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(fmt.Sprint(cancel), func(t *testing.T) {
			fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
			})
			release := make(chan struct{})
			fixture.svc.environments = &streamingManagementRepository{CloseableRepository: fixture.svc.environments, release: release}
			socket := managementChannelDial(t, fixture, fixture.login(t))
			requireWebSocketReady(t, socket)
			require.NoError(t, socket.WriteJSON(map[string]any{"type": "request", "requestId": "1", "action": "management/auditlogs/list", "fields": map[string]string{}}))
			progress := webSocketStatus(t, socket)
			require.Len(t, progress, 5)
			require.Equal(t, `"progress"`, string(progress["type"]))
			require.Equal(t, `"1"`, string(progress["requestId"]))
			require.Equal(t, `"inventory"`, string(progress["phase"]))
			require.Equal(t, "0", string(progress["completed"]))
			require.Equal(t, "1", string(progress["total"]))
			require.Empty(t, auditEventsNamed(fixture.recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted), "progress must not acknowledge a successful task or release a result")
			if cancel {
				require.NoError(t, socket.WriteJSON(map[string]string{"type": "cancel", "requestId": "1"}))
			} else {
				close(release)
			}
			var body []byte
			response := false
			finished := false
			for !finished {
				kind, data, err := socket.ReadMessage()
				require.NoError(t, err)
				if kind == websocket.BinaryMessage {
					require.True(t, response)
					require.Greater(t, len(data), 8)
					require.EqualValues(t, 1, binary.BigEndian.Uint64(data[:8]))
					body = append(body, data[8:]...)
					continue
				}
				require.Equal(t, websocket.TextMessage, kind)
				var frame map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(data, &frame))
				require.Equal(t, `"1"`, string(frame["requestId"]))
				switch string(frame["type"]) {
				case `"progress"`:
					require.False(t, response)
					require.Len(t, frame, 5)
				case `"response"`:
					require.False(t, response)
					response = true
					if !cancel {
						require.Equal(t, "200", string(frame["status"]))
					}
				case `"complete"`:
					require.False(t, cancel)
					require.True(t, response)
					require.Contains(t, string(body), `"auditlogs"`)
					finished = true
				case `"canceled"`:
					require.True(t, cancel)
					finished = true
				default:
					t.Fatalf("unexpected management status %s", data)
				}
			}
			code, data := managementChannelRead(t, socket, "2", "version/show", map[string]string{"long": "false"})
			require.Equal(t, 200, code, string(data))
			require.Contains(t, string(data), `"detail":"short"`)
		})
	}
}

func TestManagementRecordingStreamingSelectsAuthoritativePagesBeyond1024Entries(t *testing.T) {
	svc, _, _, token := managementWebFixture(t)
	started := time.Date(2026, time.September, 13, 12, 34, 56, 123456789, time.UTC)
	repository := svc.recordingRepositories["default"]
	svc.flowAuditRecorders["historical"] = svc.flowAuditRecorders[svc.Configuration.Flows[0].Name]
	svc.flowAuditlogs["historical"] = "default"
	for index := 1; index <= recording.MaximumNativeCatalogEntries+1; index++ {
		// Build real audited recordings, including their signed lifecycle intent,
		// preparation and publication. Complete the outbox in one native replay
		// below instead of repeatedly enumerating the growing receipt directory.
		var id recording.Id
		require.NoError(t, id.UnmarshalText([]byte(fmt.Sprintf("%08x-0000-4000-8000-000000000000", index))))
		metadata := recording.CastMetadata{RecordingId: id, ConnectionId: bfconnection.MustNewId(), SessionId: session.MustNewId(), OperationId: uuid.New(), Flow: "historical", Task: audit.SessionTaskExec, ProducerId: repository.producerId, StartedAt: started}
		artifact, err := repository.artifactName(id)
		require.NoError(t, err)
		startEvent := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil)
		require.NoError(t, repository.receipts.BeginLifecycle(t.Context(), artifact, started, startEvent))
		active, err := repository.native.CreateActive(t.Context(), recording.CastHeader{Version: 3, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: started.Unix()}, metadata, 300)
		require.NoError(t, err)
		exit := uint32(0)
		result := recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: started.Add(time.Second)}
		require.NoError(t, svc.recordSessionRecordingEvent(t.Context(), metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil))
		require.NoError(t, repository.stageLifecycle(t.Context(), id, sessionRecordingTerminalAuditEvent(metadata, result, nil, nil, nil, sessionRecordingFailurePhaseNone, time.Second, &exit)))
		_, err = active.Seal(time.Second, result, &exit)
		require.NoError(t, err)
	}
	pending, err := repository.receipts.PendingLifecycle(t.Context())
	require.NoError(t, err)
	require.Len(t, pending, recording.MaximumNativeCatalogEntries+1)
	require.NoError(t, svc.replaySessionRecordingLifecycles(t.Context()))
	pending, err = repository.receipts.PendingLifecycle(t.Context())
	require.NoError(t, err)
	require.Empty(t, pending, "all lifecycle evidence must be durably completed before the reader test")
	request, err := (protocol.ReadRequest{Operation: protocol.ListRecordings, Auditlog: "default", Flow: "historical", Limit: 20, Status: "all"}).Normalize()
	require.NoError(t, err)
	actor := webTestAccess(t, svc, token, "Work").auth
	var scanned, matched int64
	ctx := context.WithValue(t.Context(), managementProgressContextKey{}, func(progress managementReadProgress) error {
		if progress.Phase == "metadata" || progress.Phase == "searching" {
			scanned = progress.Completed
		}
		if progress.Phase == "finalizing" {
			matched = progress.Total
		}
		return nil
	})
	stats := &recording.CatalogReadStats{}
	ctx = recording.WithCatalogReadStats(ctx, stats)
	page, err := svc.managementRecordingPage(ctx, request, actor)
	require.NoError(t, err)
	require.EqualValues(t, recording.MaximumNativeCatalogEntries+1, scanned)
	require.EqualValues(t, recording.MaximumNativeCatalogEntries+1, matched)
	require.Len(t, page.Items, 20)
	require.EqualValues(t, 20, stats.ContentReads.Load(), "listing must not fully verify the 1,025-recording archive")
	require.NotEmpty(t, page.Next)
	for index, row := range page.Items {
		require.Equal(t, fmt.Sprintf("%08x-0000-4000-8000-000000000000", index+1), row.ID)
		require.Equal(t, "historical", row.Flow)
	}
	request.After = page.Next
	next, err := svc.managementRecordingPage(ctx, request, actor)
	require.NoError(t, err)
	require.Len(t, next.Items, 20)
	require.NotEmpty(t, next.Next)
	require.Equal(t, "00000015-0000-4000-8000-000000000000", next.Items[0].ID)
	require.EqualValues(t, recording.MaximumNativeCatalogEntries+1, matched, "cursor position must not turn the full matching total into a remaining-row count")
	require.EqualValues(t, 40, stats.ContentReads.Load())
	expectedMetadata := recording.MaximumNativeCatalogEntries + 1
	if !metadatacache.FileStampReuse {
		expectedMetadata *= 2
	}
	require.EqualValues(t, expectedMetadata, stats.MetadataReads.Load(), "only supported file-version observations may reuse the index; content reads remain page-bound on every platform")
}
