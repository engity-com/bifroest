package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
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
	release  chan struct{}
	canceled chan struct{}
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
	return &streamingManagementEnvironment{Environment: value, release: r.release, canceled: r.canceled}, nil
}

type streamingManagementEnvironment struct {
	environment.Environment
	release  chan struct{}
	canceled chan struct{}
}

func (e *streamingManagementEnvironment) ReadManagement(task environment.TaskContext, request protocol.ReadRequest, output io.Writer) (int, error) {
	if request.Operation == protocol.ListAuditlogs {
		if err := reportManagementProgress(task.Context(), "inventory", 0, 1); err != nil {
			return -1, err
		}
		select {
		case <-task.Context().Done():
			close(e.canceled)
			// Let the test observe cancellation before allowing finalization.
			<-e.release
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
			releaseRead := sync.OnceFunc(func() { close(release) })
			t.Cleanup(releaseRead)
			canceled := make(chan struct{})
			fixture.svc.environments = &streamingManagementRepository{CloseableRepository: fixture.svc.environments, release: release, canceled: canceled}
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
			// Deterministically model an expired progress-read deadline without a sleep.
			require.NoError(t, socket.SetReadDeadline(time.Now().Add(-time.Second)))
			completion := newManagementChannelTestCompletion(t, socket)
			if cancel {
				require.NoError(t, socket.WriteJSON(map[string]string{"type": "cancel", "requestId": "1"}))
				completion.waitFor(t, canceled, "backend cancellation")
				require.Empty(t, auditEventsNamed(fixture.recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted), "receiving cancellation must not acknowledge finalization")
			}
			releaseRead()
			var body []byte
			response := false
			finished := false
			for !finished {
				kind, data := completion.read(t)
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
			completed := auditEventsNamed(fixture.recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted)
			require.Len(t, completed, 1, "the terminal frame must follow task finalization")
			if cancel {
				require.Equal(t, audit.EventOutcomeCanceled, completed[0].Outcome)
			} else {
				require.Equal(t, audit.EventOutcomeSuccess, completed[0].Outcome)
			}
			code, data := managementChannelRead(t, socket, "2", "version/show", map[string]string{"long": "false"})
			require.Equal(t, 200, code, string(data))
			require.Contains(t, string(data), `"detail":"short"`)
		})
	}
}

func TestManagementRecordingStreamingSelectsAuthoritativePagesBeyond1024Entries(t *testing.T) {
	// Keep the real 1,025-entry service/metadata/page boundary, but construct
	// signed reader fixtures without replaying 1,025 durable lifecycles.
	testManagementRecordingStreamingPages(t, recording.MaximumNativeCatalogEntries+1, false)
}

func TestManagementRecordingStreamingSelectsAuditedPublishedPages(t *testing.T) {
	// Two full pages plus a tail exercise actual intent, audit, preparation,
	// sealing, publication and replay before the same authoritative reader.
	testManagementRecordingStreamingPages(t, 41, true)
}

func testManagementRecordingStreamingPages(t *testing.T, count int, audited bool) {
	t.Helper()
	svc, _, _, token := managementWebFixture(t)
	started := time.Date(2026, time.September, 13, 12, 34, 56, 123456789, time.UTC)
	repository := svc.recordingRepositories["default"]
	svc.flowAuditRecorders["historical"] = svc.flowAuditRecorders[svc.Configuration.Flows[0].Name]
	if audited {
		svc.flowAuditRecorders["historical"] = svc.auditRecorders["default"]
	}
	svc.flowAuditlogs["historical"] = "default"
	var fixtureBytes uint64
	digests := make(map[string]string)
	for index := 1; index <= count; index++ {
		var id recording.Id
		require.NoError(t, id.UnmarshalText([]byte(fmt.Sprintf("%08x-0000-4000-8000-000000000000", index))))
		metadata := recording.CastMetadata{RecordingId: id, ConnectionId: bfconnection.MustNewId(), SessionId: session.MustNewId(), OperationId: uuid.New(), Flow: "historical", Task: audit.SessionTaskExec, ProducerId: repository.producerId, StartedAt: started}
		header := recording.CastHeader{Version: 3, Terminal: recording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: started.Unix()}
		exit := uint32(0)
		result := recording.CastResult{Status: recording.CastStatusCompleted, EndedAt: started.Add(time.Second)}
		if !audited {
			var container bytes.Buffer
			writer, err := recording.NewNativeRecordingWriter(&container, svc.auditIdentities["default"], nil, header, metadata, 0, recording.NativeRecordingWriterLimits{})
			require.NoError(t, err)
			_, err = writer.Seal(time.Second, result, &exit)
			require.NoError(t, err)
			path := filepath.Join(svc.Configuration.Auditlogs[0].Recording.Directory, "sealed", id.String()+".bcast")
			require.NoError(t, os.WriteFile(path, container.Bytes(), 0600))
			fixtureBytes += uint64(container.Len())
			continue
		}
		artifact, err := repository.artifactName(id)
		require.NoError(t, err)
		startEvent := sessionRecordingAuditEvent(metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil)
		require.NoError(t, repository.receipts.BeginLifecycle(t.Context(), artifact, started, startEvent))
		active, err := repository.native.CreateActive(t.Context(), header, metadata, 300)
		require.NoError(t, err)
		require.NoError(t, svc.recordSessionRecordingEvent(t.Context(), metadata, audit.EventNameSessionRecordingStarted, "", "", nil, 0, nil, nil))
		require.NoError(t, repository.stageLifecycle(t.Context(), id, sessionRecordingTerminalAuditEvent(metadata, result, nil, nil, nil, sessionRecordingFailurePhaseNone, time.Second, &exit)))
		summary, err := active.Seal(time.Second, result, &exit)
		require.NoError(t, err)
		digests[id.String()] = summary.Digest.String()
	}
	if audited {
		pending, err := repository.receipts.PendingLifecycle(t.Context())
		require.NoError(t, err)
		require.Len(t, pending, count)
		require.NoError(t, svc.replaySessionRecordingLifecycles(t.Context()))
		pending, err = repository.receipts.PendingLifecycle(t.Context())
		require.NoError(t, err)
		require.Empty(t, pending, "all lifecycle evidence must be durably completed before the reader test")
		verified, err := audit.VerifyJournals(t.Context(), []audit.JournalSource{{
			Name: "default", Directory: svc.Configuration.Auditlogs[0].Directory, ExpectedProducerId: repository.producerId, WithSensitive: true,
		}})
		require.NoError(t, err)
		var events []audit.Event
		for _, record := range verified.Records() {
			events = append(events, record.Event)
			if record.Event.Name == audit.EventNameSessionRecordingCompleted {
				require.Contains(t, digests, record.Event.RecordingId)
				require.Equal(t, digests[record.Event.RecordingId], record.Event.RecordingDigest)
			}
		}
		require.Len(t, auditEventsNamed(events, audit.EventNameSessionRecordingStarted), count)
		require.Len(t, auditEventsNamed(events, audit.EventNameSessionRecordingCompleted), count)
	} else {
		t.Logf("reader fixture: %d genuine signed containers, %d bytes", count, fixtureBytes)
	}
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
	require.EqualValues(t, count, scanned)
	require.EqualValues(t, count, matched)
	require.Len(t, page.Items, 20)
	require.EqualValues(t, 20, stats.ContentReads.Load(), "listing must fully verify only the selected page, not the archive")
	require.NotEmpty(t, page.Next)
	for index, row := range page.Items {
		require.Equal(t, base58TestUUID(t, fmt.Sprintf("%08x-0000-4000-8000-000000000000", index+1)), row.ID)
		require.Equal(t, "historical", row.Flow)
	}
	request.After = page.Next
	next, err := svc.managementRecordingPage(ctx, request, actor)
	require.NoError(t, err)
	require.Len(t, next.Items, 20)
	require.NotEmpty(t, next.Next)
	require.Equal(t, base58TestUUID(t, "00000015-0000-4000-8000-000000000000"), next.Items[0].ID)
	require.EqualValues(t, count, matched, "cursor position must not turn the full matching total into a remaining-row count")
	require.EqualValues(t, 40, stats.ContentReads.Load())
	expectedMetadata := count
	if !metadatacache.FileStampReuse {
		expectedMetadata *= 2
	}
	require.EqualValues(t, expectedMetadata, stats.MetadataReads.Load(), "only supported file-version observations may reuse the index; content reads remain page-bound on every platform")
	if audited {
		request.After = next.Next
		tail, err := svc.managementRecordingPage(ctx, request, actor)
		require.NoError(t, err)
		require.Len(t, tail.Items, 1)
		require.Equal(t, base58TestUUID(t, "00000029-0000-4000-8000-000000000000"), tail.Items[0].ID)
		require.Empty(t, tail.Next)
		require.EqualValues(t, count, matched)
		require.EqualValues(t, count, stats.ContentReads.Load())
	}
}
