package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	managementclient "github.com/engity-com/bifroest/pkg/management/client"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func newArtifactHTTPSFixture(t *testing.T, configure ...func(*configuration.Configuration)) *webSocketFixture {
	t.Helper()
	setup := func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{AllowArtifactTransfer: true}
		conf.Flows[0].DiscoverAsSlug = "Work"
		for _, fn := range configure {
			fn(conf)
		}
	}
	fixture := newWebSocketFixture(t, nil, setup)
	flow := fixture.svc.Configuration.Flows[0]
	// Keep the real signed journal as well as the real recording repository.
	fixture.svc.flowAuditRecorders[flow.Name] = fixture.svc.auditRecorders[flow.Auditlog]
	fixture.svc.managementApplication = nil // No CLI parser may implement this path.
	fixture.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return fixture
}

func artifactHTTPSPost(t *testing.T, fixture *webSocketFixture, token, route string, fields map[string]string) *http.Response {
	t.Helper()
	fields["slug"] = "Work"
	body, err := json.Marshal(fields)
	require.NoError(t, err)
	request, err := http.NewRequestWithContext(t.Context(), "POST", "https://app.example.org"+webAPI+"management/"+route, bytes.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Origin", "https://app.example.org")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := fixture.client.Do(request)
	require.NoError(t, err)
	require.Equal(t, 2, response.ProtoMajor)
	return response
}

func artifactHTTPSSeed(t *testing.T, fixture *webSocketFixture, token string) recording.Id {
	t.Helper()
	response := artifactHTTPSPost(t, fixture, token, "flows/list", map[string]string{})
	content, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, 200, response.StatusCode, string(content))
	ids, err := fixture.svc.recordingRepositories["default"].native.ListSealed(t.Context())
	require.NoError(t, err)
	require.Len(t, ids, 1)
	return ids[0]
}

func TestHTTPSManagementArtifactsUseExistingRightsAndSharedDriverWithoutCLI(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "encrypted"}[encrypted], func(t *testing.T) {
			fixture := newArtifactHTTPSFixture(t, func(conf *configuration.Configuration) {
				if encrypted {
					conf.Auditlogs[0].EncryptionPublicKey = sessionRecordingEncryptionPublicKey(t)
				}
			})
			token := fixture.login(t)
			id := artifactHTTPSSeed(t, fixture, token)
			request := protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "default", ID: id.String()}
			response := artifactHTTPSPost(t, fixture, token, "artifacts/recording", map[string]string{"auditlog": "default", "id": id.String()})
			require.Equal(t, 200, response.StatusCode)
			require.Equal(t, wire.TransferMediaType, response.Header.Get("Content-Type"))
			require.NotEmpty(t, response.Header.Get("X-Bifroest-Connection-Id"))
			framed, err := managementclient.NewHTTPTransferResponse(response, request)
			require.NoError(t, err)
			var contents bytes.Buffer
			header, err := managementclient.ReadRecording(t.Context(), framed, id.String(), &contents, recording.DefaultMaximumNativeRecordingBytes)
			require.NoError(t, err)
			require.Equal(t, id.String(), header.ID)
			expected := fixture.svc.auditIdentities["default"].ProducerId()
			inspection, err := recording.Inspect(bytes.NewReader(contents.Bytes()), int64(contents.Len()), recording.InspectOptions{ExpectedProducerId: expected})
			require.NoError(t, err)
			require.True(t, inspection.Native.Trusted)
			if encrypted {
				require.Equal(t, recording.FormatBECastCBOR, inspection.Format)
			} else {
				require.Equal(t, recording.FormatBcast, inspection.Format)
			}
			request = protocol.ArtifactRequest{Operation: protocol.DownloadAudit, Auditlog: "default"}
			response = artifactHTTPSPost(t, fixture, token, "artifacts/audit", map[string]string{"auditlog": "default"})
			require.Equal(t, 200, response.StatusCode)
			framed, err = managementclient.NewHTTPTransferResponse(response, request)
			require.NoError(t, err)
			root := t.TempDir()
			snapshot, err := managementclient.ReadAuditSnapshot(t.Context(), framed, "default", transport.NewAuditSnapshotFileSink(root))
			require.NoError(t, err)
			require.Equal(t, expected.String(), snapshot.Producer)
			conf := fixture.svc.Configuration.Auditlogs[0]
			publicKey, err := audit.ResolveEncryptionPublicKey(conf.EncryptionPublicKey, conf.EncryptionPublicKeyFile)
			require.NoError(t, err)
			expectedRecipient, err := audit.EncryptionRecipientFingerprint(publicKey)
			require.NoError(t, err)
			require.Equal(t, expectedRecipient, snapshot.Recipient)
			sources := []audit.JournalSource{{Name: "default", Directory: filepath.Join(root, "journal"), ExpectedProducerId: expected, ExpectedEncryptionRecipient: expectedRecipient}}
			if encrypted {
				require.NotEmpty(t, snapshot.Recipient)
				require.NoError(t, audit.VerifyJournalIntegrity(t.Context(), sources))
			} else {
				verified, err := audit.VerifyJournals(t.Context(), sources)
				require.NoError(t, err)
				require.NotEmpty(t, verified.Records())
			}
			ids, err := fixture.svc.recordingRepositories["default"].native.ListSealed(t.Context())
			require.NoError(t, err)
			require.Len(t, ids, 3, "both transfers must record/seal through the common driver")
		})
	}
}

type artifactFinalAuditGate struct {
	delegate         audit.Recorder
	entered, release chan struct{}
	once             sync.Once
	failure          error
}

func (this *artifactFinalAuditGate) Record(ctx context.Context, event audit.Event) error {
	if event.Name == audit.EventNameSessionTaskCompleted {
		this.once.Do(func() { close(this.entered) })
		select {
		case <-this.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		if this.failure != nil {
			return this.failure
		}
	}
	return this.delegate.Record(ctx, event)
}
func (*artifactFinalAuditGate) Close() error { return nil }

type observedArtifactResponse struct {
	*managementclient.TransferResponse
	dataEnd chan struct{}
	once    sync.Once
}

func (this *observedArtifactResponse) Read(data []byte) (int, error) {
	n, err := this.TransferResponse.Read(data)
	if err == io.EOF {
		this.once.Do(func() { close(this.dataEnd) })
	}
	return n, err
}

func TestHTTPSArtifactDataEndCannotBypassBlockedOrFailedFinalAudit(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success-after-release", true: "failure-with-provisional-data"}[fail], func(t *testing.T) {
			fixture := newArtifactHTTPSFixture(t)
			token := fixture.login(t)
			id := artifactHTTPSSeed(t, fixture, token)
			flow := fixture.svc.Configuration.Flows[0]
			gate := &artifactFinalAuditGate{delegate: fixture.svc.flowAuditRecorders[flow.Name], entered: make(chan struct{}), release: make(chan struct{})}
			if fail {
				gate.failure = errors.New("private final-audit storage detail")
			}
			var release sync.Once
			unblock := func() { release.Do(func() { close(gate.release) }) }
			t.Cleanup(unblock)
			fixture.svc.flowAuditRecorders[flow.Name] = gate
			response := artifactHTTPSPost(t, fixture, token, "artifacts/recording", map[string]string{"auditlog": "default", "id": id.String()})
			require.Equal(t, 200, response.StatusCode)
			framed, err := managementclient.NewHTTPTransferResponse(response, protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "default", ID: id.String()})
			require.NoError(t, err)
			observed := &observedArtifactResponse{TransferResponse: framed, dataEnd: make(chan struct{})}
			var provisional bytes.Buffer
			type result struct {
				header wire.RecordingArtifactHeader
				err    error
			}
			done := make(chan result, 1)
			go func() {
				header, err := managementclient.ReadRecording(t.Context(), observed, id.String(), &provisional, recording.DefaultMaximumNativeRecordingBytes)
				done <- result{header, err}
			}()
			select {
			case <-observed.dataEnd:
			case <-time.After(2 * time.Second):
				t.Fatal("client did not observe flushed data-end")
			}
			select {
			case <-gate.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("driver did not reach final audit")
			}
			require.NotZero(t, provisional.Len())
			select {
			case <-done:
				t.Fatal("data-end was mistaken for successful final audit")
			default:
			}
			ids, err := fixture.svc.recordingRepositories["default"].native.ListSealed(t.Context())
			require.NoError(t, err)
			require.Len(t, ids, 2, "recording must be sealed before the blocked final audit")
			unblock()
			select {
			case value := <-done:
				if fail {
					require.Error(t, value.err)
					require.Equal(t, wire.RecordingArtifactHeader{}, value.header)
					require.NotContains(t, value.err.Error(), "private final-audit")
				} else {
					require.NoError(t, value.err)
					require.Equal(t, id.String(), value.header.ID)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("artifact completion did not resolve")
			}
		})
	}
}

func artifactWebRequest(handler http.Handler, token, route string, fields map[string]string) *httptest.ResponseRecorder {
	fields["slug"] = "Work"
	body, _ := json.Marshal(fields)
	return webTestRequest(handler, "POST", "app.example.org", webAPI+"management/artifacts/"+route, string(body), token)
}

func TestWebArtifactRoutesDenyPolicyBypassAndUntrustedFields(t *testing.T) {
	for _, mode := range []string{"disabled", "forced-read", "forced-dispatcher"} {
		t.Run(mode, func(t *testing.T) {
			svc, handler, recorder, token := managementWebFixture(t, func(conf *configuration.Configuration) {
				management := conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement)
				management.AllowArtifactTransfer = mode != "disabled"
				management.IncludingCredentials = true
			})
			if mode != "disabled" {
				command := "session ls"
				if mode == "forced-dispatcher" {
					command = transport.WireRecordingCommand
				}
				token = forcedManagementWebLogin(t, svc, handler, command)
			}
			before := len(auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted))
			for _, route := range []string{"recording", "audit"} {
				fields := map[string]string{"auditlog": "default"}
				if route == "recording" {
					fields["id"] = session.MustNewId().String()
				}
				response := artifactWebRequest(handler, token, route, fields)
				require.Equal(t, 403, response.Code)
				require.NotEqual(t, wire.TransferMediaType, response.Header().Get("Content-Type"))
			}
			require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted), before)
		})
	}
	_, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement).AllowArtifactTransfer = true
	})
	for _, fields := range []map[string]string{{"auditlog": "../private"}, {"auditlog": "default", "args": "audit export"}, {"auditlog": "default", "includingCredentials": "true"}, {"auditlog": "default", "allowArtifactTransfer": "true"}, {"auditlog": "default", "privateKey": "never upload"}, {"auditlog": "default", "id": "other"}} {
		require.Equal(t, 400, artifactWebRequest(handler, token, "audit", fields).Code)
	}
	require.Equal(t, 400, artifactWebRequest(handler, token, "recording", map[string]string{"auditlog": "default", "id": "bad"}).Code)
	require.Equal(t, 401, artifactWebRequest(handler, "", "audit", map[string]string{"auditlog": "default"}).Code)
}

func TestWebArtifactScopeRequiresOriginalOriginSlugAndBearer(t *testing.T) {
	_, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement).AllowArtifactTransfer = true
	})
	for _, test := range []struct{ host, body string }{{"other.example.org", `{"slug":"Work","auditlog":"default"}`}, {"app.example.org", `{"slug":"Other","auditlog":"default"}`}} {
		response := webTestRequest(handler, "POST", test.host, webAPI+"management/artifacts/audit", test.body, token)
		require.Equal(t, 401, response.Code)
	}
	cookieOnly := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Cookie", "access="+token)
		handler.ServeHTTP(w, r)
	})
	require.Equal(t, 401, webTestRequest(cookieOnly, "POST", "app.example.org", webAPI+"management/artifacts/audit", `{"slug":"Work","auditlog":"default"}`, "").Code)
	response := webTestRequest(handler, "GET", "app.example.org", webAPI+"management/artifacts/audit", "", token)
	require.Equal(t, 405, response.Code)
	_, normal, _ := webTestFixture(t)
	normalToken := webTestToken(t, webTestPassword(normal, "alice", "correct", "Work"))
	require.Equal(t, 403, artifactWebRequest(normal, normalToken, "audit", map[string]string{"auditlog": "default"}).Code)
}

type blockingArtifactRepository struct {
	environment.CloseableRepository
	entered chan struct{}
}

func (this *blockingArtifactRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, _ := environment.SessionTargetResolverFor(this.CloseableRepository, ctx.Authorization().Flow())
	return resolver.ResolveSessionTarget(ctx)
}
func (this *blockingArtifactRepository) Ensure(request environment.Request) (environment.Environment, error) {
	env, err := this.CloseableRepository.Ensure(request)
	if err != nil {
		return nil, err
	}
	return &blockingArtifactEnvironment{Environment: env, entered: this.entered}, nil
}

type blockingArtifactEnvironment struct {
	environment.Environment
	entered chan struct{}
}

func (this *blockingArtifactEnvironment) ReadManagementArtifact(task environment.TaskContext, _ protocol.ArtifactRequest, _ io.Writer) (int, error) {
	if _, ssh := task.(environment.Task); ssh {
		return -1, errors.New("artifact adapter fabricated an SSH task")
	}
	close(this.entered)
	<-task.Context().Done()
	return -1, task.Context().Err()
}

func TestWebArtifactTransferSharesQuotaAndCancellationOwnership(t *testing.T) {
	for _, mode := range []string{"logout", "revoke", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			svc, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement).AllowArtifactTransfer = true
			})
			sibling := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
			original := svc.environments
			blocked := &blockingArtifactRepository{CloseableRepository: original, entered: make(chan struct{})}
			svc.environments = blocked
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r.WithContext(ctx)) })
			go func() { done <- artifactWebRequest(wrapped, token, "audit", map[string]string{"auditlog": "default"}) }()
			select {
			case <-blocked.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("artifact operation did not enter shared driver")
			}
			access := webTestAccess(t, svc, token, "Work")
			switch mode {
			case "logout":
				require.Equal(t, 204, webTestRequest(handler, "POST", "app.example.org", webAPI+"logout", `{"slug":"Work"}`, token).Code)
			case "revoke":
				require.NoError(t, svc.sessionConnections.revoke(access.auth.Flow(), access.auth.FindSession().Id()))
			case "cancel":
				cancel()
			}
			select {
			case response := <-done:
				require.NotEqual(t, 200, response.Code)
				require.NotContains(t, response.Body.String(), "fabricated")
			case <-time.After(2 * time.Second):
				t.Fatal("artifact cancellation was ignored")
			}
			svc.environments = original
			if mode == "logout" {
				code, _, body := managementWebRead(t, handler, sibling, "flows/list", nil)
				require.Equal(t, 200, code, body)
			}
		})
	}
	svc, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement).AllowArtifactTransfer = true
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
	access := webTestAccess(t, svc, token, "Work")
	lease, err := access.auth.FindSession().ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	require.Equal(t, 403, artifactWebRequest(handler, token, "audit", map[string]string{"auditlog": "default"}).Code)
	require.NoError(t, lease.Close())
}

func TestHTTPSArtifactRevocationAfterDataEndCannotCompleteOrDisposeSession(t *testing.T) {
	for _, mode := range []string{"logout", "revoke", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newArtifactHTTPSFixture(t)
			token := fixture.login(t)
			sibling := fixture.login(t)
			id := artifactHTTPSSeed(t, fixture, token)
			flow := fixture.svc.Configuration.Flows[0]
			gate := &artifactFinalAuditGate{delegate: fixture.svc.flowAuditRecorders[flow.Name], entered: make(chan struct{}), release: make(chan struct{})}
			var release sync.Once
			unblock := func() { release.Do(func() { close(gate.release) }) }
			t.Cleanup(unblock)
			fixture.svc.flowAuditRecorders[flow.Name] = gate
			response := artifactHTTPSPost(t, fixture, token, "artifacts/recording", map[string]string{"auditlog": "default", "id": id.String()})
			framed, err := managementclient.NewHTTPTransferResponse(response, protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "default", ID: id.String()})
			require.NoError(t, err)
			observed := &observedArtifactResponse{TransferResponse: framed, dataEnd: make(chan struct{})}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				header, err := managementclient.ReadRecording(ctx, observed, id.String(), io.Discard, recording.DefaultMaximumNativeRecordingBytes)
				if header != (wire.RecordingArtifactHeader{}) {
					done <- errors.New("unconfirmed artifact header escaped")
					return
				}
				done <- err
			}()
			select {
			case <-observed.dataEnd:
			case <-time.After(2 * time.Second):
				t.Fatal("artifact data did not finish")
			}
			select {
			case <-gate.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("artifact did not wait in final audit")
			}
			access := webTestAccess(t, fixture.svc, token, "Work")
			current := access.auth.FindSession()
			switch mode {
			case "logout":
				request, err := http.NewRequestWithContext(t.Context(), "POST", "https://app.example.org"+webAPI+"logout", bytes.NewBufferString(`{"slug":"Work"}`))
				require.NoError(t, err)
				request.Header.Set("Origin", "https://app.example.org")
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Authorization", "Bearer "+token)
				reply, err := fixture.client.Do(request)
				require.NoError(t, err)
				require.Equal(t, 204, reply.StatusCode)
				require.NoError(t, reply.Body.Close())
			case "revoke":
				require.NoError(t, fixture.svc.sessionConnections.revoke(access.auth.Flow(), current.Id()))
			case "cancel":
				cancel()
			}
			select {
			case err := <-done:
				require.Error(t, err)
				require.NotContains(t, err.Error(), "unconfirmed artifact header escaped")
			case <-time.After(2 * time.Second):
				t.Fatal("artifact revocation did not finish")
			}
			unblock()
			info, err := current.Info(t.Context())
			require.NoError(t, err)
			require.NotEqual(t, session.StateDisposed, info.State())
			if mode == "logout" {
				reply := artifactHTTPSPost(t, fixture, sibling, "flows/list", map[string]string{})
				require.Equal(t, 200, reply.StatusCode)
				_, err := io.Copy(io.Discard, reply.Body)
				require.NoError(t, err)
				require.NoError(t, reply.Body.Close())
			}
		})
	}
}

type artifactSealHookRepository struct {
	environment.CloseableRepository
	hook func(io.Writer) error
}

func (this *artifactSealHookRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, _ := environment.SessionTargetResolverFor(this.CloseableRepository, ctx.Authorization().Flow())
	return resolver.ResolveSessionTarget(ctx)
}
func (this *artifactSealHookRepository) Ensure(request environment.Request) (environment.Environment, error) {
	env, err := this.CloseableRepository.Ensure(request)
	if err != nil {
		return nil, err
	}
	reader, ok := env.(environment.ManagementArtifactReader)
	if !ok {
		return nil, errors.New("missing test artifact reader")
	}
	return &artifactSealHookEnvironment{Environment: env, reader: reader, hook: this.hook}, nil
}

type artifactSealHookEnvironment struct {
	environment.Environment
	reader environment.ManagementArtifactReader
	hook   func(io.Writer) error
}

func (this *artifactSealHookEnvironment) ReadManagementArtifact(task environment.TaskContext, request protocol.ArtifactRequest, output io.Writer) (int, error) {
	if err := this.hook(output); err != nil {
		return -1, err
	}
	return this.reader.ReadManagementArtifact(task, request, output)
}

func TestHTTPSArtifactDataEndCannotBypassRecordingSealFailure(t *testing.T) {
	fixture := newArtifactHTTPSFixture(t)
	token := fixture.login(t)
	id := artifactHTTPSSeed(t, fixture, token)
	sealStarted, releaseSeal := make(chan struct{}), make(chan struct{})
	var release, signal sync.Once
	unblock := func() { release.Do(func() { close(releaseSeal) }) }
	t.Cleanup(unblock)
	original := fixture.svc.environments
	fixture.svc.environments = &artifactSealHookRepository{CloseableRepository: original, hook: func(output io.Writer) error {
		capture, ok := output.(*recordedTerminal)
		if !ok {
			return errors.New("missing actual recording capture")
		}
		coordinator, ok := capture.sink.(*sessionRecordingCoordinator)
		if !ok {
			return errors.New("missing actual recording coordinator")
		}
		coordinator.mu.Lock()
		coordinator.active.seal = func(time.Duration, recording.CastResult, *uint32) (sessionRecordingSealSummary, error) {
			signal.Do(func() { close(sealStarted) })
			<-releaseSeal
			return sessionRecordingSealSummary{}, errors.New("private seal failure detail")
		}
		coordinator.mu.Unlock()
		return nil
	}}
	response := artifactHTTPSPost(t, fixture, token, "artifacts/recording", map[string]string{"auditlog": "default", "id": id.String()})
	framed, err := managementclient.NewHTTPTransferResponse(response, protocol.ArtifactRequest{Operation: protocol.DownloadRecording, Auditlog: "default", ID: id.String()})
	require.NoError(t, err)
	observed := &observedArtifactResponse{TransferResponse: framed, dataEnd: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		header, err := managementclient.ReadRecording(t.Context(), observed, id.String(), io.Discard, recording.DefaultMaximumNativeRecordingBytes)
		if header != (wire.RecordingArtifactHeader{}) {
			done <- errors.New("unconfirmed artifact header escaped")
			return
		}
		done <- err
	}()
	select {
	case <-observed.dataEnd:
	case <-time.After(2 * time.Second):
		t.Fatal("artifact did not emit data-end")
	}
	select {
	case <-sealStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("recording did not attempt sealing")
	}
	select {
	case <-done:
		t.Fatal("artifact completed before recording seal")
	default:
	}
	unblock()
	select {
	case err := <-done:
		require.Error(t, err)
		require.NotContains(t, err.Error(), "private seal failure")
		require.NotContains(t, err.Error(), "unconfirmed artifact header escaped")
	case <-time.After(2 * time.Second):
		t.Fatal("recording seal failure did not stop artifact")
	}
}
