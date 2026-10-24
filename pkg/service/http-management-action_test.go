package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
)

func newWebTestTerminalTransport(t *testing.T) *executionTestTransport {
	return &executionTestTransport{stream: &executionTestStream{recordingTerminalTestStream: newRecordingTerminalTestStream(t)}, id: bconn.MustNewId()}
}

func managementActionFixture(t *testing.T) (*service, http.Handler, *recordingAuditRecorder, string, string, session.Session) {
	t.Helper()
	svc, handler, recorder, manager := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries = append(conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries, configuration.AuthorizationSimpleEntry{Name: "bob", Password: crypto.Password("plain:correct")})
		worker := conf.Flows[0]
		worker.Name = "worker"
		worker.DiscoverAsSlug = "Worker"
		worker.Environment.V = &configuration.EnvironmentDummy{}
		conf.Flows = append(conf.Flows, worker)
	})
	worker := webTestToken(t, webTestPassword(handler, "bob", "correct", "Worker"))
	return svc, handler, recorder, manager, worker, webTestAccess(t, svc, worker, "Worker").auth.FindSession()
}

func managementActionRequest(handler http.Handler, manager, route string, fields map[string]string) *httptest.ResponseRecorder {
	fields["slug"] = "Work"
	encoded, _ := json.Marshal(fields)
	return webTestRequest(handler, "POST", "app.example.org", webAPI+"management/sessions/"+route, string(encoded), manager)
}
func prepareManagementAction(t *testing.T, handler http.Handler, manager, action string, target session.Session) protocol.ActionPreparation {
	t.Helper()
	response := managementActionRequest(handler, manager, "prepare", map[string]string{"flow": target.Flow().String(), "id": target.Id().String(), "action": action})
	require.Equal(t, 202, response.Code, response.Body.String())
	var result protocol.ActionPreparation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.NotEmpty(t, result.ConfirmationToken)
	require.Equal(t, target.Id().String(), result.Target.ID)
	return result
}

func TestWebManagementConfirmationSeparatesDisconnectFromDispose(t *testing.T) {
	svc, handler, recorder, manager, worker, target := managementActionFixture(t)
	one := newWebTestTerminalTransport(t)
	first, err := svc.web.connect(webScope{Origin: "https://app.example.org", Slug: "Worker"}, worker, one)
	require.NoError(t, err)
	two := newWebTestTerminalTransport(t)
	second, err := svc.web.connect(webScope{Origin: "https://app.example.org", Slug: "Worker"}, worker, two)
	require.NoError(t, err)
	prepared := prepareManagementAction(t, handler, manager, "disconnect", target)
	require.False(t, first.IsClosed())
	require.False(t, second.IsClosed(), "preparation must have no target side effect")
	response := managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, 200, response.Code, response.Body.String())
	require.True(t, first.IsClosed())
	require.True(t, second.IsClosed())
	info, err := target.Info(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, session.StateDisposed, info.State())
	third, err := svc.web.connect(webScope{Origin: "https://app.example.org", Slug: "Worker"}, worker, newWebTestTerminalTransport(t))
	require.NoError(t, err, "disconnect must allow a fresh execution connection")
	prepared = prepareManagementAction(t, handler, manager, "dispose", target)
	response = managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, 200, response.Code, response.Body.String())
	require.True(t, third.IsClosed())
	current, err := svc.sessions.FindBy(t.Context(), target.Flow(), target.Id(), nil)
	require.NoError(t, err)
	info, err = current.Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateDisposed, info.State())
	_, err = svc.web.connect(webScope{Origin: "https://app.example.org", Slug: "Worker"}, worker, newWebTestTerminalTransport(t))
	require.Error(t, err)
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisconnectCompleted), 1)
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeCompleted), 1)
}

func TestWebManagementConfirmationIsOneShotAndBoundToOriginalGrantPeerScope(t *testing.T) {
	svc, handler, recorder, manager, _, target := managementActionFixture(t)
	prepared := prepareManagementAction(t, handler, manager, "disconnect", target)
	sibling := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	require.Equal(t, 403, managementActionRequest(handler, sibling, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	otherPeer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "192.0.2.12:2345"
		handler.ServeHTTP(w, r)
	})
	require.Equal(t, 403, managementActionRequest(otherPeer, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	encoded, _ := json.Marshal(map[string]string{"slug": "Other", "confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, 401, webTestRequest(handler, "POST", "app.example.org", webAPI+"management/sessions/confirm", string(encoded), manager).Code)
	var group sync.WaitGroup
	results := make(chan int, 2)
	for range 2 {
		group.Go(func() {
			results <- managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code
		})
	}
	group.Wait()
	close(results)
	success := 0
	for code := range results {
		if code == 200 {
			success++
		} else {
			require.Equal(t, 403, code)
		}
	}
	require.Equal(t, 1, success)
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisconnectStarted), 1)
	svc.web.mutex.Lock()
	require.Empty(t, svc.web.confirmations)
	svc.web.mutex.Unlock()
}

func TestWebManagementConfirmationCancelExpirySelfAndUnknownFieldsDoNotMutate(t *testing.T) {
	svc, handler, recorder, manager, _, target := managementActionFixture(t)
	self := webTestAccess(t, svc, manager, "Work").auth.FindSession()
	require.Equal(t, 403, managementActionRequest(handler, manager, "prepare", map[string]string{"flow": self.Flow().String(), "id": self.Id().String(), "action": "dispose"}).Code)
	prepared := prepareManagementAction(t, handler, manager, "dispose", target)
	require.Equal(t, 204, managementActionRequest(handler, manager, "cancel", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	require.Equal(t, 403, managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	prepared = prepareManagementAction(t, handler, manager, "dispose", target)
	key, _ := managementConfirmationKey(prepared.ConfirmationToken)
	svc.web.mutex.Lock()
	svc.web.confirmations[key].expires = time.Now().Add(-time.Second)
	svc.web.mutex.Unlock()
	require.Equal(t, 403, managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	require.Equal(t, 400, managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken, "action": "dispose"}).Code)
	require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeStarted))
}

func TestWebManagementConfirmationRejectsReplacedSessionGeneration(t *testing.T) {
	svc, handler, recorder, manager, _, target := managementActionFixture(t)
	prepared := prepareManagementAction(t, handler, manager, "dispose", target)
	replacement, err := svc.sessions.Create(t.Context(), target.Flow(), associationAdapterRemote("different"), nil)
	require.NoError(t, err)
	root := string(svc.Configuration.Session.V.(*configuration.SessionFs).Storage)
	path := filepath.Join(root, target.Flow().String(), target.Id().String())
	other := filepath.Join(root, replacement.Flow().String(), replacement.Id().String())
	require.NoError(t, os.Rename(path, path+"-old-fixture"))
	require.NoError(t, os.Rename(other, path))
	response := managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, 503, response.Code)
	require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeStarted))
	current, err := svc.sessions.FindBy(t.Context(), target.Flow(), target.Id(), nil)
	require.NoError(t, err)
	info, err := current.Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateNew, info.State())
}

func TestWebManagementConfirmationFinalAuditFailureIsNotSuccessOrReplay(t *testing.T) {
	svc, handler, recorder, manager, _, target := managementActionFixture(t)
	prepared := prepareManagementAction(t, handler, manager, "dispose", target)
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, errors.New("private final-audit cause"))
	response := managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, 503, response.Code)
	require.NotContains(t, response.Body.String(), "private final-audit cause")
	require.NotContains(t, response.Body.String(), `"completed"`)
	current, err := svc.sessions.FindBy(t.Context(), target.Flow(), target.Id(), nil)
	require.NoError(t, err)
	info, err := current.Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateDisposed, info.State(), "mutation may have completed before final-audit failure")
	require.Equal(t, 403, managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
}

func TestWebManagementPreparationBudgetAndParentLogout(t *testing.T) {
	svc, handler, recorder, manager, _, target := managementActionFixture(t)
	var tokens []string
	for range webManagementMaximumConfirmationsPerPeer {
		tokens = append(tokens, prepareManagementAction(t, handler, manager, "dispose", target).ConfirmationToken)
	}
	require.Equal(t, 429, managementActionRequest(handler, manager, "prepare", map[string]string{"action": "dispose", "flow": target.Flow().String(), "id": target.Id().String()}).Code)
	require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeStarted))
	require.Equal(t, 204, webTestRequest(handler, "POST", "app.example.org", webAPI+"logout", `{"slug":"Work"}`, manager).Code)
	for _, token := range tokens {
		require.Equal(t, 401, managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": token}).Code)
	}
	svc.web.mutex.Lock()
	svc.web.pruneLocked(time.Now())
	require.Empty(t, svc.web.confirmations)
	svc.web.mutex.Unlock()
}

type managementActionAuditHook struct {
	audit.Recorder
	once   sync.Once
	before func()
}

func (this *managementActionAuditHook) Record(ctx context.Context, event audit.Event) error {
	if event.Name == audit.EventNameSessionDisposeStarted {
		this.once.Do(this.before)
	}
	return this.Recorder.Record(ctx, event)
}

func TestWebManagementConfirmationRechecksGenerationAfterStartedAudit(t *testing.T) {
	svc, handler, recorder, manager, _, target := managementActionFixture(t)
	prepared := prepareManagementAction(t, handler, manager, "dispose", target)
	replacement, err := svc.sessions.Create(t.Context(), target.Flow(), associationAdapterRemote("replacement"), nil)
	require.NoError(t, err)
	root := string(svc.Configuration.Session.V.(*configuration.SessionFs).Storage)
	path := filepath.Join(root, target.Flow().String(), target.Id().String())
	other := filepath.Join(root, replacement.Flow().String(), replacement.Id().String())
	hook := &managementActionAuditHook{Recorder: recorder, before: func() {
		require.NoError(t, os.Rename(path, path+"-old-fixture"))
		require.NoError(t, os.Rename(other, path))
	}}
	flow := webTestAccess(t, svc, manager, "Work").auth.Flow()
	svc.flowAuditRecorders[flow] = hook
	response := managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, 503, response.Code)
	current, err := svc.sessions.FindBy(t.Context(), target.Flow(), target.Id(), nil)
	require.NoError(t, err)
	info, err := current.Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateNew, info.State())
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeStarted), 1)
	events := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeCompleted)
	require.Len(t, events, 1)
	require.Equal(t, audit.EventOutcomeFailure, events[0].Outcome)
}
