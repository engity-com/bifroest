package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
)

func managementWebFixture(t *testing.T, configure ...func(*configuration.Configuration)) (*service, http.Handler, *recordingAuditRecorder, string) {
	t.Helper()
	svc, handler, recorder := webTestFixture(t, append([]func(*configuration.Configuration){func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	}}, configure...)...)
	// Use the actual management repository/capability, not the terminal test hook.
	svc.environments = svc.environments.(*executionTestRepository).CloseableRepository
	token := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	return svc, handler, recorder, token
}

func managementWebRead(t *testing.T, handler http.Handler, token, route string, fields map[string]string) (int, protocol.ReadResult, string) {
	t.Helper()
	if fields == nil {
		fields = map[string]string{}
	}
	fields["slug"] = "Work"
	body, err := json.Marshal(fields)
	require.NoError(t, err)
	w := webTestRequest(handler, "POST", "app.example.org", webAPI+"management/"+route, string(body), token)
	var result protocol.ReadResult
	if w.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		require.Equal(t, 1, result.Version)
		require.NotEmpty(t, w.Header().Get("X-Bifroest-Connection-Id"))
	}
	return w.Code, result, w.Body.String()
}

func TestWebManagementReadUsesExistingEnvironmentAndSharedAuditRecording(t *testing.T) {
	svc, handler, recorder, token := managementWebFixture(t)
	application := svc.managementApplication
	svc.managementApplication = nil // Any accidental CLI parser delegation would fail.
	defer func() { svc.managementApplication = application }()
	code, result, body := managementWebRead(t, handler, token, "flows/list", nil)
	require.Equal(t, 200, code, body)
	require.Len(t, result.Flows.Items, 1)
	require.Equal(t, "management", result.Flows.Items[0].Environment)
	require.NotContains(t, body, "plain:correct")
	require.NotContains(t, body, token)
	events := recorder.eventsSnapshot()
	require.Len(t, auditEventsNamed(events, audit.EventNameSessionTaskStarted), 1)
	require.Len(t, auditEventsNamed(events, audit.EventNameSessionTaskCompleted), 1)
	require.Len(t, auditEventsNamed(events, audit.EventNameSessionRecordingCompleted), 1)
	ids, err := svc.recordingRepositories[svc.Configuration.Auditlogs[0].Name].native.ListSealed(t.Context())
	require.NoError(t, err)
	require.Len(t, ids, 1)
	code, result, body = managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all"})
	require.Equal(t, 200, code, body)
	require.Len(t, result.Sessions.Items, 1)
	item := result.Sessions.Items[0]
	require.Equal(t, "alice", item.User)
	require.NotNil(t, item.Owner)
	require.Equal(t, "alice", item.Owner.Subject)
	code, detail, body := managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": item.Flow, "id": item.ID})
	require.Equal(t, 200, code, body)
	require.Equal(t, item.ID, detail.Session.ID)
	access := webTestAccess(t, svc, token, "Work")
	info, err := access.auth.FindSession().Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateAuthorized, info.State())
	access.mutex.Lock()
	children := len(access.children)
	access.mutex.Unlock()
	require.Zero(t, children)
}

type blockingManagementReadRepository struct {
	environment.CloseableRepository
	entered chan struct{}
}

func (this *blockingManagementReadRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, _ := environment.SessionTargetResolverFor(this.CloseableRepository, ctx.Authorization().Flow())
	return resolver.ResolveSessionTarget(ctx)
}
func (this *blockingManagementReadRepository) Ensure(request environment.Request) (environment.Environment, error) {
	env, err := this.CloseableRepository.Ensure(request)
	if err != nil {
		return nil, err
	}
	return &blockingManagementReadEnvironment{Environment: env, entered: this.entered}, nil
}

type blockingManagementReadEnvironment struct {
	environment.Environment
	entered chan struct{}
}

func (this *blockingManagementReadEnvironment) ReadManagement(task environment.TaskContext, _ protocol.ReadRequest, _ io.Writer) (int, error) {
	if _, ssh := task.(environment.Task); ssh {
		return -1, errors.New("structured adapter supplied SSH task")
	}
	close(this.entered)
	<-task.Context().Done()
	return -1, task.Context().Err()
}

func TestWebManagementRunningReadClosesOnOwnLogoutAndSessionRevocation(t *testing.T) {
	for _, mode := range []string{"logout", "revoke", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			svc, handler, _, token := managementWebFixture(t)
			sibling := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
			original := svc.environments
			blocked := &blockingManagementReadRepository{CloseableRepository: original, entered: make(chan struct{})}
			svc.environments = blocked
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				r := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
				wrapped := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					handler.ServeHTTP(w, request.WithContext(r.Context()))
				})
				done <- webTestRequest(wrapped, "POST", "app.example.org", webAPI+"management/flows/list", `{"slug":"Work"}`, token)
			}()
			select {
			case <-blocked.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("management request did not enter typed environment")
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
			case result := <-done:
				require.NotEqual(t, 200, result.Code)
			case <-time.After(2 * time.Second):
				t.Fatal("management operation ignored cancellation")
			}
			svc.environments = original
			if mode == "logout" {
				code, _, body := managementWebRead(t, handler, sibling, "flows/list", nil)
				require.Equal(t, 200, code, body)
			}
		})
	}
}

func TestWebManagementReadUsesSharedSessionQuota(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) { conf.Session.V.(*configuration.SessionFs).MaxConnections = 1 })
	access := webTestAccess(t, svc, token, "Work")
	lease, err := access.auth.FindSession().ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	code, _, _ := managementWebRead(t, handler, token, "flows/list", nil)
	require.Equal(t, 403, code)
	require.NoError(t, lease.Close())
	code, _, body := managementWebRead(t, handler, token, "flows/list", nil)
	require.Equal(t, 200, code, body)
}

func TestWebManagementReadRejectsWrongFlowScopeAndCommands(t *testing.T) {
	_, normal, _ := webTestFixture(t)
	normalToken := webTestToken(t, webTestPassword(normal, "alice", "correct", "Work"))
	code, _, _ := managementWebRead(t, normal, normalToken, "flows/list", nil)
	require.Equal(t, 403, code)
	_, handler, _, token := managementWebFixture(t)
	for _, route := range []string{"sessions/dispose", "command", "../terminal"} {
		code, _, _ := managementWebRead(t, handler, token, route, nil)
		require.NotEqual(t, 200, code)
	}
	for _, fields := range []map[string]string{{"args": "session dispose"}, {"includingCredentials": "true"}, {"limit": "21"}, {"limit": "01"}, {"after": "invalid"}} {
		code, _, _ := managementWebRead(t, handler, token, "flows/list", fields)
		require.Equal(t, 400, code)
	}
	w := webTestRequest(handler, "POST", "other.example.org", webAPI+"management/flows/list", `{"slug":"Work"}`, token)
	require.Equal(t, 401, w.Code)
	w = webTestRequest(handler, "POST", "app.example.org", webAPI+"management/flows/list", `{"slug":"Other"}`, token)
	require.Equal(t, 401, w.Code)
	w = webTestRequest(handler, "POST", "app.example.org", webAPI+"management/flows/list", `{"slug":"Work"}`, "")
	require.Equal(t, 401, w.Code)
	w = webTestRequest(handler, "GET", "app.example.org", webAPI+"management/flows/list", "", token)
	require.Equal(t, 405, w.Code)
}

func TestWebManagementReadPagedMetadataKeepsRequestingNameSeparate(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		base := conf.Flows[0]
		conf.Flows = nil
		for _, name := range []string{"z", "a", "m"} {
			flow := base
			flow.Name = configuration.FlowName(name)
			flow.DiscoverAsSlug = ""
			conf.Flows = append(conf.Flows, flow)
		}
	})
	var names []string
	after := ""
	for range 3 {
		code, result, body := managementWebRead(t, handler, token, "flows/list", map[string]string{"limit": "1", "after": after})
		require.Equal(t, 200, code, body)
		require.Len(t, result.Flows.Items, 1)
		names = append(names, result.Flows.Items[0].Name)
		after = result.Flows.Next
	}
	require.Equal(t, []string{"a", "m", "z"}, names)
	require.Empty(t, after)
	upper := webTestToken(t, webTestPassword(handler, "ALICE", "correct", "Work"))
	require.Equal(t, webTestAccess(t, svc, token, "Work").auth.FindSession().Id(), webTestAccess(t, svc, upper, "Work").auth.FindSession().Id())
}

func TestWebManagementReadStrictFinalAuditCannotPublishBufferedData(t *testing.T) {
	_, handler, recorder, token := managementWebFixture(t)
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, errors.New("private audit diagnostic"))
	code, _, body := managementWebRead(t, handler, token, "flows/list", nil)
	require.Equal(t, 503, code)
	require.NotContains(t, body, "private audit diagnostic")
	require.NotContains(t, body, `"items"`)
}

func TestWebManagementReadReportsDamagedEntriesWithoutPathsOrCleanup(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	root := svc.Configuration.Session.V.(*configuration.SessionFs).Storage
	id := session.MustNewId().String()
	directory := filepath.Join(string(root), svc.Configuration.Flows[0].Name.String(), id)
	require.NoError(t, os.MkdirAll(directory, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "s"), []byte("private damaged bytes"), 0600))
	code, result, body := managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all"})
	require.Equal(t, 200, code, body)
	require.Positive(t, result.Sessions.Skipped)
	require.NotContains(t, body, string(root))
	require.NotContains(t, body, "private damaged bytes")
	_, err := os.Stat(directory)
	require.NoError(t, err)
}

func TestWebManagementForcedCommandCredentialsFailClosed(t *testing.T) {
	signer := webLoginTestSigner(t)
	_, handler, _, _ := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = crypto.AuthorizedKeys(`command="flow ls" ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
	})
	attempt := startWebAttempt(t, handler, "public-key", "alice", "Work", signer.PublicKey())
	step := waitWebLoginStep(t, handler, attempt, "Work")
	require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, signWebChallenge(t, signer, step)).Code)
	token := webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
	code, _, _ := managementWebRead(t, handler, token, "flows/list", nil)
	require.Equal(t, 403, code)
}
