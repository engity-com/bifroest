package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestForcedManagementActionPreparationWithholdsAllInspectionMetadata(t *testing.T) {
	for _, action := range []string{"disconnect", "dispose"} {
		t.Run(action, func(t *testing.T) {
			svc, handler, recorder, _, worker, target := managementActionFixture(t)
			token := forcedManagementWebLogin(t, svc, handler, "session "+action+" "+target.Id().String())
			conn, err := svc.web.connect(webScope{Origin: "https://app.example.org", Slug: "Worker"}, worker, newWebTestTerminalTransport(t))
			require.NoError(t, err)
			defer conn.Close()
			for _, wrong := range []map[string]string{
				{"action": map[string]string{"disconnect": "dispose", "dispose": "disconnect"}[action], "flow": "worker", "id": target.Id().String()},
				{"action": action, "flow": "worker", "id": session.MustNewId().String()},
			} {
				require.Equal(t, 403, managementActionRequest(handler, token, "prepare", wrong).Code)
			}
			for _, route := range []string{"flows/list", "sessions/list", "sessions/show", "auditlogs/list", "version/show"} {
				fields := map[string]string(nil)
				if route == "sessions/show" {
					fields = map[string]string{"flow": "worker", "id": target.Id().String()}
				}
				code, _, _ := managementWebRead(t, handler, token, route, fields)
				require.Equal(t, 403, code, route)
			}
			response := managementActionRequest(handler, token, "prepare", map[string]string{"action": action, "flow": "worker", "id": target.Id().String()})
			require.Equal(t, 202, response.Code, response.Body.String())
			var prepared protocol.ActionPreparation
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &prepared))
			require.Nil(t, prepared.Target.Details)
			var shape map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &shape))
			require.JSONEq(t, `{"flow":"worker","id":"`+target.Id().String()+`"}`, string(shape["target"]))
			for _, hidden := range []string{"owner", "createdAt", "remote", "state", "user", "lastAccessed", "validUntil", "details"} {
				require.NotContains(t, response.Body.String(), `"`+hidden+`"`)
			}
			require.False(t, conn.IsClosed(), "preparation cannot disconnect")
			require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisconnectStarted))
			require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeStarted))
			response = managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken, "action": action})
			require.Equal(t, 400, response.Code)
			response = managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
			require.Equal(t, 200, response.Code, response.Body.String())
			require.True(t, conn.IsClosed())
			require.Equal(t, 403, managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
			current, err := svc.sessions.FindBy(t.Context(), target.Flow(), target.Id(), nil)
			require.NoError(t, err)
			info, err := current.Info(t.Context())
			require.NoError(t, err)
			require.Equal(t, action == "dispose", info.State() == session.StateDisposed)
			starts := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted)
			require.Len(t, starts, 2, "one audited preparation and one commit, no hidden ShowSession")
			for _, event := range starts {
				require.NotNil(t, event.ForcedCommand)
				require.True(t, *event.ForcedCommand)
			}
			require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionRecordingCompleted), 2)
			sealed, err := svc.recordingRepositories[svc.Configuration.Auditlogs[0].Name].native.ListSealed(t.Context())
			require.NoError(t, err)
			require.Len(t, sealed, 2, "preparation and commit each seal their own recording before delivery")
		})
	}
}

func TestForcedManagementActionKeepsGlobalAmbiguityAtPreparationAndCommit(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(strconv.FormatBool(late), func(t *testing.T) {
			svc, handler, recorder, _, _, target := managementActionFixture(t)
			token := forcedManagementWebLogin(t, svc, handler, "session dispose "+target.Id().String())
			var prepared protocol.ActionPreparation
			if late {
				prepared = prepareManagementAction(t, handler, token, "dispose", target)
			}
			original := svc.sessions
			svc.sessions = &ambiguousForcedReadRepository{CloseableRepository: original, target: target}
			defer func() { svc.sessions = original }()
			if late {
				require.Equal(t, 503, managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
				require.Equal(t, 403, managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
			} else {
				require.Equal(t, 503, managementActionRequest(handler, token, "prepare", map[string]string{"action": "dispose", "flow": "worker", "id": target.Id().String()}).Code)
			}
			require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeStarted))
		})
	}
}

func TestForcedManagementActionConfirmationKeepsGrantPeerExpiryCancelAndOneShotBounds(t *testing.T) {
	svc, handler, recorder, _, _, target := managementActionFixture(t)
	command := "session disconnect " + target.Id().String()
	token := forcedManagementWebLogin(t, svc, handler, command)
	prepared := prepareManagementAction(t, handler, token, "disconnect", target)
	sibling := forcedManagementWebLogin(t, svc, handler, command)
	require.Equal(t, 403, managementActionRequest(handler, sibling, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	otherPeer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "192.0.2.12:2345"
		handler.ServeHTTP(w, r)
	})
	require.Equal(t, 403, managementActionRequest(otherPeer, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	require.Equal(t, 204, managementActionRequest(handler, token, "cancel", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	require.Equal(t, 403, managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	prepared = prepareManagementAction(t, handler, token, "disconnect", target)
	index, _ := managementConfirmationKey(prepared.ConfirmationToken)
	svc.web.mutex.Lock()
	svc.web.confirmations[index].expires = time.Now().Add(-time.Second)
	svc.web.mutex.Unlock()
	require.Equal(t, 403, managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	prepared = prepareManagementAction(t, handler, token, "disconnect", target)
	var group sync.WaitGroup
	results := make(chan int, 2)
	for range 2 {
		group.Go(func() {
			results <- managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code
		})
	}
	group.Wait()
	close(results)
	var codes []int
	for code := range results {
		codes = append(codes, code)
	}
	require.ElementsMatch(t, []int{200, 403}, codes)
	require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisconnectStarted), 1)
}

func TestForcedManagementActionRechecksGenerationAfterStartedAudit(t *testing.T) {
	svc, handler, recorder, _, _, target := managementActionFixture(t)
	token := forcedManagementWebLogin(t, svc, handler, "session dispose "+target.Id().String())
	prepared := prepareManagementAction(t, handler, token, "dispose", target)
	replacement, err := svc.sessions.Create(t.Context(), target.Flow(), associationAdapterRemote("replacement"), nil)
	require.NoError(t, err)
	root := string(svc.Configuration.Session.V.(*configuration.SessionFs).Storage)
	path := filepath.Join(root, target.Flow().String(), target.Id().String())
	other := filepath.Join(root, replacement.Flow().String(), replacement.Id().String())
	hook := &managementActionAuditHook{Recorder: recorder, before: func() {
		require.NoError(t, os.Rename(path, path+"-old-fixture"))
		require.NoError(t, os.Rename(other, path))
	}}
	svc.flowAuditRecorders[webTestAccess(t, svc, token, "Work").auth.Flow()] = hook
	response := managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, 503, response.Code)
	require.Equal(t, 403, managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	current, err := svc.sessions.FindBy(t.Context(), target.Flow(), target.Id(), nil)
	require.NoError(t, err)
	info, err := current.Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateNew, info.State())
	events := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeCompleted)
	require.Len(t, events, 1)
	require.Equal(t, audit.EventOutcomeFailure, events[0].Outcome)
}

func TestForcedManagementActionCannotTargetItsOwnSharedSession(t *testing.T) {
	svc, handler, recorder, manager, _, _ := managementActionFixture(t)
	self := webTestAccess(t, svc, manager, "Work").auth.FindSession()
	token := forcedManagementWebLogin(t, svc, handler, "session dispose "+self.Id().String())
	require.Equal(t, self.Id(), webTestAccess(t, svc, token, "Work").auth.FindSession().Id())
	require.Equal(t, 403, managementActionRequest(handler, token, "prepare", map[string]string{"flow": self.Flow().String(), "id": self.Id().String(), "action": "dispose"}).Code)
	require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeStarted))
}

func TestForcedManagementActionRetainsConnectionQuotaAndConsumesFailedCommit(t *testing.T) {
	svc, handler, recorder, _ := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
	target, err := svc.sessions.Create(t.Context(), "other", associationAdapterRemote("target"), nil)
	require.NoError(t, err)
	token := forcedManagementWebLogin(t, svc, handler, "session disconnect "+target.Id().String())
	caller := webTestAccess(t, svc, token, "Work").auth.FindSession()
	lease, err := caller.ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	require.Equal(t, 403, managementActionRequest(handler, token, "prepare", map[string]string{"action": "disconnect", "flow": "other", "id": target.Id().String()}).Code)
	require.NoError(t, lease.Close())
	prepared := prepareManagementAction(t, handler, token, "disconnect", target)
	lease, err = caller.ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	require.Equal(t, 403, managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	require.NoError(t, lease.Close())
	require.Equal(t, 403, managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
	require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisconnectStarted))
}

func TestForcedManagementActionRechecksChangedPolicyAndDoesNotReplayUncertainEffect(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(strconv.FormatBool(changed), func(t *testing.T) {
			svc, handler, recorder, _, _, target := managementActionFixture(t)
			token := forcedManagementWebLogin(t, svc, handler, "session dispose "+target.Id().String())
			prepared := prepareManagementAction(t, handler, token, "dispose", target)
			if changed {
				// Simulate an authorization's narrowed live policy, not a saved ceiling.
				policy := authorization.AuthorizedKeyPolicyOf(webTestAccess(t, svc, token, "Work").auth)
				command := "session disconnect " + target.Id().String()
				policy.ForcedCommand = &command
			} else {
				recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, errors.New("private final audit failure"))
			}
			response := managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
			if changed {
				require.Equal(t, 403, response.Code)
				require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisposeStarted))
			} else {
				require.Equal(t, 503, response.Code)
				current, err := svc.sessions.FindBy(t.Context(), target.Flow(), target.Id(), nil)
				require.NoError(t, err)
				info, err := current.Info(t.Context())
				require.NoError(t, err)
				require.Equal(t, session.StateDisposed, info.State())
			}
			require.NotContains(t, response.Body.String(), "private final audit failure")
			require.Equal(t, 403, managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken}).Code)
		})
	}
}

func TestForcedManagementActionReferenceSSHAndHTTPUseSameOperationTargetAndFormats(t *testing.T) {
	for _, action := range []string{"disconnect", "dispose"} {
		for _, format := range []string{"table", "json", "yaml", "cbor"} {
			t.Run(action+"/"+format, func(t *testing.T) {
				server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, "alice", `command="flow ls"`, nil, func(conf *configuration.Configuration) {
					conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
					worker := conf.Flows[0]
					worker.Name = "worker"
					worker.DiscoverAsSlug = "Worker"
					worker.Environment.V = &configuration.EnvironmentDummy{}
					conf.Flows = append(conf.Flows, worker)
				})
				svc := server.service
				target, err := svc.sessions.Create(t.Context(), "worker", associationAdapterRemote("private-target"), nil)
				require.NoError(t, err)
				command := "session " + action + " " + target.Id().String() + " --format=" + format
				svc.Configuration.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = crypto.AuthorizedKeys("command=" + strconv.Quote(command) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(server.signer.PublicKey()))))
				client := server.mustDial(t)
				defer client.Close()
				invocation, err := client.NewSession()
				require.NoError(t, err)
				output, err := invocation.Output("session show ignored-client-target")
				require.NoError(t, err)
				svc.web = newWebService(svc)
				handler, err := https.Boundary(configuration.HttpDomains{"app.example.org"}, svc.web)
				require.NoError(t, err)
				attempt := startWebAttempt(t, handler, "public-key", "alice", "Work", server.signer.PublicKey())
				step := waitWebLoginStep(t, handler, attempt, "Work")
				require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, signWebChallenge(t, server.signer, step)).Code)
				token := webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
				prepared := prepareManagementAction(t, handler, token, action, target)
				require.Nil(t, prepared.Target.Details)
				response := managementActionRequest(handler, token, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				var result protocol.ActionResult
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
				if format == "table" {
					require.Contains(t, string(output), target.Id().String())
					require.Contains(t, string(output), action)
				} else {
					var native protocol.SessionActionResult
					decodeForcedReadReference(t, format, output, &native)
					require.Equal(t, native, result.Result)
				}
			})
		}
	}
}
