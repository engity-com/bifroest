package service

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
)

func forcedManagementWebLogin(t *testing.T, svc *service, handler http.Handler, command string) string {
	t.Helper()
	signer := webLoginTestSigner(t)
	entry := &svc.Configuration.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0]
	entry.AuthorizedKeys = crypto.AuthorizedKeys("command=" + strconv.Quote(command) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
	attempt := startWebAttempt(t, handler, "public-key", "alice", "Work", signer.PublicKey())
	step := waitWebLoginStep(t, handler, attempt, "Work")
	require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, signWebChallenge(t, signer, step)).Code)
	return webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
}

func TestForcedManagementSessionReadIntersectsFiltersAndWithholdsExtraMetadata(t *testing.T) {
	svc, handler, recorder, manager, _, target := managementActionFixture(t)
	_, err := svc.sessions.Create(t.Context(), "other", associationAdapterRemote("bob"), nil)
	require.NoError(t, err)
	second, err := svc.sessions.Create(t.Context(), target.Flow(), associationAdapterRemote("bob"), nil)
	require.NoError(t, err)
	_, err = svc.sessions.Create(t.Context(), target.Flow(), associationAdapterRemote("alice"), nil)
	require.NoError(t, err)
	for _, format := range []string{"table", "json", "yaml", "cbor"} {
		t.Run(format, func(t *testing.T) {
			token := forcedManagementWebLogin(t, svc, handler, "session ls --flow=worker --user=bob --state=all --format="+format)
			code, _, _ := managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "active"})
			require.Equal(t, 403, code, "an additional active predicate must not reveal the withheld/exact validity deadline")
			var ids []string
			after := ""
			for range 2 {
				code, result, body := managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all", "limit": "1", "after": after})
				require.Equal(t, 200, code, body)
				require.Len(t, result.Sessions.Items, 1)
				item := result.Sessions.Items[0]
				ids = append(ids, item.ID)
				require.Equal(t, "worker", item.Flow)
				require.Equal(t, "bob", item.User)
				require.Nil(t, item.Owner)
				require.True(t, item.PolicyLimited)
				if format == "table" {
					require.Empty(t, item.Remote)
					require.Nil(t, item.ValidUntil)
					require.Nil(t, item.LastAccessed)
				} else {
					require.NotEmpty(t, item.Remote)
				}
				after = result.Sessions.Next
			}
			require.ElementsMatch(t, []string{target.Id().String(), second.Id().String()}, ids)
			require.Empty(t, after)
			code, result, body := managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all", "flow": "other"})
			require.Equal(t, 200, code, body)
			require.Empty(t, result.Sessions.Items)
			code, result, body = managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all", "user": "alice"})
			require.Equal(t, 200, code, body)
			require.Empty(t, result.Sessions.Items)
			code, _, _ = managementWebRead(t, handler, token, "flows/list", nil)
			require.Equal(t, 403, code)
			code, _, _ = managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": "worker", "id": target.Id().String()})
			require.Equal(t, 403, code)
			require.Equal(t, 403, managementActionRequest(handler, token, "prepare", map[string]string{"action": "dispose", "flow": "worker", "id": target.Id().String()}).Code)
		})
	}
	code, result, body := managementWebRead(t, handler, manager, "sessions/list", map[string]string{"state": "all", "flow": "worker", "user": "bob"})
	require.Equal(t, 200, code, body)
	for _, item := range result.Sessions.Items {
		if item.ID == target.Id().String() {
			require.NotNil(t, item.Owner)
			require.False(t, item.PolicyLimited)
		}
	}
	starts := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted)
	found := false
	for _, event := range starts {
		if event.ForcedCommand != nil && *event.ForcedCommand {
			found = true
		}
	}
	require.True(t, found, "structured forced reads must be recorded as forced, not unrestricted tasks")
}

func TestForcedManagementSessionReadDoesNotBroadenDefaultActiveState(t *testing.T) {
	svc, handler, _, _, _, target := managementActionFixture(t)
	token := forcedManagementWebLogin(t, svc, handler, "session ls --flow worker --user bob --format json")
	code, result, body := managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all"})
	require.Equal(t, 200, code, body)
	require.Empty(t, result.Sessions.Items)
	_, err := target.NotifyLastAccess(t.Context(), associationAdapterRemote("bob"), session.StateAuthorized)
	require.NoError(t, err)
	code, result, body = managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all"})
	require.Equal(t, 200, code, body)
	require.Len(t, result.Sessions.Items, 1)
	require.Equal(t, target.Id().String(), result.Sessions.Items[0].ID)
	code, result, body = managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "new"})
	require.Equal(t, 200, code, body)
	require.Empty(t, result.Sessions.Items)
}

func TestForcedManagementSingleReadRequiresExactIDAndPreservesGlobalAmbiguity(t *testing.T) {
	svc, handler, _, _, _, target := managementActionFixture(t)
	token := forcedManagementWebLogin(t, svc, handler, "session show "+target.Id().String()+" --format=json")
	code, result, body := managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": target.Flow().String(), "id": target.Id().String()})
	require.Equal(t, 200, code, body)
	require.Nil(t, result.Session.Owner)
	require.True(t, result.Session.PolicyLimited)
	require.NotEmpty(t, result.Session.Remote)
	code, _, _ = managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": target.Flow().String(), "id": session.MustNewId().String()})
	require.Equal(t, 403, code)
	code, _, _ = managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all"})
	require.Equal(t, 403, code)
	original := svc.sessions
	svc.sessions = &ambiguousForcedReadRepository{CloseableRepository: original, target: target}
	defer func() { svc.sessions = original }()
	code, _, body = managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": target.Flow().String(), "id": target.Id().String()})
	require.Equal(t, 503, code)
	require.NotContains(t, body, `"session"`)
}

type ambiguousForcedReadRepository struct {
	session.CloseableRepository
	target session.Session
}

func (this *ambiguousForcedReadRepository) FindAll(ctx context.Context, consume session.Consumer, opts *session.FindOpts) error {
	if err := this.CloseableRepository.FindAll(ctx, consume, opts); err != nil {
		return err
	}
	_, err := consume(ctx, &forcedReadOtherFlowSession{Session: this.target})
	return err
}

type forcedReadOtherFlowSession struct{ session.Session }

func (*forcedReadOtherFlowSession) Flow() configuration.FlowName { return "other" }

func TestForcedManagementReferenceSSHAndHTTPAgreeOnSupportedDataCeilings(t *testing.T) {
	for _, kind := range []string{"flow", "session"} {
		for _, format := range []string{"table", "json", "yaml", "cbor"} {
			t.Run(kind+"/"+format, func(t *testing.T) {
				command := kind + " ls --format=" + format
				if kind == "session" {
					command += " --user=alice --state=all --flow=restricted-key"
				}
				server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, "alice", "command="+strconv.Quote(command), nil, func(conf *configuration.Configuration) {
					conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
				})
				client := server.mustDial(t)
				defer client.Close()
				invocation, err := client.NewSession()
				require.NoError(t, err)
				output, err := invocation.Output("session dispose ignored-client-argument")
				require.NoError(t, err, "the existing SSH driver must override the client request")
				svc := server.service
				svc.web = newWebService(svc)
				handler, err := https.Boundary(configuration.HttpDomains{"app.example.org"}, svc.web)
				require.NoError(t, err)
				attempt := startWebAttempt(t, handler, "public-key", "alice", "Work", server.signer.PublicKey())
				step := waitWebLoginStep(t, handler, attempt, "Work")
				require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, signWebChallenge(t, server.signer, step)).Code)
				token := webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
				if kind == "flow" {
					code, result, body := managementWebRead(t, handler, token, "flows/list", nil)
					require.Equal(t, 200, code, body)
					if format == "table" {
						require.Contains(t, string(output), "restricted-key")
						require.Contains(t, string(output), "management")
					} else {
						var rows []protocol.FlowSummary
						decodeForcedReadReference(t, format, output, &rows)
						require.Equal(t, rows, result.Flows.Items)
					}
				} else {
					code, result, body := managementWebRead(t, handler, token, "sessions/list", map[string]string{"state": "all"})
					require.Equal(t, 200, code, body)
					require.Len(t, result.Sessions.Items, 1)
					item := result.Sessions.Items[0]
					require.Nil(t, item.Owner)
					require.True(t, item.PolicyLimited)
					if format == "table" {
						require.Contains(t, string(output), item.ID)
						require.Empty(t, item.Remote)
						require.NotContains(t, string(output), "alice@127.0.0.1")
					} else {
						var rows []protocol.SessionView
						decodeForcedReadReference(t, format, output, &rows)
						require.Len(t, rows, 1)
						require.Equal(t, rows[0].ID, item.ID)
						require.Equal(t, rows[0].Flow, item.Flow)
						require.Equal(t, rows[0].User, item.User)
						require.Equal(t, rows[0].CreatedAt, item.CreatedAt)
						require.Equal(t, rows[0].Remote, item.Remote)
					}
				}
			})
		}
	}
}

func decodeForcedReadReference(t *testing.T, format string, raw []byte, target any) {
	t.Helper()
	switch format {
	case "json":
		require.NoError(t, json.Unmarshal(raw, target))
	case "yaml":
		require.NoError(t, yaml.Unmarshal(raw, target))
	case "cbor":
		require.NoError(t, cbor.Unmarshal(raw, target))
	default:
		t.Fatal("unsupported reference format")
	}
}

func TestForcedManagementShowReferenceSSHAndHTTPKeepExactIDAndPrecision(t *testing.T) {
	for _, format := range []string{"table", "json", "yaml", "cbor"} {
		t.Run(format, func(t *testing.T) {
			server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, "alice", `command="flow ls"`, nil, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
			})
			initial := server.mustDial(t)
			require.NoError(t, initial.Close())
			var target session.Session
			require.NoError(t, server.service.sessions.FindAll(t.Context(), func(_ context.Context, current session.Session) (bool, error) { target = current; return false, nil }, nil))
			require.NotNil(t, target)
			command := "session show " + target.Id().String() + " --format=" + format
			server.service.Configuration.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].AuthorizedKeys = crypto.AuthorizedKeys("command=" + strconv.Quote(command) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(server.signer.PublicKey()))))
			client := server.mustDial(t)
			defer client.Close()
			invocation, err := client.NewSession()
			require.NoError(t, err)
			output, err := invocation.Output("flow ls")
			require.NoError(t, err)
			svc := server.service
			svc.web = newWebService(svc)
			handler, err := https.Boundary(configuration.HttpDomains{"app.example.org"}, svc.web)
			require.NoError(t, err)
			attempt := startWebAttempt(t, handler, "public-key", "alice", "Work", server.signer.PublicKey())
			step := waitWebLoginStep(t, handler, attempt, "Work")
			require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, signWebChallenge(t, server.signer, step)).Code)
			token := webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
			code, result, body := managementWebRead(t, handler, token, "sessions/show", map[string]string{"flow": target.Flow().String(), "id": target.Id().String()})
			require.Equal(t, 200, code, body)
			item := result.Session
			require.True(t, item.PolicyLimited)
			require.Nil(t, item.Owner)
			require.NotEmpty(t, item.Remote)
			if format == "table" {
				require.Contains(t, string(output), item.ID)
				require.Contains(t, string(output), item.Remote)
				require.Zero(t, item.CreatedAt.Nanosecond())
			} else {
				var row protocol.SessionView
				decodeForcedReadReference(t, format, output, &row)
				require.Equal(t, row.ID, item.ID)
				require.Equal(t, row.Flow, item.Flow)
				require.Equal(t, row.CreatedAt, item.CreatedAt)
				require.Equal(t, row.Remote, item.Remote)
			}
		})
	}
}
