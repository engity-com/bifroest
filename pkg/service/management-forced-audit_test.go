package service

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
)

// Configuration metadata only: add disabled summaries after fixture startup,
// without opening their deliberately private/nonexistent files or repositories.
func addForcedAuditSummaries(svc *service) {
	for index := 20; index >= 0; index-- {
		svc.Configuration.Auditlogs = append(svc.Configuration.Auditlogs, configuration.Auditlog{
			Name: configuration.AuditlogName(fmt.Sprintf("audit%02d", index)), Enabled: false,
			Directory: "private audit directory", IdentityFile: "private identity file",
			EncryptionPublicKeyFile: crypto.PublicKeysFile("private recipient file"),
		})
	}
}

func TestForcedManagementAuditReadPagesWithoutCliAndCannotCrossOperation(t *testing.T) {
	for _, format := range []string{"table", "json", "yaml", "cbor"} {
		t.Run(format, func(t *testing.T) {
			svc, handler, recorder, _ := managementWebFixture(t, func(conf *configuration.Configuration) {
				management := conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement)
				management.AllowArtifactTransfer, management.IncludingCredentials = true, true
			})
			svc.managementApplication = nil
			addForcedAuditSummaries(svc)
			id := catalogRecording(t, svc, "default", 1)
			token := forcedManagementWebLogin(t, svc, handler, "audit ls --format="+format)
			var names []string
			after := ""
			for _, size := range []int{20, 2} {
				code, result, body := managementWebRead(t, handler, token, "auditlogs/list", map[string]string{"after": after})
				require.Equal(t, 200, code, body)
				require.Len(t, result.Auditlogs.Items, size)
				for _, row := range result.Auditlogs.Items {
					names = append(names, row.Name)
					if row.Name != "default" {
						require.False(t, row.Enabled)
						require.False(t, row.RecordingEnabled)
						require.True(t, row.Encrypted)
					}
				}
				after = result.Auditlogs.Next
				for _, secret := range []string{token, "private", "identityFile", "directory", "recipient file", "plain:correct", `"owner"`, `"producerId"`} {
					require.NotContains(t, body, secret)
				}
			}
			require.Empty(t, after)
			require.Len(t, names, 22)
			require.Equal(t, "audit00", names[0])
			require.Equal(t, "audit20", names[20])
			require.Equal(t, "default", names[21])
			for route, fields := range map[string]map[string]string{
				"flows/list": {}, "sessions/list": {"state": "all"},
				"sessions/show":   {"flow": "work", "id": id.String()},
				"recordings/list": {"auditlog": "default"},
			} {
				code, _, body := managementWebRead(t, handler, token, route, fields)
				require.Equal(t, 403, code, route+body)
			}
			for _, action := range []string{"disconnect", "dispose"} {
				require.Equal(t, 403, managementActionRequest(handler, token, "prepare", map[string]string{"action": action, "flow": "work", "id": id.String()}).Code)
			}
			for _, kind := range []string{"recording", "audit"} {
				fields := map[string]string{"auditlog": "default"}
				if kind == "recording" {
					fields["id"] = id.String()
				}
				require.Equal(t, 403, artifactWebRequest(handler, token, kind, fields).Code, "the configured transfer right does not remove a forced read ceiling")
			}
			code, _, _ := managementWebRead(t, handler, token, "auditlogs/list", map[string]string{"includingCredentials": "true"})
			require.Equal(t, 400, code)
			starts := auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskStarted)
			require.Len(t, starts, 2, "denied cross-operation requests must not start a driver execution")
			for _, event := range starts {
				require.NotNil(t, event.ForcedCommand)
				require.True(t, *event.ForcedCommand)
			}
			require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionTaskCompleted), 2)
			// Real recording lifecycle still belongs to each successful metadata read.
			require.Len(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionRecordingCompleted), 3)
			recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, errors.New("private forced audit completion failure"))
			code, _, body := managementWebRead(t, handler, token, "auditlogs/list", nil)
			require.Equal(t, 503, code, body)
			require.NotContains(t, body, `"items"`)
			require.NotContains(t, body, "private forced")
		})
	}
}

func TestForcedManagementAuditReadRetainsQuotaAndLogoutIsolation(t *testing.T) {
	svc, handler, _, sibling := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
	token := forcedManagementWebLogin(t, svc, handler, "audit ls")
	access := webTestAccess(t, svc, token, "Work")
	saved := access.auth.FindSession()
	require.Equal(t, saved.Id(), webTestAccess(t, svc, sibling, "Work").auth.FindSession().Id())
	lease, err := saved.ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	code, _, _ := managementWebRead(t, handler, token, "auditlogs/list", nil)
	require.Equal(t, 403, code)
	require.NoError(t, lease.Close())
	code, _, body := managementWebRead(t, handler, token, "auditlogs/list", nil)
	require.Equal(t, 200, code, body)
	require.Equal(t, 204, webTestRequest(handler, "POST", "app.example.org", webAPI+"logout", `{"slug":"Work"}`, token).Code)
	code, _, _ = managementWebRead(t, handler, token, "auditlogs/list", nil)
	require.Equal(t, 401, code)
	code, _, body = managementWebRead(t, handler, sibling, "flows/list", nil)
	require.Equal(t, 200, code, body, "logout must not revoke the sibling's independent permission")
	info, err := saved.Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateAuthorized, info.State(), "metadata/logout must not dispose the persistent session")
}

func TestForcedManagementAuditReadReferenceSSHAndHTTPExposeTheSameSummary(t *testing.T) {
	for _, format := range []string{"table", "json", "yaml", "cbor"} {
		t.Run(format, func(t *testing.T) {
			server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, "alice", "command="+strconv.Quote("audit ls --format="+format), nil, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
			})
			svc := server.service
			addForcedAuditSummaries(svc)
			client := server.mustDial(t)
			invocation, err := client.NewSession()
			require.NoError(t, err)
			output, err := invocation.Output("session dispose ignored-client-command")
			require.NoError(t, err)
			require.NotContains(t, string(output), "private")
			var reference []protocol.AuditlogSummary
			if format == "table" {
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")
				require.Equal(t, []string{"NAME", "AUDIT", "RECORDING", "ENCRYPTED"}, strings.Fields(lines[0]))
				for _, line := range lines[1:] {
					cells := strings.Fields(line)
					require.Len(t, cells, 4)
					enabled, err := strconv.ParseBool(cells[1])
					require.NoError(t, err)
					recording, err := strconv.ParseBool(cells[2])
					require.NoError(t, err)
					encrypted, err := strconv.ParseBool(cells[3])
					require.NoError(t, err)
					reference = append(reference, protocol.AuditlogSummary{Name: cells[0], Enabled: enabled, RecordingEnabled: recording, Encrypted: encrypted})
				}
			} else {
				decodeForcedReadReference(t, format, output, &reference)
			}
			svc.web = newWebService(svc)
			handler, err := https.Boundary(configuration.HttpDomains{"app.example.org"}, svc.web)
			require.NoError(t, err)
			attempt := startWebAttempt(t, handler, "public-key", "alice", "Work", server.signer.PublicKey())
			step := waitWebLoginStep(t, handler, attempt, "Work")
			require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, signWebChallenge(t, server.signer, step)).Code)
			token := webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
			// HTTP must not depend on the SSH CLI application used by the reference.
			svc.managementApplication = nil
			var actual []protocol.AuditlogSummary
			after := ""
			for {
				code, result, body := managementWebRead(t, handler, token, "auditlogs/list", map[string]string{"after": after})
				require.Equal(t, 200, code, body)
				actual = append(actual, result.Auditlogs.Items...)
				after = result.Auditlogs.Next
				if after == "" {
					break
				}
			}
			require.Equal(t, reference, actual)
		})
	}
}
