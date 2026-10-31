package service

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/sys"
)

type versionMarkupTestVersion struct{ serviceTestVersion }

func (versionMarkupTestVersion) Title() string {
	return `<b>version fixture</b><script>window.versionInjected = true</script>`
}

func TestForcedManagementVersionReferenceSSHAndHTTPKeepExactNativeOutput(t *testing.T) {
	for _, test := range []struct {
		command string
		long    bool
	}{
		{"version", true}, {"version --long", true},
		{"version --long=true", true}, {"version --long=false", false},
	} {
		t.Run(test.command, func(t *testing.T) {
			server := newAuthorizedKeysTestServerWithUsernameAndConfiguration(t, "alice", "command="+strconv.Quote(test.command), nil, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{IncludingCredentials: true, AllowArtifactTransfer: true}
			})
			client := server.mustDial(t)
			invocation, err := client.NewSession()
			require.NoError(t, err)
			reference, err := invocation.Output("session dispose ignored-client-command")
			require.NoError(t, err)
			svc := server.service
			svc.web = newWebService(svc)
			handler, err := https.Boundary(configuration.HttpDomains{"app.example.org"}, svc.web)
			require.NoError(t, err)
			attempt := startWebAttempt(t, handler, "public-key", "alice", "Work", server.signer.PublicKey())
			step := waitWebLoginStep(t, handler, attempt, "Work")
			require.Equal(t, 202, answerWebStep(handler, attempt, "Work", step, signWebChallenge(t, server.signer, step)).Code)
			token := webTestToken(t, finishWebAttempt(t, handler, attempt, "Work"))
			svc.managementApplication = nil // HTTP must use no CLI parser or SSH self-dial.
			code, result, body := managementWebRead(t, handler, token, "version/show", map[string]string{"long": strconv.FormatBool(test.long)})
			require.Equal(t, 200, code, body)
			require.Equal(t, protocol.ShowVersion, result.Operation)
			require.NotNil(t, result.VersionInfo)
			require.Equal(t, string(reference), result.VersionInfo.Text)
			detail := "short"
			if test.long {
				detail = "long"
			}
			require.Equal(t, detail, result.VersionInfo.Detail)
			code, _, _ = managementWebRead(t, handler, token, "version/show", map[string]string{"long": strconv.FormatBool(!test.long)})
			require.Equal(t, 403, code, "a fixed short version cannot disclose long metadata, or replace the forced output mode")
			for route, fields := range map[string]map[string]string{
				"flows/list": {}, "sessions/list": {}, "auditlogs/list": {},
				"sessions/show":   {"flow": "work", "id": "9c77b24c-62f4-44c2-aea3-771c75e5a107"},
				"recordings/list": {"auditlog": "default"},
			} {
				code, _, _ := managementWebRead(t, handler, token, route, fields)
				require.Equal(t, 403, code, route)
			}
			for _, kind := range []string{"audit", "recording"} {
				fields := map[string]string{"auditlog": "default"}
				if kind == "recording" {
					fields["id"] = "9c77b24c-62f4-44c2-aea3-771c75e5a107"
				}
				require.Equal(t, 403, artifactWebRequest(handler, token, kind, fields).Code)
			}
			require.Equal(t, 403, managementActionRequest(handler, token, "prepare", map[string]string{"action": "dispose", "flow": "work", "id": "9c77b24c-62f4-44c2-aea3-771c75e5a107"}).Code)
		})
	}
}

func TestWebVersionReadKeepsBoundsInputsQuotaAndFinalAudit(t *testing.T) {
	svc, handler, recorder, sibling := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
	token := forcedManagementWebLogin(t, svc, handler, "version --long=false")
	for _, fields := range []map[string]string{{"long": "False"}, {"long": "0"}, {"long": "true", "limit": "1"}, {"long": "false", "includingCredentials": "true"}, {"long": "false", "command": "version"}} {
		code, _, _ := managementWebRead(t, handler, token, "version/show", fields)
		require.Equal(t, 400, code)
	}
	access := webTestAccess(t, svc, token, "Work")
	lease, err := access.auth.FindSession().ConnectionInterceptor(t.Context())
	require.NoError(t, err)
	code, _, _ := managementWebRead(t, handler, token, "version/show", map[string]string{"long": "false"})
	require.Equal(t, 403, code)
	require.NoError(t, lease.Close())
	code, result, body := managementWebRead(t, handler, token, "version/show", map[string]string{"long": "false"})
	require.Equal(t, 200, code, body)
	require.Equal(t, sys.FormatVersion(svc.Version, sys.VersionFormatShort)+"\n", result.VersionInfo.Text)
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, errors.New("private version final audit failure"))
	code, _, body = managementWebRead(t, handler, token, "version/show", map[string]string{"long": "false"})
	require.Equal(t, 503, code)
	require.NotContains(t, body, "versionInfo")
	require.NotContains(t, body, "private version")
	recorder.setErrorBeforeRecordForName(audit.EventNameSessionTaskCompleted, nil)
	require.Equal(t, 204, webTestRequest(handler, "POST", "app.example.org", webAPI+"logout", `{"slug":"Work"}`, token).Code)
	code, _, _ = managementWebRead(t, handler, token, "version/show", map[string]string{"long": "false"})
	require.Equal(t, 401, code)
	code, result, body = managementWebRead(t, handler, sibling, "version/show", nil)
	require.Equal(t, 200, code, body)
	require.Equal(t, "long", result.VersionInfo.Detail)

	_, plainHandler, _ := webTestFixture(t)
	plainToken := webTestToken(t, webTestPassword(plainHandler, "alice", "correct", "Work"))
	code, _, _ = managementWebRead(t, plainHandler, plainToken, "version/show", nil)
	require.Equal(t, 403, code, "a terminal grant is not management authorization")
	svc.Version = oversizedVersion{serviceTestVersion{}}
	code, _, body = managementWebRead(t, handler, sibling, "version/show", nil)
	require.Equal(t, 503, code)
	require.NotContains(t, body, "versionInfo")
}

type oversizedVersion struct{ serviceTestVersion }

func (oversizedVersion) Title() string { return strings.Repeat("v", protocol.MaximumResponseBytes) }
