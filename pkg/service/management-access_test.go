package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/access"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/session"
)

func managementTestEnvironment(credentials, downloads bool) *configuration.EnvironmentManagement {
	result := &configuration.EnvironmentManagement{}
	setManagementTestCredentials(result, credentials)
	setManagementTestDownloads(result, downloads)
	return result
}

func setManagementTestCredentials(conf *configuration.EnvironmentManagement, allowed bool) {
	conf.Access = conf.Access.WithConstant(access.FlowsCredentials, allowed)
}

func setManagementTestDownloads(conf *configuration.EnvironmentManagement, allowed bool) {
	conf.Access = conf.Access.WithConstant(access.AuditlogsDownload, allowed).WithConstant(access.RecordingsDownload, allowed)
}

func managementTestPolicy(t *testing.T, source string) access.Policy {
	t.Helper()
	var result access.Policy
	require.NoError(t, yaml.Unmarshal([]byte(source), &result))
	return result
}

func TestManagementAccessSSHRecursiveAndTemplateMatrix(t *testing.T) {
	for _, test := range []struct {
		name, source                          string
		metrics, flows, sessions, credentials bool
	}{
		{"default", "", true, true, true, false},
		{"all", "true", true, true, true, true},
		{"none", "false", false, false, false, false},
		{"empty", "{}", false, false, false, false},
		{"metrics group", "metrics: true", true, false, false, false},
		{"metrics leaf", "metrics: {read: true}", true, false, false, false},
		{"sessions group", "sessions: true", false, false, true, false},
		{"root template", `'{{ eq .authorization.entry.name "restricted-key-user" }}'`, true, true, true, true},
		{"leaf template", `metrics: {read: '{{ eq .connection.transport "ssh" }}'}`, true, false, false, false},
		{"invalid unrelated", "metrics: true\nsessions: '{{ fail \"PRIVATE-CLAIM\" }}'", true, false, false, false},
		{"invalid root", `'{{ print "PRIVATE-CLAIM" }}'`, false, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var policy access.Policy
			if test.source != "" {
				policy = managementTestPolicy(t, test.source)
			}
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{Access: policy}
			})
			client := server.mustDial(t)
			for _, query := range []struct {
				args       []string
				allowed    bool
				permission access.Permission
			}{
				{[]string{"metrics", "show", "bifroest_connections_active"}, test.metrics, access.MetricsRead},
				{[]string{"flow", "ls"}, test.flows, access.FlowsRead},
				{[]string{"session", "ls"}, test.sessions, access.SessionsRead},
			} {
				formats := []string{"table", "json", "yaml", "cbor", "wire"}
				if query.permission == access.MetricsRead {
					formats = []string{"table", "json", "openmetrics", "wire"}
				}
				for _, format := range formats {
					channel, err := client.NewSession()
					require.NoError(t, err)
					var stderr bytes.Buffer
					channel.Stderr = &stderr
					command := strings.Join(query.args, " ") + " --format=" + format
					if format == "wire" {
						encoded, err := transport.EncodeWireRequest(query.args)
						require.NoError(t, err)
						channel.Stdin = bytes.NewReader(encoded)
						command = transport.WireCommand
					}
					content, err := channel.Output(command)
					_ = channel.Close()
					if query.allowed {
						require.NoError(t, err, stderr.String())
					} else {
						require.Error(t, err)
						require.Empty(t, content)
						require.Contains(t, stderr.String(), "management access denied: "+string(query.permission))
					}
					require.NotContains(t, stderr.String(), "PRIVATE-CLAIM")
				}
			}
			if test.flows {
				channel, err := client.NewSession()
				require.NoError(t, err)
				output, err := channel.Output("flow show restricted-key --format=yaml")
				require.NoError(t, err)
				require.Equal(t, test.credentials, bytes.Contains(output, []byte("ssh-ed25519")))
			}
		})
	}
}

func TestManagementAccessSSHChecksEveryOperationBeforeLookup(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{Access: access.Constant(false)}
	})
	client := server.mustDial(t)
	id := session.MustNewId().String()
	for _, test := range []struct {
		command    string
		permission access.Permission
	}{
		{"version", access.VersionRead}, {"flow show restricted-key", access.FlowsRead},
		{"session show " + id, access.SessionsRead}, {"session disconnect " + id, access.SessionsDisconnect}, {"session dispose " + id, access.SessionsDispose},
		{"audit ls", access.AuditlogsRead}, {"audit show default", access.AuditlogsRead}, {"audit producer-id default", access.AuditlogsRead},
		{"audit events default", access.AuditlogsEvents}, {"audit export default", access.AuditlogsEvents}, {"audit merge default", access.AuditlogsEvents}, {"audit verify default", access.AuditlogsVerify},
		{"recording ls default", access.RecordingsRead}, {"recording show default " + id, access.RecordingsRead}, {"recording verify default " + id, access.RecordingsVerify},
		{"recording export --with-sensitive default " + id, access.RecordingsDownload}, {"recording play --with-sensitive default " + id, access.RecordingsDownload},
		{"key export public restricted-key", access.KeysRead},
		{transport.WireAuditCommand, access.AuditlogsDownload}, {transport.WireRecordingCommand, access.RecordingsDownload},
	} {
		t.Run(test.command, func(t *testing.T) {
			channel, err := client.NewSession()
			require.NoError(t, err)
			var stderr bytes.Buffer
			channel.Stderr = &stderr
			output, err := channel.Output(test.command)
			require.Error(t, err)
			require.Empty(t, output)
			require.Contains(t, stderr.String(), "management access denied: "+string(test.permission))
		})
	}
}

func TestManagementAccessHTTPAndWebSocketReadMatrix(t *testing.T) {
	for _, selected := range access.Permissions() {
		t.Run(string(selected), func(t *testing.T) {
			policy := access.Constant(false).WithConstant(selected, true)
			fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{Access: policy}
			})
			token := fixture.login(t)
			socket := managementChannelDial(t, fixture, token, false)
			ready := webSocketStatus(t, socket)
			require.JSONEq(t, fmt.Sprintf("[%q]", selected), string(ready["capabilities"]))
			for index, query := range []struct {
				route      string
				fields     map[string]string
				permission access.Permission
			}{
				{"flows/list", nil, access.FlowsRead}, {"sessions/list", map[string]string{"state": "all"}, access.SessionsRead},
				{"auditlogs/list", nil, access.AuditlogsRead}, {"audit-events/list", map[string]string{"auditlog": "default"}, access.AuditlogsEvents},
				{"recordings/list", map[string]string{"auditlog": "default"}, access.RecordingsRead},
				{"recordings/verify", map[string]string{"auditlog": "default"}, access.RecordingsVerify},
				{"version/show", map[string]string{"long": "false"}, access.VersionRead},
			} {
				code, _, body := managementWebRead(t, fixture.svc.web, token, query.route, query.fields)
				if selected != query.permission {
					require.Equal(t, 403, code, body)
				} else {
					require.Equal(t, 200, code, body)
				}
				delete(query.fields, "slug")
				code, data := managementChannelRead(t, socket, fmt.Sprint(index+1), query.route, query.fields)
				if selected != query.permission {
					require.Equal(t, 403, code, string(data))
				} else {
					require.Equal(t, 200, code, string(data))
				}
			}
		})
	}
}

func TestManagementAccessActionOnlyHasNoDetailsAndRechecksConfirmation(t *testing.T) {
	svc, handler, recorder, _, _, target := managementActionFixture(t)
	conf := svc.Configuration.Flows[0].Environment.V.(*configuration.EnvironmentManagement)
	conf.Access = access.Constant(false).WithConstant(access.SessionsDisconnect, true)
	// A policy change affects the session target. Reauthenticate the actor before
	// preparing; the already authorized worker session remains the target.
	manager := webTestToken(t, webTestPassword(handler, "alice", "correct", "Work"))
	prepared := prepareManagementAction(t, handler, manager, "disconnect", target)
	require.Nil(t, prepared.Target.Details)
	code, _, _ := managementWebRead(t, handler, manager, "sessions/show", map[string]string{"flow": target.Flow().String(), "id": target.Id().String()})
	require.Equal(t, 403, code)
	conf.Access = access.Constant(false)
	response := managementActionRequest(handler, manager, "confirm", map[string]string{"confirmationToken": prepared.ConfirmationToken})
	require.Equal(t, 403, response.Code, response.Body.String())
	require.Empty(t, auditEventsNamed(recorder.eventsSnapshot(), audit.EventNameSessionDisconnectStarted))
}

func TestManagementAccessIndependentArtifactDownloads(t *testing.T) {
	for _, permission := range []access.Permission{access.AuditlogsDownload, access.RecordingsDownload} {
		t.Run(string(permission), func(t *testing.T) {
			fixture := newArtifactHTTPSFixture(t)
			token := fixture.login(t)
			id := artifactHTTPSSeed(t, fixture, token)
			conf := fixture.svc.Configuration.Flows[0].Environment.V.(*configuration.EnvironmentManagement)
			conf.Access = access.Constant(false).WithConstant(permission, true)
			token = fixture.login(t)
			for _, query := range []struct {
				route      string
				fields     map[string]string
				permission access.Permission
			}{
				{"artifacts/audit", map[string]string{"auditlog": "default"}, access.AuditlogsDownload},
				{"artifacts/recording", map[string]string{"auditlog": "default", "id": id.String()}, access.RecordingsDownload},
			} {
				response := artifactHTTPSPost(t, fixture, token, query.route, query.fields)
				if permission == query.permission {
					require.Equal(t, 200, response.StatusCode)
				} else {
					require.Equal(t, 403, response.StatusCode)
				}
				require.NoError(t, response.Body.Close())
			}
			code, _, _ := managementWebRead(t, fixture.svc.web, token, "recordings/list", map[string]string{"auditlog": "default"})
			require.Equal(t, 403, code)
			socket := managementChannelDial(t, fixture, token)
			requireWebSocketReady(t, socket)
			code, _ = managementChannelRead(t, socket, "1", "artifacts/recordings", map[string]string{"auditlog": "default"})
			require.Equal(t, 403, code, "source inventory requires recordings.read as well as download")
		})
	}
}

func TestManagementAccessRechecksImmediatelyBeforeMutation(t *testing.T) {
	for _, dispose := range []bool{false, true} {
		control, target, recorder := newManagementSessionControlTest(t)
		conn := newTrackedSessionConnection(t, control.service)
		control.service.sessionConnections.track(conn, target)
		defer func() { require.NoError(t, conn.Close()) }()
		_, err := control.performTarget(t.Context(), target, dispose, func(context.Context) error {
			control.service.Configuration.Flows[len(control.service.Configuration.Flows)-1].Environment.V.(*configuration.EnvironmentManagement).Access = access.Constant(false)
			return nil
		})
		require.ErrorIs(t, err, access.ErrDenied)
		require.False(t, conn.closed.Load())
		require.Zero(t, target.disposeCalls)
		events := recorder.eventsSnapshot()
		require.Len(t, events, 2)
		require.Equal(t, audit.EventOutcomeFailure, events[1].Outcome)
	}
}

func TestManagementAccessForcedCommandsIntersectAndNeverGrant(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, `command="version"`, nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{Access: access.Constant(false).WithConstant(access.MetricsRead, true)}
	})
	channel, err := server.mustDial(t).NewSession()
	require.NoError(t, err)
	var stderr bytes.Buffer
	channel.Stderr = &stderr
	output, err := channel.Output("metrics show")
	require.Error(t, err)
	require.Empty(t, output)
	require.Contains(t, stderr.String(), "version.read")
	for _, allowed := range []bool{false, true} {
		svc, handler, _, _ := managementWebFixture(t, func(conf *configuration.Configuration) {
			conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{Access: access.Constant(allowed)}
		})
		token := forcedManagementWebLogin(t, svc, handler, "version --long=false")
		grant := webTestAccess(t, svc, token, "Work")
		capabilities := svc.managementCapabilities(t.Context(), &environmentContext{service: svc, authorization: grant.auth})
		if allowed {
			require.Equal(t, []access.Permission{access.VersionRead}, capabilities)
		} else {
			require.Empty(t, capabilities)
		}
		code, _, body := managementWebRead(t, handler, token, "version/show", map[string]string{"long": "false"})
		if allowed {
			require.Equal(t, 200, code, body)
		} else {
			require.Equal(t, 403, code, body)
		}
	}
}

type managementAccessDeniedRepository struct {
	environment.CloseableRepository
}

func (r managementAccessDeniedRepository) Ensure(request environment.Request) (environment.Environment, error) {
	env, err := r.CloseableRepository.Ensure(request)
	if err != nil {
		return nil, err
	}
	return managementAccessDeniedEnvironment{Environment: env}, nil
}
func (r managementAccessDeniedRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, _ := environment.SessionTargetResolverFor(r.CloseableRepository, ctx.Authorization().Flow())
	return resolver.ResolveSessionTarget(ctx)
}

type managementAccessDeniedEnvironment struct{ environment.Environment }

func (managementAccessDeniedEnvironment) ReadManagement(environment.TaskContext, protocol.ReadRequest, io.Writer) (int, error) {
	return -1, access.Denied(access.FlowsRead)
}
func TestManagementAccessBackendDenialUsesForbiddenNotUnavailable(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	svc.environments = managementAccessDeniedRepository{CloseableRepository: svc.environments}
	code, _, body := managementWebRead(t, handler, token, "flows/list", nil)
	require.Equal(t, 403, code, body)
}
