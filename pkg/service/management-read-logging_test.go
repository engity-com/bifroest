package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/echocat/slf4g/level"
	logrecording "github.com/echocat/slf4g/testing/recording"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestManagementRecordingHTTPFailureLogsTheBackendCauseButNotTheRequestOrBearer(t *testing.T) {
	provider := logrecording.NewProvider()
	provider.SetLevel(level.Debug)
	defer provider.HookGlobally()()
	svc, handler, _, token := managementWebFixture(t)
	svc.recordingRepositories["default"] = nil
	code, _, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default", "flow": "docker", "query": "DO-NOT-LOG-QUERY"})
	require.Equal(t, 503, code)
	require.NotContains(t, body, "no active recording repository")
	count := 0
	for _, event := range provider.GetAll() {
		message, _ := event.Get(provider.GetFieldKeysSpec().GetMessage())
		if message != "structured management read failed" {
			continue
		}
		count++
		require.Equal(t, level.Error, event.GetLevel())
		cause, _ := event.Get(provider.GetFieldKeysSpec().GetError())
		require.Contains(t, fmt.Sprint(cause), "no active recording repository")
		for key, expected := range map[string]string{"operation": "recordings.list", "auditlog": "default", "flow": svc.Configuration.Flows[0].Name.String(), "targetFlow": "docker"} {
			value, present := event.Get(key)
			require.True(t, present, key)
			require.Equal(t, expected, fmt.Sprint(value), key)
		}
		connection, _ := event.Get("connection")
		require.NotEmpty(t, connection)
		for _, key := range []string{"body", "query", "slug", "Authorization", "accessToken"} {
			_, present := event.Get(key)
			require.False(t, present, key)
		}
		require.NotContains(t, fmt.Sprint(event), token)
		require.NotContains(t, fmt.Sprint(event), "DO-NOT-LOG-QUERY")
	}
	require.Equal(t, 1, count, "one server diagnostic per failed structured read")
}

type managementReadFailureRepository struct {
	environment.CloseableRepository
	cause error
}

func (this *managementReadFailureRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, _ := environment.SessionTargetResolverFor(this.CloseableRepository, ctx.Authorization().Flow())
	return resolver.ResolveSessionTarget(ctx)
}

func (this *managementReadFailureRepository) Ensure(request environment.Request) (environment.Environment, error) {
	value, err := this.CloseableRepository.Ensure(request)
	if err != nil {
		return nil, err
	}
	return &managementReadFailureEnvironment{Environment: value, cause: this.cause}, nil
}

type managementReadFailureEnvironment struct {
	environment.Environment
	cause error
}

func (this *managementReadFailureEnvironment) ReadManagement(environment.TaskContext, protocol.ReadRequest, io.Writer) (int, error) {
	return -1, this.cause
}

func TestManagementChannelReadLogsCorrelatedFailureAndKeepsExpectedCancellationAtDebug(t *testing.T) {
	for _, test := range []struct {
		name, message string
		cause         error
		severity      level.Level
		warming       bool
	}{
		{"backend", "structured management read failed", errors.New("catalog backend test diagnostic"), level.Error, false},
		{"deadline", "structured management read failed", context.DeadlineExceeded, level.Error, false},
		{"canceled", "structured management read canceled", context.Canceled, level.Debug, false},
		{"warmup", "structured management read failed", &recording.NativeCatalogWarmupError{Cached: 1, Total: 2}, level.Error, true},
		{"mixed-warmup", "structured management read failed", errors.Join(&recording.NativeCatalogWarmupError{Cached: 1, Total: 2}, errors.New("audit failure")), level.Error, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := logrecording.NewProvider()
			provider.SetLevel(level.Debug)
			defer provider.HookGlobally()()
			fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
			})
			fixture.svc.environments = &managementReadFailureRepository{CloseableRepository: fixture.svc.environments, cause: test.cause}
			token := fixture.login(t)
			socket := managementChannelDial(t, fixture, token)
			requireWebSocketReady(t, socket)
			code, body := managementChannelRead(t, socket, "4", "recordings/list", map[string]string{"auditlog": "default"})
			require.Equal(t, 503, code)
			require.NotContains(t, string(body), test.cause.Error())
			require.Equal(t, test.warming, strings.Contains(string(body), `"code":"recording-catalog-incomplete"`))
			count := 0
			for _, event := range provider.GetAll() {
				message, _ := event.Get(provider.GetFieldKeysSpec().GetMessage())
				if message != test.message {
					continue
				}
				count++
				require.Equal(t, test.severity, event.GetLevel())
				cause, _ := event.Get(provider.GetFieldKeysSpec().GetError())
				require.Contains(t, fmt.Sprint(cause), test.cause.Error())
				id, _ := event.Get("requestId")
				require.Equal(t, "4", id)
				channel, _ := event.Get("channel")
				require.NotEmpty(t, channel)
				operation, _ := event.Get("operation")
				require.Equal(t, "recordings.list", fmt.Sprint(operation))
				require.NotContains(t, fmt.Sprint(event), token)
			}
			require.Equal(t, 1, count)
		})
	}
}

func TestManagementRecordingHTTPWarmupReturnsOnlyItsFixedPublicCondition(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	svc.environments = &managementReadFailureRepository{CloseableRepository: svc.environments, cause: &recording.NativeCatalogWarmupError{Cached: 1, Total: 2}}
	code, _, body := managementWebRead(t, handler, token, "recordings/list", map[string]string{"auditlog": "default"})
	require.Equal(t, 503, code)
	require.JSONEq(t, `{"error":"recording catalog verification incomplete; refresh to continue","code":"recording-catalog-incomplete"}`, body)
	require.NotContains(t, body, "cached")
	require.NotContains(t, body, token)
}
