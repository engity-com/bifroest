package service

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

// Lease tests need real authorization, session storage and admission checks, but
// no terminal execution, recording, TLS endpoint, SSH server or scheduler.
func terminalConnectionTestFixture(t *testing.T, configure ...func(*configuration.SessionFs)) (*service, *terminalConnectionTestTransport, authorization.Authorization) {
	t.Helper()
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(fmt.Sprintf(`
session:
  type: fs
  storage: %q
flows:
  - name: lease-test
    authorization:
      type: simple
      entries:
        - name: alice
          password: plain:correct
    environment:
      type: dummy
`, filepath.ToSlash(t.TempDir()))), "terminal-connection-test.yaml"))
	for _, fn := range configure {
		fn(conf.Session.V.(*configuration.SessionFs))
	}
	svc := &service{
		Service:             &Service{Configuration: conf},
		connectionLifecycle: newConnectionLifecycle(),
		terminalAdmissions:  newConnectionLifecycle(),
		executions:          newConnectionLifecycle(),
		flowAuditRecorders:  map[configuration.FlowName]audit.Recorder{"lease-test": audit.NewNoopRecorder()},
	}
	svc.terminalContext, svc.cancelTerminals = context.WithCancel(t.Context())
	t.Cleanup(func() { require.NoError(t, svc.Close()) })
	var err error
	svc.sessions, err = session.NewFacadeRepository(t.Context(), &svc.Configuration.Session)
	require.NoError(t, err)
	svc.environments, err = environment.NewDummyRepository(t.Context(), "lease-test", conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy), nil, nil)
	require.NoError(t, err)
	svc.authorizer, err = authorization.NewAuthorizerFacadeWithObserver(t.Context(), &svc.Configuration.Flows, svc.observeFlowAuthorization)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	transport := &terminalConnectionTestTransport{ctx: ctx, cancel: cancel, id: bconn.MustNewId()}
	t.Cleanup(cancel)
	auth, err := svc.authorizer.AuthorizePassword(&passwordAuthorizeRequest{authorizeRequest: authorizeRequest{service: svc, connection: transport}, password: "correct"})
	require.NoError(t, err)
	require.True(t, auth.IsAuthorized())
	require.NotNil(t, auth.FindSession())
	return svc, transport, auth
}

type terminalConnectionTestTransport struct {
	ctx    context.Context
	cancel context.CancelFunc
	id     bconn.Id
}

func (this *terminalConnectionTestTransport) Id() bconn.Id { return this.id }
func (*terminalConnectionTestTransport) Remote() bnet.Remote {
	return associationAdapterRemote("alice")
}
func (*terminalConnectionTestTransport) Logger() log.Logger {
	return log.GetLogger("terminal-connection-test")
}
func (this *terminalConnectionTestTransport) Lifetime() context.Context { return this.ctx }
func (this *terminalConnectionTestTransport) Close() error              { this.cancel(); return nil }

func registerTerminalConnectionForTest(t *testing.T, svc *service, transport terminalTransport, auth authorization.Authorization) *terminalConnection {
	t.Helper()
	conn, err := svc.registerTerminalConnection(transport, auth)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
		waitTerminalConnectionForTest(t, conn)
	})
	return conn
}

func waitTerminalConnectionForTest(t *testing.T, conn *terminalConnection) {
	t.Helper()
	select {
	case <-conn.done:
	case <-time.After(2 * time.Second):
		t.Error("connection validity worker did not stop")
	}
}

type terminalConnectionDeniedRepository struct {
	environment.CloseableRepository
}

func (*terminalConnectionDeniedRepository) WillBeAccepted(environment.Context) (bool, error) {
	return false, nil
}

func TestNeutralConnectionLeanFixtureRetainsAdmissionGates(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"missing authorization", "missing transport", "canceled transport", "disposed session", "stopped admission", "revoked session", "denied environment"} {
		t.Run(mode, func(t *testing.T) {
			svc, transport, auth := terminalConnectionTestFixture(t)
			var source terminalTransport = transport
			switch mode {
			case "missing authorization":
				auth = nil
			case "missing transport":
				source = (*terminalConnectionTestTransport)(nil)
			case "canceled transport":
				transport.cancel()
			case "disposed session":
				_, err := auth.FindSession().Dispose(t.Context())
				require.NoError(t, err)
			case "stopped admission":
				svc.terminalAdmissions.stop()
			case "revoked session":
				require.NoError(t, svc.sessionConnections.revoke(auth.Flow(), auth.FindSession().Id()))
			case "denied environment":
				svc.environments = &terminalConnectionDeniedRepository{svc.environments}
			}
			conn, err := svc.registerTerminalConnection(source, auth)
			require.Error(t, err)
			require.Nil(t, conn)
			require.Zero(t, svc.connectionLifecycle.active, "failed admission must release its lifecycle registration")
			require.Zero(t, svc.terminalAdmissions.active)
			require.Empty(t, svc.sessionConnections.connections)
		})
	}
}

func TestNeutralConnectionLeanFixtureReleasesLeaseAfterCancellation(t *testing.T) {
	t.Parallel()
	svc, transport, auth := terminalConnectionTestFixture(t, func(conf *configuration.SessionFs) { conf.MaxConnections = 1 })
	conn := registerTerminalConnectionForTest(t, svc, transport, auth)
	transport.cancel()
	waitTerminalConnectionForTest(t, conn)
	require.True(t, conn.IsClosed())
	require.Zero(t, svc.connectionLifecycle.active)
	require.Empty(t, svc.sessionConnections.connections)
	// A leaked repository lease would reject this independent connection.
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	second := &terminalConnectionTestTransport{ctx: ctx, cancel: cancel, id: bconn.MustNewId()}
	require.False(t, registerTerminalConnectionForTest(t, svc, second, auth).IsClosed())
}
