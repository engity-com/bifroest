package service

import (
	"context"
	gonet "net"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func runtimeAdmissionTestAttach(t *testing.T, svc *service) {
	t.Helper()
	snapshot, err := configuration.NewSnapshot(svc.Configuration)
	require.NoError(t, err)
	svc.runtime = newRuntimeGenerations(snapshot)
	svc.runtime.activeConnections = &svc.activeConnections
	svc.generation = svc.runtime.initial
	svc.sessionConnections.runtime = svc.runtime
	require.NoError(t, svc.registerRuntimeSessions(t.Context()))
}

// Prepare real providers and borrow the existing session store. This helper is
// deliberately limited to the dummy test environment; it is not a production
// generation factory or a shortcut around listener/background-worker ownership.
func runtimeAdmissionTestActivate(t *testing.T, previous *service, conf configuration.Configuration) (*service, *runtimeActivation) {
	t.Helper()
	snapshot, err := configuration.NewSnapshot(conf)
	require.NoError(t, err)
	generation, err := previous.runtime.prepare(snapshot)
	require.NoError(t, err)
	t.Cleanup(func() { previous.runtime.discard(generation) })
	next := &service{
		Service: &Service{Configuration: snapshot.Configuration()},
		runtime: previous.runtime, generation: generation, sessions: previous.sessions,
	}
	next.sessionConnections.runtime = next.runtime
	authorizer, err := authorization.NewAuthorizerFacade(t.Context(), &next.Configuration.Flows)
	require.NoError(t, err)
	next.authorizer = authorizer
	t.Cleanup(func() { require.NoError(t, authorizer.Close()) })
	require.Len(t, next.Configuration.Flows, 1)
	flow := &next.Configuration.Flows[0]
	environments, err := environment.NewDummyRepository(t.Context(), flow.Name, flow.Environment.V.(*configuration.EnvironmentDummy), nil, nil)
	require.NoError(t, err)
	next.environments = environments
	t.Cleanup(func() { require.NoError(t, environments.Close()) })
	activation, err := next.runtime.activate(t.Context(), generation)
	require.NoError(t, err)
	return next, activation
}

func runtimeAdmissionTestTransport(t *testing.T) *terminalConnectionTestTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &terminalConnectionTestTransport{ctx: ctx, cancel: cancel, id: bconn.MustNewId()}
}

func runtimeAdmissionTestPassword(t *testing.T, svc *service, password string) authorization.Authorization {
	t.Helper()
	auth, err := svc.authorizer.AuthorizePassword(&passwordAuthorizeRequest{
		authorizeRequest: authorizeRequest{service: svc, connection: runtimeAdmissionTestTransport(t)},
		password:         password,
	})
	require.NoError(t, err)
	return auth
}

func TestRuntimeAdmissionEnvironmentChangeCreatesNewSessionWithoutClosingOldTerminal(t *testing.T) {
	svc, transport, original := terminalConnectionTestFixture(t)
	runtimeAdmissionTestAttach(t, svc)
	old := registerTerminalConnectionForTest(t, svc, transport, original)
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).Banner = template.MustNewString("new environment")
	conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(17)
	next, activation := runtimeAdmissionTestActivate(t, svc, conf)
	require.Empty(t, activation.connections)
	newAuth := runtimeAdmissionTestPassword(t, next, "correct")
	require.True(t, newAuth.IsAuthorized())
	require.NotEqual(t, original.FindSession().Id(), newAuth.FindSession().Id())
	require.Same(t, svc.generation, svc.runtime.sessionOwner(original.FindSession()))
	require.Same(t, next.generation, svc.runtime.sessionOwner(newAuth.FindSession()))
	require.False(t, old.IsClosed())
	require.NoError(t, old.activity())
	require.True(t, svc.Configuration.Flows[0].Environment.V.(*configuration.EnvironmentDummy).Banner.IsZero())
	require.Equal(t, "new environment", next.Configuration.Flows[0].Environment.V.(*configuration.EnvironmentDummy).Banner.String())
	var visible []session.Id
	request := &authorizeRequest{service: next, connection: runtimeAdmissionTestTransport(t)}
	require.NoError(t, request.Sessions().FindAll(t.Context(), func(_ context.Context, candidate session.Session) (bool, error) {
		visible = append(visible, candidate.Id())
		return true, nil
	}, nil))
	require.Equal(t, []session.Id{newAuth.FindSession().Id()}, visible)
	var persisted int
	require.NoError(t, svc.sessions.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) {
		persisted++
		return true, nil
	}, nil))
	require.Equal(t, 2, persisted, "the shared store must preserve old sessions for their original owners and cleanup")
	registered := registerTerminalConnectionForTest(t, next, runtimeAdmissionTestTransport(t), newAuth)
	require.False(t, registered.IsClosed())
}

func TestRuntimeAdmissionNewAuthenticationIsRequiredButOldTerminalSurvives(t *testing.T) {
	svc, transport, original := terminalConnectionTestFixture(t)
	runtimeAdmissionTestAttach(t, svc)
	old := registerTerminalConnectionForTest(t, svc, transport, original)
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
	next, activation := runtimeAdmissionTestActivate(t, svc, conf)
	require.Empty(t, activation.connections)
	require.False(t, runtimeAdmissionTestPassword(t, next, "correct").IsAuthorized())
	accepted := runtimeAdmissionTestPassword(t, next, "changed")
	require.True(t, accepted.IsAuthorized())
	require.Equal(t, original.FindSession().Id(), accepted.FindSession().Id(), "an unchanged environment may retain compatible session reuse after new credential verification")
	require.Same(t, svc.generation, svc.runtime.sessionOwner(accepted.FindSession()))
	require.False(t, old.IsClosed())
	require.NoError(t, old.activity())
}

func TestRuntimeAdmissionDeletionClosesTerminalAndSavedAuthorizationCannotReturn(t *testing.T) {
	svc, transport, original := terminalConnectionTestFixture(t)
	runtimeAdmissionTestAttach(t, svc)
	old := registerTerminalConnectionForTest(t, svc, transport, original)
	originalConfig := svc.generation.snapshot.Configuration()
	removedConfig := svc.generation.snapshot.Configuration()
	removedConfig.Flows[0].Name = "replacement"
	removed, activation := runtimeAdmissionTestActivate(t, svc, removedConfig)
	require.True(t, svc.sessionConnections.isRevoked(original.FindSession()))
	require.NoError(t, activation.closeConnections())
	require.True(t, old.IsClosed())
	waitTerminalConnectionForTest(t, old)
	rejected, err := svc.registerTerminalConnection(runtimeAdmissionTestTransport(t), original)
	require.Error(t, err)
	require.Nil(t, rejected)

	recreated, activation := runtimeAdmissionTestActivate(t, removed, originalConfig)
	require.NoError(t, activation.closeConnections())
	require.False(t, recreated.runtime.sessionCompatible(recreated.generation, original.FindSession()))
	newAuth := runtimeAdmissionTestPassword(t, recreated, "correct")
	require.True(t, newAuth.IsAuthorized())
	require.NotEqual(t, original.FindSession().Id(), newAuth.FindSession().Id())
	conn := registerTerminalConnectionForTest(t, recreated, runtimeAdmissionTestTransport(t), newAuth)
	require.False(t, conn.IsClosed())
}

func TestRuntimeAdmissionSessionRevocationClosesConnectionsAcrossGenerations(t *testing.T) {
	svc, transport, original := terminalConnectionTestFixture(t)
	runtimeAdmissionTestAttach(t, svc)
	old := registerTerminalConnectionForTest(t, svc, transport, original)
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Title = "new title"
	next, _ := runtimeAdmissionTestActivate(t, svc, conf)
	auth := runtimeAdmissionTestPassword(t, next, "correct")
	require.Equal(t, original.FindSession().Id(), auth.FindSession().Id())
	newConn := registerTerminalConnectionForTest(t, next, runtimeAdmissionTestTransport(t), auth)
	require.NoError(t, svc.sessionConnections.revoke(original.Flow(), original.FindSession().Id()))
	require.True(t, old.IsClosed())
	require.True(t, newConn.IsClosed())
	require.True(t, next.sessionConnections.isRevoked(auth.FindSession()))
	late, err := next.registerTerminalConnection(runtimeAdmissionTestTransport(t), auth)
	require.Error(t, err)
	require.Nil(t, late)
}

func TestRuntimeAdmissionDisconnectClosesAllGenerationsWithoutRevokingSession(t *testing.T) {
	svc, transport, original := terminalConnectionTestFixture(t)
	runtimeAdmissionTestAttach(t, svc)
	old := registerTerminalConnectionForTest(t, svc, transport, original)
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Title = "new title"
	next, _ := runtimeAdmissionTestActivate(t, svc, conf)
	auth := runtimeAdmissionTestPassword(t, next, "correct")
	newConn := registerTerminalConnectionForTest(t, next, runtimeAdmissionTestTransport(t), auth)
	require.NoError(t, svc.sessionConnections.disconnect(original.Flow(), original.FindSession().Id()))
	require.True(t, old.IsClosed())
	require.True(t, newConn.IsClosed())
	require.False(t, next.sessionConnections.isRevoked(auth.FindSession()))
	late := registerTerminalConnectionForTest(t, next, runtimeAdmissionTestTransport(t), auth)
	require.False(t, late.IsClosed())
}

type runtimeAdmissionBlockedRepository struct {
	session.Repository
	entered chan struct{}
	release chan struct{}
	created session.Session
}

func (this *runtimeAdmissionBlockedRepository) Create(ctx context.Context, flow configuration.FlowName, remote bnet.Remote, token []byte) (session.Session, error) {
	created, err := this.Repository.Create(ctx, flow, remote, token)
	if err != nil {
		return nil, err
	}
	this.created = created
	close(this.entered)
	<-this.release
	return created, nil
}

func TestRuntimeAdmissionSessionCreationRacingDeletionIsDisposedAndRejected(t *testing.T) {
	svc, _, _ := terminalConnectionTestFixture(t)
	runtimeAdmissionTestAttach(t, svc)
	blocked := &runtimeAdmissionBlockedRepository{Repository: svc.sessions, entered: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(blocked.release) })
	t.Cleanup(unblock)
	request := &authorizeRequest{service: svc, connection: runtimeAdmissionTestTransport(t)}
	view := &compatibleSessionRepository{Repository: blocked, environments: svc.environments, authorizeRequest: request}
	done := make(chan error, 1)
	go func() {
		created, err := view.Create(t.Context(), "lease-test", associationAdapterRemote("alice"), []byte("test-token"))
		if created != nil {
			t.Error("a session created across flow deletion was published")
		}
		done <- err
	}()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("session creation did not start")
	}
	removedConfig := svc.generation.snapshot.Configuration()
	removedConfig.Flows[0].Name = "replacement"
	_, _ = runtimeAdmissionTestActivate(t, svc, removedConfig)
	unblock()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("session creation did not finish")
	}
	require.True(t, svc.runtime.sessionRevoked(blocked.created))
	require.Same(t, svc.generation, svc.runtime.sessionOwner(blocked.created))
	persisted, err := svc.sessions.FindBy(t.Context(), blocked.created.Flow(), blocked.created.Id(), nil)
	require.NoError(t, err)
	info, err := persisted.Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, session.StateDisposed, info.State())
}

func TestRuntimeAdmissionAssociatedSessionsRespectEnvironmentRevisionBeforeTargetResolution(t *testing.T) {
	svc, storage := newAssociatedService(t)
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(`flows:
  - name: work
    authorization: {type: none}
    environment:
      type: ssh
      address: '{{ if .remote.user }}{{ .remote.user }}{{ else }}hostA{{ end }}'
      user: account
      acceptAllHostKeys: true
      identityFiles: ["/must/not/load/for/selection"]
`), ""))
	conf.Session.V = storage
	svc.Service = &Service{Configuration: conf}
	runtimeAdmissionTestAttach(t, svc)
	t.Cleanup(func() {
		svc.runtime.stop()
		svc.runtime.forgetSessions()
	})
	first, handled, err := svc.resolveAuthenticatedSession(associationAdapter(t, "hostA", bconn.TransportSsh), []byte("credential"))
	require.NoError(t, err)
	require.True(t, handled)

	nextConfig := svc.generation.snapshot.Configuration()
	nextConfig.Flows[0].Environment.V.(*configuration.EnvironmentSsh).PortForwardingAllowed = template.BoolOf(false)
	snapshot, err := configuration.NewSnapshot(nextConfig)
	require.NoError(t, err)
	generation, err := svc.runtime.prepare(snapshot)
	require.NoError(t, err)
	next := &service{Service: &Service{Configuration: nextConfig}, runtime: svc.runtime, generation: generation, sessions: svc.sessions, environments: svc.environments}
	_, err = svc.runtime.activate(t.Context(), generation)
	require.NoError(t, err)
	// The target resolver/repository is intentionally unchanged: even the exact
	// same backend selection must not join the previous environment revision.
	second, handled, err := next.resolveAuthenticatedSession(associationAdapter(t, "hostA", bconn.TransportHttp), []byte("credential"))
	require.NoError(t, err)
	require.True(t, handled)
	require.NotEqual(t, first.Id(), second.Id())
	associationOne, err := session.AssociationOf(t.Context(), first)
	require.NoError(t, err)
	associationTwo, err := session.AssociationOf(t.Context(), second)
	require.NoError(t, err)
	require.Equal(t, associationOne.Target, associationTwo.Target)
	require.Same(t, svc.generation, svc.runtime.sessionOwner(first))
	require.Same(t, generation, svc.runtime.sessionOwner(second))
}

func TestRuntimeAdmissionSharesConnectionBudgetInsteadOfResettingPerGeneration(t *testing.T) {
	conf := runtimeGenerationTestSnapshot(t, runtimeGenerationTestSource).Configuration()
	conf.Ssh.MaxConnections = 1
	snapshot, err := configuration.NewSnapshot(conf)
	require.NoError(t, err)
	registry := newRuntimeGenerations(snapshot)
	t.Cleanup(func() {
		registry.stop()
		registry.forgetSessions()
	})
	owner := &service{Service: &Service{Configuration: conf}, runtime: registry, generation: registry.initial}
	registry.activeConnections = &owner.activeConnections
	other := &service{Service: &Service{Configuration: snapshot.Configuration()}, runtime: registry, generation: registry.initial}
	owner.activeConnections.Store(1) // An existing connection in another view.
	server, peer := gonet.Pipe()
	defer func() { _ = server.Close(); _ = peer.Close() }()
	conn, err := other.newConnection(server, newLimiterSSHContext("192.0.2.1"), log.GetLogger("runtime-admission-test"))
	require.NoError(t, err)
	require.Nil(t, conn)
	require.EqualValues(t, 1, owner.activeConnections.Load())
	require.Zero(t, other.activeConnections.Load(), "a local counter is not a fresh global allowance")
	owner.activeConnections.Add(-1)
	conn, err = other.newConnection(server, newLimiterSSHContext("192.0.2.1"), log.GetLogger("runtime-admission-test"))
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.EqualValues(t, 1, owner.activeConnections.Load())
	require.NoError(t, conn.Close())
	require.Zero(t, owner.activeConnections.Load())
}
