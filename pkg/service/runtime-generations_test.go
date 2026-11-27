package service

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
)

const runtimeGenerationTestSource = `environments:
  shared: {type: dummy, banner: original}
authorizations:
  shared:
    type: simple
    entries: [{name: alice, password: "plain:correct"}]
flows:
  - {name: first, environment: shared, authorization: shared}
  - {name: second, environment: shared, authorization: shared}
  - name: independent
    environment: {type: dummy}
    authorization: {type: none}
`

func runtimeGenerationTestSnapshot(t *testing.T, source string) *configuration.Snapshot {
	t.Helper()
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(source), ""))
	result, err := configuration.NewSnapshot(conf)
	require.NoError(t, err)
	return result
}

func runtimeGenerationTestRegistry(t *testing.T) *runtimeGenerations {
	t.Helper()
	result := newRuntimeGenerations(runtimeGenerationTestSnapshot(t, runtimeGenerationTestSource))
	t.Cleanup(func() {
		result.stop()
		result.forgetSessions()
	})
	return result
}

func runtimeGenerationTestActivate(t *testing.T, registry *runtimeGenerations, source string) (*runtimeGeneration, *runtimeActivation) {
	t.Helper()
	next, err := registry.prepare(runtimeGenerationTestSnapshot(t, source))
	require.NoError(t, err)
	activation, err := registry.activate(t.Context(), next)
	require.NoError(t, err)
	return next, activation
}

func runtimeGenerationTestSession(flow configuration.FlowName) *houseKeeperTestSession {
	return &houseKeeperTestSession{flow: flow, id: session.MustNewId()}
}

type runtimeGenerationTestConnection struct {
	*terminalConnectionTestTransport
	closed  atomic.Bool
	onClose func()
}

func (this *runtimeGenerationTestConnection) IsClosed() bool { return this.closed.Load() }
func (this *runtimeGenerationTestConnection) Close() error {
	if !this.closed.CompareAndSwap(false, true) {
		return nil
	}
	if this.onClose != nil {
		this.onClose()
	}
	return this.terminalConnectionTestTransport.Close()
}

func runtimeGenerationTestAdmit(t *testing.T, registry *runtimeGenerations, generation *runtimeGeneration, sess session.Session) (*runtimeGenerationTestConnection, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	conn := &runtimeGenerationTestConnection{terminalConnectionTestTransport: &terminalConnectionTestTransport{ctx: ctx, cancel: cancel, id: bconn.MustNewId()}}
	release, err := registry.admit(generation, conn)
	require.NoError(t, err)
	t.Cleanup(release)
	if sess != nil {
		require.True(t, registry.bindConnection(conn, sess))
	}
	return conn, release
}

func runtimeGenerationTestNotDrained(t *testing.T, generation *runtimeGeneration) {
	t.Helper()
	select {
	case <-generation.drained:
		t.Fatal("generation was drained while still in use")
	default:
	}
}

func runtimeGenerationTestDrained(t *testing.T, generation *runtimeGeneration) {
	t.Helper()
	select {
	case <-generation.drained:
	default:
		t.Fatal("generation retained resources after its last owner was released")
	}
}

func TestRuntimeGenerationEnvironmentChangesPreserveExistingOwnership(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	initial := registry.initial
	oldSession := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(initial, oldSession, true))
	oldConnection, releaseConnection := runtimeGenerationTestAdmit(t, registry, initial, oldSession)
	releaseExecution, err := registry.retain(initial)
	require.NoError(t, err)
	defer releaseExecution()

	next, activation := runtimeGenerationTestActivate(t, registry, strings.Replace(runtimeGenerationTestSource, "banner: original", "banner: original, exitCode: 17", 1))
	require.Empty(t, activation.connections)
	require.Empty(t, activation.sessions)
	require.Same(t, initial.flows["first"].identity, next.flows["first"].identity)
	require.NotSame(t, initial.flows["first"].environment, next.flows["first"].environment)
	require.NotSame(t, initial.flows["second"].environment, next.flows["second"].environment)
	require.Same(t, initial.flows["independent"].environment, next.flows["independent"].environment)
	require.False(t, oldConnection.IsClosed())
	require.True(t, registry.allowFlow(initial, "first"), "already admitted connections retain their rules")
	require.True(t, registry.sessionCompatible(initial, oldSession))
	require.False(t, registry.sessionCompatible(next, oldSession))
	require.Same(t, initial, registry.sessionOwner(oldSession))
	require.Error(t, registry.bindSession(next, oldSession, false))

	newSession := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(next, newSession, true))
	require.Same(t, next, registry.sessionOwner(newSession))
	require.True(t, registry.sessionCompatible(next, newSession))
	require.False(t, registry.sessionCompatible(initial, newSession))
	runtimeGenerationTestNotDrained(t, initial)

	registry.finalSessionDeleted(oldSession.Flow(), oldSession.Id())
	releaseConnection()
	runtimeGenerationTestNotDrained(t, initial)
	releaseExecution()
	releaseExecution() // Resource releases must be idempotent.
	runtimeGenerationTestDrained(t, initial)
	_, err = registry.retain(initial)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, "original", initial.snapshot.Configuration().Flows[0].Environment.V.(*configuration.EnvironmentDummy).Banner.String())
}

func TestRuntimeGenerationAuthenticationAndPolicyChangesKeepEnvironmentRevision(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	initial := registry.initial
	sess := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(initial, sess, true))
	conn, _ := runtimeGenerationTestAdmit(t, registry, initial, sess)
	source := strings.Replace(runtimeGenerationTestSource, "plain:correct", "plain:new-password", 1)
	source = strings.Replace(source, "name: first,", "name: first, title: Changed,", 1)
	next, activation := runtimeGenerationTestActivate(t, registry, source)
	require.Empty(t, activation.connections)
	require.False(t, conn.IsClosed())
	require.Same(t, initial.flows["first"].environment, next.flows["first"].environment)
	require.True(t, registry.sessionCompatible(next, sess), "this is only environment compatibility, not authentication")
	require.Same(t, initial, registry.sessionOwner(sess), "existing refresh/cleanup resources retain their original owner")
}

func TestRuntimeGenerationEnvironmentChangeBackDoesNotResurrectEarlierSession(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	old := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(registry.initial, old, true))
	_, _ = runtimeGenerationTestActivate(t, registry, strings.Replace(runtimeGenerationTestSource, "banner: original", "banner: original, exitCode: 17", 1))
	restored, _ := runtimeGenerationTestActivate(t, registry, runtimeGenerationTestSource)
	require.NotSame(t, registry.initial.flows["first"].environment, restored.flows["first"].environment)
	require.False(t, registry.sessionCompatible(restored, old))
}

func TestRuntimeGenerationDeletionRevokesAllOlderGenerationsAndRecreationIsNew(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	initial := registry.initial
	firstSession := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(initial, firstSession, true))
	firstConnection, _ := runtimeGenerationTestAdmit(t, registry, initial, firstSession)
	pending, _ := runtimeGenerationTestAdmit(t, registry, initial, nil)

	changedSource := strings.Replace(runtimeGenerationTestSource, "banner: original", "banner: changed", 1)
	changed, _ := runtimeGenerationTestActivate(t, registry, changedSource)
	secondSession := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(changed, secondSession, true))
	secondConnection, _ := runtimeGenerationTestAdmit(t, registry, changed, secondSession)
	unrelated := runtimeGenerationTestSession("independent")
	require.NoError(t, registry.bindSession(changed, unrelated, true))
	unrelatedConnection, _ := runtimeGenerationTestAdmit(t, registry, changed, unrelated)

	removedSource := strings.Replace(changedSource, "  - {name: first, environment: shared, authorization: shared}\n", "", 1)
	_, activation := runtimeGenerationTestActivate(t, registry, removedSource)
	require.ElementsMatch(t, []managedConnection{firstConnection, secondConnection}, activation.connections)
	require.ElementsMatch(t, []sessionConnectionKey{
		{flow: firstSession.Flow(), id: firstSession.Id()},
		{flow: secondSession.Flow(), id: secondSession.Id()},
	}, activation.sessions)
	require.True(t, registry.sessionRevoked(firstSession))
	require.True(t, registry.sessionRevoked(secondSession))
	require.False(t, registry.allowFlow(initial, "first"))
	require.False(t, registry.allowFlow(changed, "first"))
	require.False(t, registry.bindConnection(pending, firstSession), "an in-flight handshake cannot finish against a removed flow")

	// Close is deliberately outside the registry lock.
	firstConnection.onClose = func() { require.Same(t, initial, registry.sessionOwner(firstSession)) }
	require.NoError(t, activation.closeConnections())
	require.True(t, firstConnection.IsClosed())
	require.True(t, secondConnection.IsClosed())
	require.False(t, unrelatedConnection.IsClosed())

	recreated, _ := runtimeGenerationTestActivate(t, registry, changedSource)
	require.NotSame(t, initial.flows["first"].identity, recreated.flows["first"].identity)
	require.False(t, registry.sessionCompatible(recreated, firstSession))
	require.Error(t, registry.bindSession(recreated, firstSession, false))
	require.False(t, registry.bindConnection(pending, secondSession))
	fresh := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(recreated, fresh, true))
	require.True(t, registry.sessionCompatible(recreated, fresh))
	require.False(t, registry.sessionRevoked(fresh))
	require.Same(t, initial, registry.sessionOwner(firstSession))
}

func TestRuntimeGenerationRejectedCandidatesDoNotRevokeOrReplaceCurrent(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	initial := registry.initial
	source := strings.Replace(runtimeGenerationTestSource, "  - {name: first, environment: shared, authorization: shared}\n", "", 1)
	candidate, err := registry.prepare(runtimeGenerationTestSnapshot(t, source))
	require.NoError(t, err)
	require.True(t, registry.allowFlow(initial, "first"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = registry.activate(ctx, candidate)
	require.ErrorIs(t, err, context.Canceled)
	require.Same(t, initial, registry.current)
	require.True(t, registry.allowFlow(initial, "first"))
	registry.discard(candidate)
	registry.discard(candidate)
	runtimeGenerationTestDrained(t, candidate)
	_, err = registry.activate(t.Context(), candidate)
	require.Error(t, err)
	require.Same(t, initial, registry.current)
}

func TestRuntimeGenerationRejectsStaleAndForeignActivation(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	snapshot := runtimeGenerationTestSnapshot(t, runtimeGenerationTestSource)
	first, err := registry.prepare(snapshot)
	require.NoError(t, err)
	stale, err := registry.prepare(snapshot)
	require.NoError(t, err)
	_, err = registry.activate(t.Context(), first)
	require.NoError(t, err)
	require.Nil(t, first.parent, "active generations must not retain an unbounded parent/snapshot chain")
	_, err = registry.activate(t.Context(), stale)
	require.ErrorIs(t, err, errStaleRuntimeGeneration)
	registry.discard(stale)
	runtimeGenerationTestDrained(t, stale)

	foreign := runtimeGenerationTestRegistry(t)
	_, err = registry.activate(t.Context(), foreign.current)
	require.Error(t, err)
	require.Same(t, first, registry.current)
}

func TestRuntimeGenerationSocketClosureDoesNotReleaseHandlerResources(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	initial := registry.initial
	conn, release := runtimeGenerationTestAdmit(t, registry, initial, nil)
	conn.onClose = func() { registry.untrack(conn) }
	_, _ = runtimeGenerationTestActivate(t, registry, runtimeGenerationTestSource)
	require.NoError(t, conn.Close())
	runtimeGenerationTestNotDrained(t, initial)
	release()
	runtimeGenerationTestDrained(t, initial)
}

func TestRuntimeGenerationDoesNotReuseUnknownSessionsAfterStartupOwnerDrained(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	next, _ := runtimeGenerationTestActivate(t, registry, runtimeGenerationTestSource)
	runtimeGenerationTestDrained(t, registry.initial)
	unknown := runtimeGenerationTestSession("first")
	require.False(t, registry.sessionCompatible(next, unknown))
	require.Error(t, registry.bindSession(next, unknown, false))
	fresh := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(next, fresh, true))
	require.True(t, registry.sessionCompatible(next, fresh))
}

func TestRuntimeGenerationSessionCreatedDuringDeletionRemainsOwnedButDenied(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	initial := registry.initial
	release, err := registry.retain(initial) // Creation is already in progress.
	require.NoError(t, err)
	defer release()
	source := strings.Replace(runtimeGenerationTestSource, "  - {name: first, environment: shared, authorization: shared}\n", "", 1)
	_, _ = runtimeGenerationTestActivate(t, registry, source)
	late := runtimeGenerationTestSession("first")
	require.Error(t, registry.bindSession(initial, late, true))
	require.True(t, registry.sessionRevoked(late))
	require.Same(t, initial, registry.sessionOwner(late))
	release()
	runtimeGenerationTestNotDrained(t, initial)
	registry.finalSessionDeleted(late.Flow(), late.Id())
	runtimeGenerationTestDrained(t, initial)
}

func TestRuntimeGenerationBindingRacesFlowDeletion(t *testing.T) {
	for range 100 {
		registry := runtimeGenerationTestRegistry(t)
		sess := runtimeGenerationTestSession("first")
		require.NoError(t, registry.bindSession(registry.initial, sess, true))
		conn, _ := runtimeGenerationTestAdmit(t, registry, registry.initial, nil)
		source := strings.Replace(runtimeGenerationTestSource, "  - {name: first, environment: shared, authorization: shared}\n", "", 1)
		next, err := registry.prepare(runtimeGenerationTestSnapshot(t, source))
		require.NoError(t, err)
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			if !registry.bindConnection(conn, sess) {
				_ = conn.Close()
			}
		}()
		go func() {
			defer workers.Done()
			activation, err := registry.activate(t.Context(), next)
			if err != nil {
				t.Error(err)
				return
			}
			if err := activation.closeConnections(); err != nil {
				t.Error(err)
			}
		}()
		workers.Wait()
		require.True(t, conn.IsClosed())
		require.True(t, registry.sessionRevoked(sess))
	}
}

func TestRuntimeGenerationShutdownForgetsOwnershipWithoutDeletingSessions(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	initial := registry.initial
	sess := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(initial, sess, true))
	_, release := runtimeGenerationTestAdmit(t, registry, initial, sess)
	registry.stop()
	registry.stop()
	require.False(t, registry.allowFlow(initial, "first"))
	require.False(t, registry.sessionRevoked(sess), "shutdown is not a persistent flow deletion")
	_, err := registry.prepare(initial.snapshot)
	require.ErrorIs(t, err, context.Canceled)
	registry.forgetSessions()
	registry.forgetSessions()
	runtimeGenerationTestNotDrained(t, initial)
	release()
	runtimeGenerationTestDrained(t, initial)
}

func TestRuntimeGenerationIndividualRevocationUsesSharedFlowAndSessionScope(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	first := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(registry.initial, first, true))
	one, _ := runtimeGenerationTestAdmit(t, registry, registry.initial, first)
	otherFlow := &houseKeeperTestSession{flow: "second", id: first.Id()}
	require.NoError(t, registry.bindSession(registry.initial, otherFlow, true))
	other, _ := runtimeGenerationTestAdmit(t, registry, registry.initial, otherFlow)
	next, _ := runtimeGenerationTestActivate(t, registry, strings.Replace(runtimeGenerationTestSource, "plain:correct", "plain:changed", 1))
	two, _ := runtimeGenerationTestAdmit(t, registry, next, first)
	closing := registry.revokeSession(first.Flow(), first.Id())
	require.ElementsMatch(t, []managedConnection{one, two}, closing)
	require.NoError(t, closeSessionConnections(closing))
	require.True(t, one.IsClosed())
	require.True(t, two.IsClosed())
	require.False(t, other.IsClosed())
	require.True(t, registry.sessionRevoked(first))
	require.False(t, registry.sessionRevoked(otherFlow))
	require.False(t, registry.sessionCompatible(next, first))
	late, _ := runtimeGenerationTestAdmit(t, registry, next, nil)
	require.False(t, registry.bindConnection(late, first))
}
