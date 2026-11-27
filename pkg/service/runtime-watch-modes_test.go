package service

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type runtimeReuseDrainingListener struct {
	net.Listener
	drained chan struct{}
}

func (this *runtimeReuseDrainingListener) Drained() <-chan struct{} { return this.drained }

type runtimeReuseClosingEnvironment struct {
	environment.Environment
	closed atomic.Int32
}

func (this *runtimeReuseClosingEnvironment) Close() error { this.closed.Add(1); return nil }

func TestRuntimeReuseReverseListenerPinsResourceOwnerUntilDrained(t *testing.T) {
	physical, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	drained := make(chan struct{})
	owner := &runtimeReuseClosingEnvironment{}
	var released atomic.Int32
	listener := &environmentReverseTCPListener{
		Listener: &runtimeReuseDrainingListener{Listener: physical, drained: drained},
		owner:    owner, release: func() { released.Add(1) },
	}
	require.NoError(t, listener.Close())
	require.Zero(t, owner.closed.Load())
	require.Zero(t, released.Load())
	close(drained)
	require.Eventually(t, func() bool { return released.Load() == 1 }, time.Second, time.Millisecond)
	require.EqualValues(t, 1, owner.closed.Load())
	require.NoError(t, listener.Close())
	require.EqualValues(t, 1, released.Load())
}

func TestRuntimeReconnectOnlyClosesRelevantFlowsAndFencesLateAuthentication(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	registry.watch = configuration.WatchModeReconnect
	original := registry.initial
	first := runtimeGenerationTestSession("first")
	stable := runtimeGenerationTestSession("independent")
	require.NoError(t, registry.bindSession(original, first, true))
	require.NoError(t, registry.bindSession(original, stable, true))
	changed, _ := runtimeGenerationTestAdmit(t, registry, original, first)
	untouched, _ := runtimeGenerationTestAdmit(t, registry, original, stable)
	pending, _ := runtimeGenerationTestAdmit(t, registry, original, nil)
	source := strings.Replace(runtimeGenerationTestSource, "plain:correct", "plain:changed", 1)
	_, activation := runtimeGenerationTestActivate(t, registry, source)
	require.Len(t, activation.connections, 1)
	require.NoError(t, activation.closeConnections())
	require.True(t, changed.IsClosed())
	require.False(t, untouched.IsClosed())
	require.False(t, registry.allowFlow(original, "first"))
	require.True(t, registry.allowFlow(original, "independent"))
	require.False(t, registry.bindConnection(pending, first), "old pending credentials must not publish after reconnect activation")
}

// Model a resource selector that includes an immutable provisioning choice.
// Backend tests separately exercise the real Docker/Kubernetes projections.
type runtimeReuseTargetRepository struct {
	environment.CloseableRepository
	provisioning string
	identity     string
}

func (this *runtimeReuseTargetRepository) ResolveSessionTarget(environment.Context) (session.Target, error) {
	return session.NewTarget("dummy", map[string]string{"provisioning": this.provisioning, "identity": this.identity})
}

func (this *runtimeReuseTargetRepository) ResolveSessionReuseTarget(_ environment.Context, previous configuration.Environment) (session.Target, error) {
	return session.NewTarget("dummy", map[string]string{"provisioning": previous.V.(*configuration.EnvironmentDummy).ExitCode.String(), "identity": this.identity})
}

func TestRuntimeReuseSelectsOriginalTargetOnlyForKnownOwnedSessions(t *testing.T) {
	for _, changedIdentity := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-target", true: "changed-target"}[changedIdentity], func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			svc.Watch, svc.runtime.watch = configuration.WatchModeReuse, configuration.WatchModeReuse
			provisioning := svc.Configuration.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode.String()
			svc.environments = &runtimeReuseTargetRepository{CloseableRepository: svc.environments, provisioning: provisioning, identity: "original"}
			original := runtimeAdmissionTestPassword(t, svc, "correct").FindSession()
			require.NotNil(t, original)
			next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
				conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(17)
			})
			identity := "original"
			if changedIdentity {
				identity = "different"
			}
			next.environments = &runtimeReuseTargetRepository{CloseableRepository: next.environments, provisioning: "17", identity: identity}
			runtimeSshActivate(t, svc, next)
			auth := runtimeAdmissionTestPassword(t, next, "correct")
			require.True(t, auth.IsAuthorized())
			if changedIdentity {
				require.NotEqual(t, original.Id(), auth.FindSession().Id())
			} else {
				require.Equal(t, original.Id(), auth.FindSession().Id())
				require.Same(t, svc.generation, svc.runtime.sessionOwner(auth.FindSession()))
			}
		})
	}
}

func TestRuntimeReuseDoesNotReinterpretOidcGrantUnderNewAuthority(t *testing.T) {
	ctx, settings := runtimeOidcSettings(t)
	svc := runtimeResourcesFixtureContext(t, ctx, func(conf *configuration.Configuration) { conf.Flows[0].Authorization.V = settings })
	svc.Watch, svc.runtime.watch = configuration.WatchModeReuse, configuration.WatchModeReuse
	sess := runtimeOidcSession(t, svc)
	conf := svc.generation.snapshot.Configuration()
	conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(17)
	conf.Flows[0].Authorization.V.(*configuration.AuthorizationOidcDeviceAuth).ClientSecret = template.MustNewString("changed-secret")
	next, err := svc.prepareGeneration(ctx, conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(next.generation) {
			<-next.generationClosed
		}
	})
	runtimeSshActivate(t, svc, next)
	require.True(t, svc.runtime.sessionCompatible(next.generation, sess), "reuse relaxes environment revision equality")
	require.False(t, next.loginSessionCompatible(sess), "a retained grant still belongs to its original OIDC authority")
	require.Same(t, svc.generation, svc.runtime.sessionOwner(sess))
}

func TestRuntimeReuseCannotCrossEnvironmentTypeBoundaryOrReviveRemovedFlow(t *testing.T) {
	registry := runtimeGenerationTestRegistry(t)
	registry.watch = configuration.WatchModeReuse
	original := registry.initial
	sess := runtimeGenerationTestSession("first")
	require.NoError(t, registry.bindSession(original, sess, true))
	changed, _ := runtimeGenerationTestActivate(t, registry, strings.Replace(runtimeGenerationTestSource, "banner: original", "banner: original, exitCode: 17", 1))
	require.True(t, registry.sessionCompatible(changed, sess))
	require.NoError(t, registry.bindSession(changed, sess, false))
	require.Same(t, original, registry.sessionOwner(sess))
	_, _ = runtimeGenerationTestActivate(t, registry, strings.Replace(runtimeGenerationTestSource, "type: dummy, banner: original", "type: management", 1))
	reverted, _ := runtimeGenerationTestActivate(t, registry, runtimeGenerationTestSource)
	require.False(t, registry.sessionCompatible(reverted, sess), "reverting the provider type must not revive the earlier reuse lineage")
	_, _ = runtimeGenerationTestActivate(t, registry, strings.Replace(runtimeGenerationTestSource, "name: first,", "name: replacement,", 1))
	recreated, _ := runtimeGenerationTestActivate(t, registry, runtimeGenerationTestSource)
	require.False(t, registry.sessionCompatible(recreated, sess))
}

func TestRuntimePresentationChangesKeepBrowserActionsAndEnvironmentRevision(t *testing.T) {
	for _, mode := range []configuration.WatchMode{configuration.WatchModePreserve, configuration.WatchModeReconnect, configuration.WatchModeReuse} {
		t.Run(mode.String(), func(t *testing.T) {
			registry := runtimeGenerationTestRegistry(t)
			registry.watch = mode
			original := registry.initial
			sess := runtimeGenerationTestSession("first")
			require.NoError(t, registry.bindSession(original, sess, true))
			conn, _ := runtimeGenerationTestAdmit(t, registry, original, sess)
			source := strings.Replace(runtimeGenerationTestSource, "banner: original", "banner: changed", 1)
			source = strings.Replace(source, "name: first,", "name: first, title: New label,", 1)
			next, activation := runtimeGenerationTestActivate(t, registry, source)
			require.Empty(t, activation.connections)
			require.False(t, conn.IsClosed())
			require.Same(t, original.flows["first"].actions, next.flows["first"].actions)
			require.Same(t, original.flows["first"].environment, next.flows["first"].environment)
			require.True(t, registry.allowFlow(original, "first"))
			require.True(t, registry.sessionCompatible(next, sess))
		})
	}
}
