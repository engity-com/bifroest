package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/https"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

type runtimeListenerTestRun struct {
	svc    *service
	inputs *runtimeListeners
	cancel context.CancelFunc
	await  func() error
	mutex  sync.Mutex
	bound  []net.Listener
}

func runtimeListenerTestStart(t *testing.T, svc *service, bind func(bnet.Address) (net.Listener, error)) *runtimeListenerTestRun {
	t.Helper()
	return runtimeListenerTestStartContext(t, context.Background(), svc, bind)
}

func runtimeListenerTestStartContext(t *testing.T, parent context.Context, svc *service, bind func(bnet.Address) (net.Listener, error)) *runtimeListenerTestRun {
	t.Helper()
	result := &runtimeListenerTestRun{svc: svc}
	ctx, cancel := context.WithCancel(parent)
	result.cancel = cancel
	done := make(chan error, 1)
	go func() {
		_, err := svc.runListeners(ctx, func(address bnet.Address) (net.Listener, error) {
			var listener net.Listener
			var err error
			if bind == nil {
				listener, err = address.Listen()
			} else {
				listener, err = bind(address)
			}
			if !isNilDependency(listener) {
				result.mutex.Lock()
				result.bound = append(result.bound, listener)
				result.mutex.Unlock()
			}
			return listener, err
		})
		done <- err
	}()
	result.await = awaitHTTPListenerTestRun(t, done)
	t.Cleanup(func() { cancel(); require.NoError(t, result.await()) })
	require.Eventually(t, func() bool {
		svc.resources.mutex.Lock()
		inputs := svc.resources.listeners
		svc.resources.mutex.Unlock()
		if inputs == nil {
			return false
		}
		inputs.mutex.Lock()
		ready := inputs.ready
		inputs.mutex.Unlock()
		if ready {
			result.inputs = inputs
		}
		return ready
	}, 5*time.Second, time.Millisecond)
	return result
}

func (this *runtimeListenerTestRun) scope(t *testing.T, transport, address string, ordinal int) (*runtimeListener, net.Listener) {
	t.Helper()
	this.inputs.mutex.Lock()
	scope := this.inputs.scopes[runtimeListenerKey{transport, address, ordinal}]
	var physical net.Listener
	if scope != nil {
		physical = scope.physical
	}
	this.inputs.mutex.Unlock()
	require.NotNil(t, scope)
	return scope, physical
}

func runtimeListenerTestActivate(t *testing.T, svc, candidate *service) *runtimeActivation {
	t.Helper()
	result, err := svc.activateGeneration(t.Context(), candidate)
	require.NoError(t, err)
	require.NoError(t, result.cleanupErr)
	return result
}

func TestRuntimeListenersKeepUnchangedScopesAndDetachWithoutClosingSsh(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, nil)
	address := svc.Configuration.Ssh.Addresses[0].String()
	originalScope, original := run.scope(t, "SSH", address, 0)
	old := runtimeSshDial(t, svc, original.Addr().String(), "correct")
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Ssh.Addresses = append(conf.Ssh.Addresses, conf.Ssh.Addresses[0])
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
	})
	runtimeListenerTestActivate(t, svc, next)
	retainedScope, retained := run.scope(t, "SSH", address, 0)
	require.Same(t, originalScope, retainedScope)
	require.Same(t, original, retained)
	addedScope, added := run.scope(t, "SSH", address, 1)
	fresh := runtimeSshDial(t, svc, added.Addr().String(), "changed")
	runtimeSshRun(t, old, 0)
	runtimeSshRun(t, fresh, 0)
	removed := runtimeSshCandidate(t, next, func(conf *configuration.Configuration) { conf.Ssh.Addresses = conf.Ssh.Addresses[:1] })
	runtimeListenerTestActivate(t, svc, removed)
	_, physical := run.scope(t, "SSH", address, 1)
	require.Nil(t, physical)
	probe, err := net.DialTimeout("tcp", added.Addr().String(), 200*time.Millisecond)
	if probe != nil {
		_ = probe.Close()
	}
	require.Error(t, err)
	runtimeSshRun(t, fresh, 0)
	runtimeSshRun(t, old, 0)
	require.NoError(t, fresh.Close())
	require.Eventually(t, func() bool {
		run.inputs.mutex.Lock()
		defer run.inputs.mutex.Unlock()
		return addedScope.retired && run.inputs.scopes[addedScope.spec.key] == nil
	}, 3*time.Second, time.Millisecond)
	runtimeSshRun(t, runtimeSshDial(t, svc, original.Addr().String(), "changed"), 0)
}

func TestRuntimeListenersDisableAndReenableRetainsLiveScopeAndChannelBudget(t *testing.T) {
	svc := runtimeResourcesFixture(t, func(conf *configuration.Configuration) { conf.Ssh.MaxChannels = 1 })
	run := runtimeListenerTestStart(t, svc, nil)
	address := svc.Configuration.Ssh.Addresses[0].String()
	scope, physical := run.scope(t, "SSH", address, 0)
	old := runtimeSshDial(t, svc, physical.Addr().String(), "correct")
	channel, err := old.NewSession()
	require.NoError(t, err)
	defer func() { _ = channel.Close() }()
	disabled := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Ssh.Enabled = new(false) })
	runtimeListenerTestActivate(t, svc, disabled)
	_, current := run.scope(t, "SSH", address, 0)
	require.Nil(t, current)
	enabled := runtimeSshCandidate(t, disabled, func(conf *configuration.Configuration) { conf.Ssh.Enabled = new(true) })
	runtimeListenerTestActivate(t, svc, enabled)
	reactivated, physical := run.scope(t, "SSH", address, 0)
	require.Same(t, scope, reactivated)
	fresh := runtimeSshDial(t, svc, physical.Addr().String(), "correct")
	excess, err := fresh.NewSession()
	if excess != nil {
		_ = excess.Close()
	}
	var shortage *gossh.OpenChannelError
	require.ErrorAs(t, err, &shortage)
	require.Equal(t, gossh.ResourceShortage, shortage.Reason)
	require.NoError(t, channel.Close())
	var resumed *gossh.Session
	require.Eventually(t, func() bool {
		resumed, err = old.NewSession()
		return err == nil
	}, 3*time.Second, time.Millisecond)
	defer func() { _ = resumed.Close() }()
	require.NoError(t, resumed.Run("test"))
}

func TestRuntimeListenersKeepIndependentBudgetsForDifferentSshAddresses(t *testing.T) {
	svc := runtimeResourcesFixture(t, func(conf *configuration.Configuration) {
		conf.Ssh.MaxChannels = 1
		conf.Ssh.Addresses = append(conf.Ssh.Addresses, conf.Ssh.Addresses[0])
	})
	run := runtimeListenerTestStart(t, svc, nil)
	address := svc.Configuration.Ssh.Addresses[0].String()
	_, first := run.scope(t, "SSH", address, 0)
	_, second := run.scope(t, "SSH", address, 1)
	client := runtimeSshDial(t, svc, first.Addr().String(), "correct")
	held, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = held.Close() }()
	runtimeSshRun(t, runtimeSshDial(t, svc, second.Addr().String(), "correct"), 0)
}

func TestRuntimeListenerBindFailurePreservesAcceptedConfigurationAndClosesStaging(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, nil)
	_, original := run.scope(t, "SSH", svc.Configuration.Ssh.Addresses[0].String(), 0)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Ssh.Addresses = append(conf.Ssh.Addresses, conf.Ssh.Addresses[0], bnet.MustNewAddress(occupied.Addr().String()))
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
	})
	result, err := svc.activateGeneration(t.Context(), next)
	require.ErrorContains(t, err, "cannot bind SSH")
	require.Nil(t, result)
	require.Same(t, svc.generation, svc.runtime.current)
	runtimeSshRun(t, runtimeSshDial(t, svc, original.Addr().String(), "correct"), 0)
	run.mutex.Lock()
	staged := run.bound[len(run.bound)-1]
	require.Len(t, run.bound, 2, "one new listener bound before the next one failed")
	run.mutex.Unlock()
	probe, err := net.DialTimeout("tcp", staged.Addr().String(), 200*time.Millisecond)
	if probe != nil {
		_ = probe.Close()
	}
	require.Error(t, err, "failed preparation must release its staged address")
}

func TestRuntimeListenerStaleCandidateNeverChangesTopology(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, nil)
	stale := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Ssh.Addresses = append(conf.Ssh.Addresses, conf.Ssh.Addresses[0])
	})
	winner := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "winner" })
	runtimeListenerTestActivate(t, svc, winner)
	result, err := svc.activateGeneration(t.Context(), stale)
	require.ErrorIs(t, err, errStaleRuntimeGeneration)
	require.Nil(t, result)
	require.Same(t, winner.generation, svc.runtime.current)
	run.inputs.mutex.Lock()
	require.Len(t, run.inputs.scopes, 1)
	run.inputs.mutex.Unlock()
}

func TestRuntimeListenerActivationClosesRemovedFlowsWithoutCallerFinalization(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, nil)
	_, physical := run.scope(t, "SSH", svc.Configuration.Ssh.Addresses[0].String(), 0)
	client := runtimeSshDial(t, svc, physical.Addr().String(), "correct")
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Name = "replacement" })
	result := runtimeListenerTestActivate(t, svc, next)
	require.Len(t, result.connections, 1)
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	select {
	case _ = <-done: // Closing the socket is expected; only completion matters.
	case <-time.After(3 * time.Second):
		t.Fatal("activation did not close the removed flow's SSH connection")
	}
}

func TestRuntimeListenerRemovedScopeWaitsForHandlerNotOnlySocket(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, nil)
	address := svc.Configuration.Ssh.Addresses[0].String()
	scope, physical := run.scope(t, "SSH", address, 0)
	// Reuse the real gated provider from the SSH lifecycle integration tests.
	gate := &runtimeSshGatedRepository{CloseableRepository: svc.environments, entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	svc.environments = gate
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	client := runtimeSshDial(t, svc, physical.Addr().String(), "correct")
	channel, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = channel.Close() }()
	done := make(chan error, 1)
	go func() { done <- channel.Run("test") }()
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("SSH handler did not start")
	}
	disabled := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Ssh.Enabled = new(false) })
	runtimeListenerTestActivate(t, svc, disabled)
	require.NoError(t, client.Close())
	require.Eventually(t, func() bool {
		run.inputs.mutex.Lock()
		defer run.inputs.mutex.Unlock()
		return scope.transports == 0
	}, 3*time.Second, time.Millisecond)
	run.inputs.mutex.Lock()
	require.False(t, scope.retired, "a closed socket is not the end of the handler lease")
	require.Equal(t, 1, scope.handlers)
	run.inputs.mutex.Unlock()
	unblock()
	_ = <-done // The transport was intentionally closed before the handler returned.
	require.Eventually(t, func() bool {
		run.inputs.mutex.Lock()
		defer run.inputs.mutex.Unlock()
		return scope.retired
	}, 3*time.Second, time.Millisecond)
}

type runtimeListenerCloseRetry struct {
	net.Listener
	fail atomic.Bool
}

func (this *runtimeListenerCloseRetry) Close() error {
	if this.fail.CompareAndSwap(true, false) {
		return errors.New("injected listener close failure")
	}
	return this.Listener.Close()
}

func TestRuntimeListenerCloseFailureIsPostCommitAndRetried(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, func(address bnet.Address) (net.Listener, error) {
		listener, err := address.Listen()
		if err != nil {
			return nil, err
		}
		wrapped := &runtimeListenerCloseRetry{Listener: listener}
		return wrapped, nil
	})
	_, physical := run.scope(t, "SSH", svc.Configuration.Ssh.Addresses[0].String(), 0)
	client := runtimeSshDial(t, svc, physical.Addr().String(), "correct")
	physical.(*runtimeListenerCloseRetry).fail.Store(true)
	disabled := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Ssh.Enabled = new(false)
		conf.Ssh.Addresses = bnet.NetAddresses{bnet.MustNewAddress(physical.Addr().String())}
	})
	result, err := svc.activateGeneration(t.Context(), disabled)
	require.NoError(t, err)
	require.ErrorContains(t, result.cleanupErr, "injected listener close failure")
	require.Same(t, disabled.generation, svc.runtime.current)
	enabled := runtimeSshCandidate(t, disabled, func(conf *configuration.Configuration) { conf.Ssh.Enabled = new(true) })
	runtimeListenerTestActivate(t, svc, enabled)
	_, rebound := run.scope(t, "SSH", physical.Addr().String(), 0)
	require.Equal(t, physical.Addr().String(), rebound.Addr().String(), "cleanup must free a fixed port before its next binding")
	run.inputs.mutex.Lock()
	require.Empty(t, run.inputs.pendingClose)
	run.inputs.mutex.Unlock()
	runtimeSshRun(t, client, 0)
}

func TestRuntimeListenerShutdownCancelsAndJoinsStagedBinding(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var calls atomic.Int32
	run := runtimeListenerTestStart(t, svc, func(address bnet.Address) (net.Listener, error) {
		if calls.Add(1) > 1 {
			close(entered)
			<-release
		}
		return address.Listen()
	})
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Ssh.Addresses = append(conf.Ssh.Addresses, conf.Ssh.Addresses[0])
	})
	activated := make(chan error, 1)
	go func() { _, err := svc.activateGeneration(t.Context(), next); activated <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("staged bind did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- svc.Close() }()
	select {
	case <-run.inputs.ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not cancel listeners")
	}
	select {
	case err := <-closed:
		t.Fatalf("process cleanup did not wait for the staged bind: %v", err)
	default:
	}
	unblock()
	require.ErrorIs(t, <-activated, context.Canceled)
	require.NoError(t, <-closed)
	require.NoError(t, run.await())
	require.False(t, next.generation.activated)
}

func TestRuntimeListenerHttpsRemovalKeepsOldHttpConnectionAndSsh(t *testing.T) {
	f := newSshTunnelFixture(t, true, true, true, false, func(conf *configuration.Configuration) {
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp("^Work$")
		conf.Flows[0].Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}}}
	})
	svc := f.svc
	ssh := runtimeSshDial(t, svc, f.directAddress, "correct")
	client := &http.Client{Transport: f.transport, Timeout: 3 * time.Second}
	body := `{"slug":"Work","user":"alice","password":"correct"}`
	code, data, initial, _ := runtimeHttpRequest(t, client, "login/password", body, "")
	runtimeHttpToken(t, code, data)
	added := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Http.Addresses = append(conf.Http.Addresses, bnet.MustNewAddress("127.0.0.2:0"))
	})
	runtimeListenerTestActivate(t, svc, added)
	svc.resources.mutex.Lock()
	inputs := svc.resources.listeners
	svc.resources.mutex.Unlock()
	inputs.mutex.Lock()
	scope := inputs.scopes[runtimeListenerKey{"HTTPS", "127.0.0.2:0", 0}]
	inputs.mutex.Unlock()
	require.NotNil(t, scope)
	// Removing the original address must not Close the shared HTTP server.
	removed := runtimeSshCandidate(t, added, func(conf *configuration.Configuration) { conf.Http.Addresses = conf.Http.Addresses[1:] })
	runtimeListenerTestActivate(t, svc, removed)
	code, data, reused, _ := runtimeHttpRequest(t, client, "login/password", body, "")
	runtimeHttpToken(t, code, data)
	require.Same(t, initial.Conn, reused.Conn)
	runtimeSshRun(t, ssh, 0)
	disabled := runtimeSshCandidate(t, removed, func(conf *configuration.Configuration) { conf.Http.Enabled = configuration.HttpDisabled })
	runtimeListenerTestActivate(t, svc, disabled)
	code, _, _, _ = runtimeHttpRequest(t, client, "login/password", body, "")
	require.Equal(t, http.StatusNotFound, code, "disabled HTTP must not accept new actions on an old keep-alive connection")
	runtimeSshRun(t, ssh, 0)
	enabled := runtimeSshCandidate(t, disabled, func(conf *configuration.Configuration) { conf.Http.Enabled = configuration.HttpEnabled })
	runtimeListenerTestActivate(t, svc, enabled)
	inputs.mutex.Lock()
	reopened := inputs.scopes[runtimeListenerKey{"HTTPS", "127.0.0.2:0", 0}].physical
	inputs.mutex.Unlock()
	transport := f.transport.Clone()
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", reopened.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	code, data, _, _ = runtimeHttpRequest(t, &http.Client{Transport: transport, Timeout: 3 * time.Second}, "login/password", body, "")
	runtimeHttpToken(t, code, data)
	require.NoError(t, ssh.Close())
}

func TestRuntimeListenerSafetySettingsStillRequireCompleteRestart(t *testing.T) {
	for _, field := range []string{"proxy", "limit", "http-first-enable"} {
		t.Run(field, func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			conf := svc.generation.snapshot.Configuration()
			conf.Ssh.Addresses = append(conf.Ssh.Addresses, conf.Ssh.Addresses[0])
			switch field {
			case "proxy":
				conf.Ssh.ProxyProtocol = !conf.Ssh.ProxyProtocol
			case "limit":
				conf.Ssh.MaxChannels++
			case "http-first-enable":
				conf.Http = &configuration.Http{}
				require.NoError(t, conf.Http.SetDefaults())
				conf.Http.Enabled, conf.Http.Tls = configuration.HttpEnabled, &configuration.Tls{Dummy: true}
				conf.Http.Domains = configuration.HttpDomains{"app.example.org"}
			}
			candidate, err := svc.prepareGeneration(t.Context(), conf)
			require.ErrorContains(t, err, "requires restart")
			require.Nil(t, candidate)
			require.Same(t, svc.generation, svc.runtime.current)
		})
	}
}

func TestRuntimeListenerAddressReorderingDoesNotRebind(t *testing.T) {
	svc := runtimeResourcesFixture(t, func(conf *configuration.Configuration) {
		conf.Ssh.Addresses = append(conf.Ssh.Addresses, bnet.MustNewAddress("127.0.0.2:0"))
	})
	run := runtimeListenerTestStart(t, svc, nil)
	before := append(bnet.NetAddresses(nil), svc.Configuration.Ssh.Addresses...)
	scope, physical := run.scope(t, "SSH", before[0].String(), 0)
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Ssh.Addresses[0], conf.Ssh.Addresses[1] = conf.Ssh.Addresses[1], conf.Ssh.Addresses[0]
	})
	runtimeListenerTestActivate(t, svc, next)
	after, kept := run.scope(t, "SSH", before[0].String(), 0)
	require.Same(t, scope, after)
	require.Same(t, physical, kept)
	run.mutex.Lock()
	require.Len(t, run.bound, 2)
	run.mutex.Unlock()
	runtimeSshRun(t, runtimeSshDial(t, svc, physical.Addr().String(), "correct"), 0)
}

func TestRuntimeListenerNilBindingsNeverEnterCleanup(t *testing.T) {
	for _, typed := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil", true: "typed-nil"}[typed], func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			var fail atomic.Bool
			run := runtimeListenerTestStart(t, svc, func(address bnet.Address) (net.Listener, error) {
				if fail.Load() {
					if typed {
						return (*net.TCPListener)(nil), errors.New("injected bind failure")
					}
					return nil, nil
				}
				return address.Listen()
			})
			fail.Store(true)
			next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
				conf.Ssh.Addresses = append(conf.Ssh.Addresses, conf.Ssh.Addresses[0])
			})
			result, err := svc.activateGeneration(t.Context(), next)
			require.ErrorContains(t, err, "cannot bind SSH")
			require.Nil(t, result)
			require.Same(t, svc.generation, svc.runtime.current)
			run.inputs.mutex.Lock()
			require.Empty(t, run.inputs.pendingClose)
			run.inputs.mutex.Unlock()
		})
	}
}

func TestRuntimeListenerLastIdleScopeCanBeRemovedAndRecreated(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, nil)
	address := svc.Configuration.Ssh.Addresses[0].String()
	current := svc
	for range 3 {
		scope, physical := run.scope(t, "SSH", address, 0)
		disabled := runtimeSshCandidate(t, current, func(conf *configuration.Configuration) { conf.Ssh.Enabled = new(false) })
		runtimeListenerTestActivate(t, svc, disabled)
		run.inputs.mutex.Lock()
		require.True(t, scope.retired)
		require.True(t, scope.expected)
		require.Empty(t, run.inputs.scopes)
		run.inputs.mutex.Unlock()
		probe, err := net.DialTimeout("tcp", physical.Addr().String(), 200*time.Millisecond)
		if probe != nil {
			_ = probe.Close()
		}
		require.Error(t, err)
		current = runtimeSshCandidate(t, disabled, func(conf *configuration.Configuration) { conf.Ssh.Enabled = new(true) })
		runtimeListenerTestActivate(t, svc, current)
		reopened, _ := run.scope(t, "SSH", address, 0)
		require.NotSame(t, scope, reopened)
	}
	_, physical := run.scope(t, "SSH", address, 0)
	runtimeSshRun(t, runtimeSshDial(t, svc, physical.Addr().String(), "correct"), 0)
}

func TestRuntimeListenerUnexpectedScopeCloseCannotBecomeExpectedAfterDrain(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	run := runtimeListenerTestStart(t, svc, nil)
	scope, physical := run.scope(t, "SSH", svc.Configuration.Ssh.Addresses[0].String(), 0)
	client := runtimeSshDial(t, svc, physical.Addr().String(), "correct")
	// Model the server closing its virtual listener after an unexpected failure.
	// Its subsequent transport/handler cleanup must not reclassify that failure.
	require.NoError(t, scope.Close())
	result := run.await()
	// This test deliberately stopped the service with a fatal listener error.
	run.await = func() error { return nil }
	require.Error(t, result)
	require.False(t, svc.isProblematicError(client.Close()), "the server may already have closed the client socket")
	run.inputs.mutex.Lock()
	require.False(t, scope.expected)
	require.Error(t, run.inputs.failure)
	run.inputs.mutex.Unlock()
}

func TestRuntimeListenerHttpDisablePreventsDelayedLoginPublication(t *testing.T) {
	f := newSshTunnelFixture(t, true, true, true, false, func(conf *configuration.Configuration) {
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp("^Work$")
		conf.Flows[0].Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}}}
	})
	svc, handler := f.svc, f.svc.web
	flow := svc.Configuration.Flows[0].Name
	gate := &maintenanceTestAuditGate{Recorder: svc.flowAuditRecorders[flow], name: audit.EventNameAuthenticationCompleted, entered: make(chan struct{}), release: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	svc.flowAuditRecorders[flow] = gate
	done := make(chan int, 1)
	go func() { done <- webTestPassword(handler, "alice", "correct", "Work").Code }()
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("login did not reach final audit")
	}
	disabled := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Http.Enabled = configuration.HttpDisabled })
	runtimeListenerTestActivate(t, svc, disabled)
	unblock()
	require.Equal(t, http.StatusServiceUnavailable, <-done)
	require.Empty(t, svc.web.access, "disabled HTTP must not publish a delayed browser grant")
}

func TestRuntimeListenerHttpDisablePreservesExistingTunnels(t *testing.T) {
	f := newSshTunnelFixture(t, false, false, true, false, nil)
	clients := []*gossh.Client{f.dial(t, "https1"), f.dial(t, "https2"), f.dial(t, "wss")}
	probe := f.request(t, http.MethodGet, https.SshTunnelPath, nil)
	require.Equal(t, http.StatusMethodNotAllowed, probe.StatusCode)
	_, err := io.Copy(io.Discard, probe.Body)
	require.NoError(t, err)
	require.NoError(t, probe.Body.Close())
	disabled := runtimeSshCandidate(t, f.svc, func(conf *configuration.Configuration) { conf.Http.Enabled = configuration.HttpDisabled })
	runtimeListenerTestActivate(t, f.svc, disabled)
	probe = f.request(t, http.MethodGet, https.SshTunnelPath, nil)
	require.Equal(t, http.StatusNotFound, probe.StatusCode, "an existing HTTP connection must not open a new tunnel after disabling")
	for _, client := range clients {
		runtimeSshRun(t, client, 0)
		require.NoError(t, client.Close())
	}
}

func TestRuntimeListenerCloseInvalidatesUncommittedRetentionPlan(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	inputs := newRuntimeListeners(svc, t.Context(), nil)
	t.Cleanup(func() { inputs.cancel(nil); require.NoError(t, inputs.stop()) })
	initial, err := inputs.prepare(t.Context(), svc.Configuration)
	require.NoError(t, err)
	inputs.mutex.Lock()
	inputs.installLocked(initial)
	scope := inputs.scopes[runtimeListenerSpecs(svc.Configuration, false)[0].key]
	inputs.mutex.Unlock()
	staged, err := inputs.prepare(t.Context(), svc.Configuration)
	require.NoError(t, err)
	defer func() { require.NoError(t, staged.close()) }()
	require.Empty(t, staged.added, "the prepared plan intended to retain the existing listener")
	require.NoError(t, scope.Close())
	inputs.mutex.Lock()
	require.NotEqual(t, staged.version, inputs.version, "closing a retained input must invalidate preparation before Serve reports its result")
	inputs.mutex.Unlock()
}
